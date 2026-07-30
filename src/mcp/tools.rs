//! MCP tool layer: maps calendar/task tool calls onto a [`CalDavClient`].
//!
//! Every tool serializes its domain result (or a small ack object) as pretty-printed
//! JSON text via [`ok_json`] - this keeps the mapping mechanical and lets clients
//! parse a stable, self-describing payload rather than free text.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::caldav::client::CalDavClient;
use crate::caldav::model::{Event, EventPatch, Todo, TodoPatch};
use crate::error::Error;

/// Parameters for listing events within a time window.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListEventsReq {
    /// Calendar href to query, e.g. "/dav/calendars/user/me/work/".
    pub calendar: String,
    /// Start of the time window (inclusive), RFC 3339.
    pub start: DateTime<Utc>,
    /// End of the time window (exclusive), RFC 3339.
    pub end: DateTime<Utc>,
}

/// Parameters identifying a single event or task by UID within a calendar.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetByUidReq {
    /// Calendar href the object lives in.
    pub calendar: String,
    /// UID of the event or task.
    pub uid: String,
}

/// Parameters for listing tasks (VTODOs), with optional client-side filters.
/// Filters are combined with AND; omitting a filter leaves that dimension
/// unrestricted, so an all-`None` request returns every task in the calendar.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListTasksReq {
    /// Calendar href to query, e.g. "/dav/calendars/user/me/todo/".
    pub calendar: String,
    /// Keep only tasks whose status matches this value (case-insensitive):
    /// NEEDS-ACTION | IN-PROCESS | COMPLETED | CANCELLED.
    pub status: Option<TaskStatus>,
    /// Keep only tasks with a due date strictly before this instant (RFC 3339).
    /// Tasks without a due date are excluded when this is set.
    pub due_before: Option<DateTime<Utc>>,
    /// Keep only tasks with a due date at or after this instant (RFC 3339).
    /// Tasks without a due date are excluded when this is set.
    pub due_after: Option<DateTime<Utc>>,
}

/// Parameters for creating a new event.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateEventReq {
    /// Calendar href to create the event in.
    pub calendar: String,
    /// Event title/summary.
    pub summary: String,
    /// Start time, RFC 3339.
    pub start: DateTime<Utc>,
    /// End time, RFC 3339.
    pub end: DateTime<Utc>,
    /// Optional location text.
    pub location: Option<String>,
    /// Optional free-text description.
    pub description: Option<String>,
    /// Optional recurrence rule, e.g. "FREQ=WEEKLY;BYDAY=MO".
    pub rrule: Option<String>,
}

/// Parameters for updating an existing event. Fields set to `None` are left
/// unchanged. This always edits the whole series, never a single instance.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateEventReq {
    /// Calendar href the event lives in.
    pub calendar: String,
    /// UID of the event to update.
    pub uid: String,
    /// New title/summary, if changing.
    pub summary: Option<String>,
    /// New start time, if changing.
    pub start: Option<DateTime<Utc>>,
    /// New end time, if changing.
    pub end: Option<DateTime<Utc>>,
    /// New location, if changing.
    pub location: Option<String>,
    /// New description, if changing.
    pub description: Option<String>,
    /// New recurrence rule, if changing.
    pub rrule: Option<String>,
    /// Names of optional fields to unset (remove the value entirely). Clearable
    /// fields: "location", "description", "rrule". If a field is both given a new
    /// value above and named here, the new value wins. Unknown names are rejected.
    pub clear: Option<Vec<String>>,
}

/// RFC5545 §3.8.1.11 status values valid for a VTODO. Constraining the MCP schema
/// to this closed set stops a bogus free-text status being written verbatim into the
/// STATUS property. The JSON/iCal tokens are the exact enumerated values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
pub enum TaskStatus {
    #[serde(rename = "NEEDS-ACTION")]
    NeedsAction,
    #[serde(rename = "IN-PROCESS")]
    InProcess,
    #[serde(rename = "COMPLETED")]
    Completed,
    #[serde(rename = "CANCELLED")]
    Cancelled,
}

impl TaskStatus {
    /// The RFC5545 STATUS token for this value, as written into the VTODO.
    fn as_ical_token(self) -> &'static str {
        match self {
            TaskStatus::NeedsAction => "NEEDS-ACTION",
            TaskStatus::InProcess => "IN-PROCESS",
            TaskStatus::Completed => "COMPLETED",
            TaskStatus::Cancelled => "CANCELLED",
        }
    }
}

/// Parameters for creating a new task (VTODO).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateTaskReq {
    /// Calendar href to create the task in.
    pub calendar: String,
    /// Task title/summary.
    pub summary: String,
    /// Optional due date/time, RFC 3339.
    pub due: Option<DateTime<Utc>>,
    /// Optional status: NEEDS-ACTION | IN-PROCESS | COMPLETED | CANCELLED.
    pub status: Option<TaskStatus>,
    /// Optional free-text description.
    pub description: Option<String>,
    /// Optional priority, iCalendar scale (0 = undefined, 1 = highest, 9 = lowest).
    pub priority: Option<u8>,
}

/// Parameters for updating an existing task. Fields set to `None` are left
/// unchanged.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateTaskReq {
    /// Calendar href the task lives in.
    pub calendar: String,
    /// UID of the task to update.
    pub uid: String,
    /// New title/summary, if changing.
    pub summary: Option<String>,
    /// New due date/time, if changing.
    pub due: Option<DateTime<Utc>>,
    /// New status, if changing.
    pub status: Option<TaskStatus>,
    /// New description, if changing.
    pub description: Option<String>,
    /// New priority, if changing.
    pub priority: Option<u8>,
    /// Names of optional fields to unset (remove the value entirely). Clearable
    /// fields: "due", "status", "description", "priority". If a field is both
    /// given a new value above and named here, the new value wins. Unknown names
    /// are rejected.
    pub clear: Option<Vec<String>>,
}

/// Serialize `v` as pretty JSON text and wrap it as a successful tool result.
fn ok_json<T: serde::Serialize>(v: &T) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(v).map_err(|e| {
        McpError::internal_error(format!("failed to serialize tool result: {e}"), None)
    })?;
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

/// Map a domain [`Error`] onto the MCP error type.
fn map_err(e: Error) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

/// Map an unknown-field name from `clear_fields` onto an MCP invalid-params error.
fn map_clear_err(field: String) -> McpError {
    McpError::invalid_params(format!("unknown field in clear list: {field}"), None)
}

/// A fresh UID for a newly-created event or task.
fn new_uid() -> String {
    format!("mcp-{}", uuid::Uuid::new_v4())
}

/// MCP server exposing calendar and task tools backed by a [`CalDavClient`].
#[derive(Clone)]
pub struct CalendarServer {
    client: Arc<dyn CalDavClient>,
    tool_router: ToolRouter<CalendarServer>,
}

#[tool_router]
impl CalendarServer {
    pub fn new(client: Arc<dyn CalDavClient>) -> Self {
        Self {
            client,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "List all calendars available to this account.")]
    async fn list_calendars(&self) -> Result<CallToolResult, McpError> {
        let calendars = self.client.list_calendars().await.map_err(map_err)?;
        ok_json(&calendars)
    }

    #[tool(description = "List events in a calendar within a time window.")]
    async fn list_events(
        &self,
        Parameters(req): Parameters<ListEventsReq>,
    ) -> Result<CallToolResult, McpError> {
        let events = self
            .client
            .list_events(&req.calendar, req.start, req.end)
            .await
            .map_err(map_err)?;
        ok_json(&events)
    }

    #[tool(description = "Get a single event by UID.")]
    async fn get_event(
        &self,
        Parameters(req): Parameters<GetByUidReq>,
    ) -> Result<CallToolResult, McpError> {
        let event = self
            .client
            .get_event(&req.calendar, &req.uid)
            .await
            .map_err(map_err)?;
        ok_json(&event)
    }

    #[tool(description = "Create a new event.")]
    async fn create_event(
        &self,
        Parameters(req): Parameters<CreateEventReq>,
    ) -> Result<CallToolResult, McpError> {
        let event = Event {
            uid: new_uid(),
            href: None,
            etag: None,
            summary: req.summary,
            start: req.start,
            end: req.end,
            location: req.location,
            description: req.description,
            rrule: req.rrule,
            is_instance: false,
        };
        self.client
            .put_event(&req.calendar, &event)
            .await
            .map_err(map_err)?;
        ok_json(&event)
    }

    #[tool(
        description = "Update an existing event. This always edits the whole series, never a single instance."
    )]
    async fn update_event(
        &self,
        Parameters(req): Parameters<UpdateEventReq>,
    ) -> Result<CallToolResult, McpError> {
        let patch = EventPatch {
            summary: req.summary,
            start: req.start,
            end: req.end,
            location: req.location,
            description: req.description,
            rrule: req.rrule,
        };
        let mut event = self
            .client
            .get_event(&req.calendar, &req.uid)
            .await
            .map_err(map_err)?;
        // Clear before patching so an explicit new value in the patch wins over a
        // clear of the same field.
        if let Some(clear) = &req.clear {
            event.clear_fields(clear).map_err(map_clear_err)?;
        }
        event.apply_patch(patch);
        event.is_instance = false;
        self.client
            .put_event(&req.calendar, &event)
            .await
            .map_err(map_err)?;
        ok_json(&event)
    }

    #[tool(description = "Delete an event by UID.")]
    async fn delete_event(
        &self,
        Parameters(req): Parameters<GetByUidReq>,
    ) -> Result<CallToolResult, McpError> {
        self.client
            .delete_event(&req.calendar, &req.uid)
            .await
            .map_err(map_err)?;
        ok_json(&serde_json::json!({ "deleted": req.uid }))
    }

    #[tool(
        description = "List tasks (VTODOs) in a calendar, with optional status and due-date filters."
    )]
    async fn list_tasks(
        &self,
        Parameters(req): Parameters<ListTasksReq>,
    ) -> Result<CallToolResult, McpError> {
        let todos = self
            .client
            .list_todos(&req.calendar)
            .await
            .map_err(map_err)?;
        // Client-side filtering: fetch everything, then narrow. Pushing these
        // predicates into the CalDAV calendar-query REPORT is a documented
        // follow-up (issue #7).
        let want_status = req.status.map(TaskStatus::as_ical_token);
        let todos: Vec<Todo> = todos
            .into_iter()
            .filter(|t| match want_status {
                Some(want) => t
                    .status
                    .as_deref()
                    .is_some_and(|got| got.eq_ignore_ascii_case(want)),
                None => true,
            })
            .filter(|t| match (req.due_after, req.due_before) {
                (None, None) => true,
                (after, before) => match t.due {
                    Some(due) => after.is_none_or(|a| due >= a) && before.is_none_or(|b| due < b),
                    // A task with no due date can't satisfy a due-window filter.
                    None => false,
                },
            })
            .collect();
        ok_json(&todos)
    }

    #[tool(description = "Get a single task (VTODO) by UID.")]
    async fn get_task(
        &self,
        Parameters(req): Parameters<GetByUidReq>,
    ) -> Result<CallToolResult, McpError> {
        let todo = self
            .client
            .get_todo(&req.calendar, &req.uid)
            .await
            .map_err(map_err)?;
        ok_json(&todo)
    }

    #[tool(description = "Create a new task.")]
    async fn create_task(
        &self,
        Parameters(req): Parameters<CreateTaskReq>,
    ) -> Result<CallToolResult, McpError> {
        let todo = Todo {
            uid: new_uid(),
            href: None,
            etag: None,
            summary: req.summary,
            due: req.due,
            status: req.status.map(|s| s.as_ical_token().to_string()),
            description: req.description,
            priority: req.priority,
        };
        self.client
            .put_todo(&req.calendar, &todo)
            .await
            .map_err(map_err)?;
        ok_json(&todo)
    }

    #[tool(description = "Update an existing task.")]
    async fn update_task(
        &self,
        Parameters(req): Parameters<UpdateTaskReq>,
    ) -> Result<CallToolResult, McpError> {
        let patch = TodoPatch {
            summary: req.summary,
            due: req.due,
            status: req.status.map(|s| s.as_ical_token().to_string()),
            description: req.description,
            priority: req.priority,
        };
        let mut todo = self
            .client
            .get_todo(&req.calendar, &req.uid)
            .await
            .map_err(map_err)?;
        // Clear before patching so an explicit new value in the patch wins over a
        // clear of the same field.
        if let Some(clear) = &req.clear {
            todo.clear_fields(clear).map_err(map_clear_err)?;
        }
        todo.apply_patch(patch);
        self.client
            .put_todo(&req.calendar, &todo)
            .await
            .map_err(map_err)?;
        ok_json(&todo)
    }

    #[tool(description = "Delete a task by UID.")]
    async fn delete_task(
        &self,
        Parameters(req): Parameters<GetByUidReq>,
    ) -> Result<CallToolResult, McpError> {
        self.client
            .delete_todo(&req.calendar, &req.uid)
            .await
            .map_err(map_err)?;
        ok_json(&serde_json::json!({ "deleted": req.uid }))
    }
}

#[tool_handler]
impl ServerHandler for CalendarServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some("Manage a Fastmail calendar: events and tasks over CalDAV.".into()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::caldav::model::Calendar;
    use crate::error::Result;

    /// A canned [`CalDavClient`] that never hits the network: one calendar named
    /// "Work", and `get_event`/`get_todo` echo the requested UID back with a fixed
    /// summary so tests can assert a patch was actually applied on top of it.
    struct MockClient;

    #[async_trait]
    impl CalDavClient for MockClient {
        async fn list_calendars(&self) -> Result<Vec<Calendar>> {
            Ok(vec![Calendar {
                href: "/cal/work/".into(),
                display_name: "Work".into(),
                color: None,
                components: vec!["VEVENT".into()],
                ctag: None,
            }])
        }

        async fn list_events(
            &self,
            _cal_href: &str,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
        ) -> Result<Vec<Event>> {
            Ok(vec![])
        }

        async fn get_event(&self, _cal_href: &str, uid: &str) -> Result<Event> {
            Ok(Event {
                uid: uid.to_string(),
                href: Some(format!("/cal/{uid}.ics")),
                etag: Some("\"e1\"".into()),
                summary: "Original summary".into(),
                start: Utc::now(),
                end: Utc::now(),
                location: Some("Original location".into()),
                description: Some("Original description".into()),
                rrule: Some("FREQ=DAILY".into()),
                is_instance: false,
            })
        }

        async fn put_event(&self, _cal_href: &str, _ev: &Event) -> Result<()> {
            Ok(())
        }

        async fn delete_event(&self, _cal_href: &str, _uid: &str) -> Result<()> {
            Ok(())
        }

        async fn list_todos(&self, _cal_href: &str) -> Result<Vec<Todo>> {
            Ok(sample_todos())
        }

        async fn get_todo(&self, _cal_href: &str, uid: &str) -> Result<Todo> {
            Ok(Todo {
                uid: uid.to_string(),
                href: Some(format!("/cal/{uid}.ics")),
                etag: Some("\"t1\"".into()),
                summary: "Original task".into(),
                due: Some(Utc::now()),
                status: Some("NEEDS-ACTION".into()),
                description: Some("Original description".into()),
                priority: Some(5),
            })
        }

        async fn put_todo(&self, _cal_href: &str, _td: &Todo) -> Result<()> {
            Ok(())
        }

        async fn delete_todo(&self, _cal_href: &str, _uid: &str) -> Result<()> {
            Ok(())
        }
    }

    /// Parse an RFC 3339 timestamp into a UTC [`DateTime`] for test fixtures.
    fn dt(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    /// A canned set of four VTODOs with varying status and due dates, used to
    /// assert that `list_tasks` filters narrow the result correctly.
    fn sample_todos() -> Vec<Todo> {
        let mk = |uid: &str, status: Option<&str>, due: Option<&str>| Todo {
            uid: uid.into(),
            href: Some(format!("/cal/{uid}.ics")),
            etag: Some("\"t1\"".into()),
            summary: format!("Task {uid}"),
            due: due.map(dt),
            status: status.map(str::to_string),
            description: None,
            priority: None,
        };
        vec![
            // "a" is stored lower-case to prove the status match is case-insensitive
            // against the canonical iCal token.
            mk("a", Some("needs-action"), Some("2026-08-01T00:00:00Z")),
            mk("b", Some("COMPLETED"), Some("2026-08-10T00:00:00Z")),
            mk("c", Some("IN-PROCESS"), None),
            mk("d", Some("NEEDS-ACTION"), Some("2026-08-20T00:00:00Z")),
        ]
    }

    /// Concatenate all text content blocks of a [`CallToolResult`] for substring
    /// assertions - the tools here only ever emit a single `Content::text` block,
    /// but this stays correct if that changes.
    fn result_text(result: &CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn list_calendars_returns_json() {
        let server = CalendarServer::new(Arc::new(MockClient));
        let result = server.list_calendars().await.unwrap();
        let text = result_text(&result);
        assert!(
            text.contains("Work"),
            "expected calendar name in result, got: {text}"
        );
    }

    #[tokio::test]
    async fn update_event_applies_patch() {
        let server = CalendarServer::new(Arc::new(MockClient));
        let req = UpdateEventReq {
            calendar: "/cal/work/".into(),
            uid: "evt-1".into(),
            summary: Some("New".into()),
            start: None,
            end: None,
            location: None,
            description: None,
            rrule: None,
            clear: None,
        };
        let result = server.update_event(Parameters(req)).await.unwrap();
        let text = result_text(&result);
        assert!(
            text.contains("New"),
            "expected patched summary in result, got: {text}"
        );
        // The original summary from MockClient::get_event must be gone - proves the
        // patch replaced it rather than the mock's canned value leaking through.
        assert!(
            !text.contains("Original summary"),
            "unpatched summary leaked through: {text}"
        );
    }

    #[tokio::test]
    async fn create_task_writes_each_status_token() {
        let server = CalendarServer::new(Arc::new(MockClient));
        let cases = [
            (TaskStatus::NeedsAction, "NEEDS-ACTION"),
            (TaskStatus::InProcess, "IN-PROCESS"),
            (TaskStatus::Completed, "COMPLETED"),
            (TaskStatus::Cancelled, "CANCELLED"),
        ];
        for (status, token) in cases {
            let req = CreateTaskReq {
                calendar: "/cal/work/".into(),
                summary: "Task".into(),
                due: None,
                status: Some(status),
                description: None,
                priority: None,
            };
            let result = server.create_task(Parameters(req)).await.unwrap();
            let text = result_text(&result);
            assert!(
                text.contains(token),
                "expected status token {token} in result, got: {text}"
            );
        }
    }

    #[tokio::test]
    async fn update_task_writes_status_token() {
        let server = CalendarServer::new(Arc::new(MockClient));
        let req = UpdateTaskReq {
            calendar: "/cal/work/".into(),
            uid: "todo-1".into(),
            summary: None,
            due: None,
            status: Some(TaskStatus::Completed),
            description: None,
            priority: None,
            clear: None,
        };
        let result = server.update_task(Parameters(req)).await.unwrap();
        let text = result_text(&result);
        assert!(
            text.contains("COMPLETED"),
            "expected status token COMPLETED in result, got: {text}"
        );
    }

    #[tokio::test]
    async fn update_event_clears_named_field() {
        let server = CalendarServer::new(Arc::new(MockClient));
        let req = UpdateEventReq {
            calendar: "/cal/work/".into(),
            uid: "evt-1".into(),
            summary: None,
            start: None,
            end: None,
            location: None,
            description: None,
            rrule: None,
            clear: Some(vec!["location".into()]),
        };
        let result = server.update_event(Parameters(req)).await.unwrap();
        let text = result_text(&result);
        // The mock's event has a location; clearing it removes it, while the
        // untouched description survives.
        assert!(
            !text.contains("Original location"),
            "cleared location leaked through: {text}"
        );
        assert!(
            text.contains("Original description"),
            "untouched description was dropped: {text}"
        );
    }

    #[tokio::test]
    async fn update_event_set_beats_clear() {
        let server = CalendarServer::new(Arc::new(MockClient));
        let req = UpdateEventReq {
            calendar: "/cal/work/".into(),
            uid: "evt-1".into(),
            summary: None,
            start: None,
            end: None,
            location: Some("Room 5".into()),
            description: None,
            rrule: None,
            // location is both set and cleared - the explicit set must win.
            clear: Some(vec!["location".into()]),
        };
        let result = server.update_event(Parameters(req)).await.unwrap();
        let text = result_text(&result);
        assert!(
            text.contains("Room 5"),
            "explicit set should beat clear, got: {text}"
        );
    }

    #[tokio::test]
    async fn update_event_rejects_unknown_clear_field() {
        let server = CalendarServer::new(Arc::new(MockClient));
        let req = UpdateEventReq {
            calendar: "/cal/work/".into(),
            uid: "evt-1".into(),
            summary: None,
            start: None,
            end: None,
            location: None,
            description: None,
            rrule: None,
            clear: Some(vec!["summary".into()]),
        };
        let err = server.update_event(Parameters(req)).await.unwrap_err();
        assert!(
            err.to_string().contains("summary"),
            "expected error naming the bad field, got: {err}"
        );
    }

    #[tokio::test]
    async fn update_task_clears_named_field() {
        let server = CalendarServer::new(Arc::new(MockClient));
        let req = UpdateTaskReq {
            calendar: "/cal/work/".into(),
            uid: "task-1".into(),
            summary: None,
            due: None,
            status: None,
            description: None,
            priority: None,
            clear: Some(vec!["description".into()]),
        };
        let result = server.update_task(Parameters(req)).await.unwrap();
        let text = result_text(&result);
        assert!(
            !text.contains("Original description"),
            "cleared description leaked through: {text}"
        );
        // Untouched status survives.
        assert!(
            text.contains("NEEDS-ACTION"),
            "untouched status was dropped: {text}"
        );
    }

    #[tokio::test]
    async fn update_task_set_beats_clear() {
        let server = CalendarServer::new(Arc::new(MockClient));
        let req = UpdateTaskReq {
            calendar: "/cal/work/".into(),
            uid: "task-1".into(),
            summary: None,
            due: None,
            status: Some(TaskStatus::Completed),
            description: None,
            priority: None,
            // status is both set and cleared - the explicit set must win.
            clear: Some(vec!["status".into()]),
        };
        let result = server.update_task(Parameters(req)).await.unwrap();
        let text = result_text(&result);
        assert!(
            text.contains("COMPLETED"),
            "explicit set should beat clear, got: {text}"
        );
    }

    #[tokio::test]
    async fn update_task_rejects_unknown_clear_field() {
        let server = CalendarServer::new(Arc::new(MockClient));
        let req = UpdateTaskReq {
            calendar: "/cal/work/".into(),
            uid: "task-1".into(),
            summary: None,
            due: None,
            status: None,
            description: None,
            priority: None,
            clear: Some(vec!["uid".into()]),
        };
        let err = server.update_task(Parameters(req)).await.unwrap_err();
        assert!(
            err.to_string().contains("uid"),
            "expected error naming the bad field, got: {err}"
        );
    }

    #[test]
    fn create_task_req_accepts_valid_status() {
        let json = serde_json::json!({
            "calendar": "/cal/work/",
            "summary": "Task",
            "status": "IN-PROCESS"
        });
        let req: CreateTaskReq =
            serde_json::from_value(json).expect("valid status token must deserialize");
        assert!(matches!(req.status, Some(TaskStatus::InProcess)));
    }

    #[test]
    fn create_task_req_rejects_invalid_status() {
        let json = serde_json::json!({
            "calendar": "/cal/work/",
            "summary": "Task",
            "status": "BOGUS"
        });
        assert!(
            serde_json::from_value::<CreateTaskReq>(json).is_err(),
            "an invalid status value must be rejected at deserialization"
        );
    }

    /// Run `list_tasks` with the given filters and return the resulting UIDs, sorted.
    async fn list_task_uids(req: ListTasksReq) -> Vec<String> {
        let server = CalendarServer::new(Arc::new(MockClient));
        let result = server.list_tasks(Parameters(req)).await.unwrap();
        let todos: Vec<Todo> = serde_json::from_str(&result_text(&result)).unwrap();
        let mut uids: Vec<String> = todos.into_iter().map(|t| t.uid).collect();
        uids.sort();
        uids
    }

    #[tokio::test]
    async fn list_tasks_no_filter_returns_all() {
        let uids = list_task_uids(ListTasksReq {
            calendar: "/cal/work/".into(),
            status: None,
            due_before: None,
            due_after: None,
        })
        .await;
        assert_eq!(uids, vec!["a", "b", "c", "d"]);
    }

    #[tokio::test]
    async fn list_tasks_status_filter_is_case_insensitive() {
        // Matches both "a" (stored "needs-action") and "d" (stored "NEEDS-ACTION").
        let uids = list_task_uids(ListTasksReq {
            calendar: "/cal/work/".into(),
            status: Some(TaskStatus::NeedsAction),
            due_before: None,
            due_after: None,
        })
        .await;
        assert_eq!(uids, vec!["a", "d"]);
    }

    #[tokio::test]
    async fn list_tasks_due_before_excludes_undated_and_later() {
        // a (2026-08-01) and b (2026-08-10) are before the cutoff; d (2026-08-20)
        // is after and c has no due date, so both are excluded.
        let uids = list_task_uids(ListTasksReq {
            calendar: "/cal/work/".into(),
            status: None,
            due_before: Some(dt("2026-08-15T00:00:00Z")),
            due_after: None,
        })
        .await;
        assert_eq!(uids, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn list_tasks_due_after_is_inclusive_and_excludes_undated() {
        // due_after is an inclusive lower bound: b (2026-08-10) and d (2026-08-20)
        // qualify; a (2026-08-01) is earlier and c has no due date.
        let uids = list_task_uids(ListTasksReq {
            calendar: "/cal/work/".into(),
            status: None,
            due_before: None,
            due_after: Some(dt("2026-08-10T00:00:00Z")),
        })
        .await;
        assert_eq!(uids, vec!["b", "d"]);
    }

    #[tokio::test]
    async fn list_tasks_combines_status_and_due_window() {
        // NEEDS-ACTION tasks are a and d; the window [08-05, 08-25) keeps only d.
        let uids = list_task_uids(ListTasksReq {
            calendar: "/cal/work/".into(),
            status: Some(TaskStatus::NeedsAction),
            due_before: Some(dt("2026-08-25T00:00:00Z")),
            due_after: Some(dt("2026-08-05T00:00:00Z")),
        })
        .await;
        assert_eq!(uids, vec!["d"]);
    }
}
