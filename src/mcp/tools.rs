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

/// Parameters scoping a request to a single calendar.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CalendarRef {
    /// Calendar href to operate on.
    pub calendar: String,
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
    pub status: Option<String>,
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
    pub status: Option<String>,
    /// New description, if changing.
    pub description: Option<String>,
    /// New priority, if changing.
    pub priority: Option<u8>,
}

/// Serialize `v` as pretty JSON text and wrap it as a successful tool result.
fn ok_json<T: serde::Serialize>(v: &T) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(v)
        .map_err(|e| McpError::internal_error(format!("failed to serialize tool result: {e}"), None))?;
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

/// Map a domain [`Error`] onto the MCP error type.
fn map_err(e: Error) -> McpError {
    McpError::internal_error(e.to_string(), None)
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
    async fn list_events(&self, Parameters(req): Parameters<ListEventsReq>) -> Result<CallToolResult, McpError> {
        let events = self
            .client
            .list_events(&req.calendar, req.start, req.end)
            .await
            .map_err(map_err)?;
        ok_json(&events)
    }

    #[tool(description = "Get a single event by UID.")]
    async fn get_event(&self, Parameters(req): Parameters<GetByUidReq>) -> Result<CallToolResult, McpError> {
        let event = self.client.get_event(&req.calendar, &req.uid).await.map_err(map_err)?;
        ok_json(&event)
    }

    #[tool(description = "Create a new event.")]
    async fn create_event(&self, Parameters(req): Parameters<CreateEventReq>) -> Result<CallToolResult, McpError> {
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
        self.client.put_event(&req.calendar, &event).await.map_err(map_err)?;
        ok_json(&event)
    }

    #[tool(description = "Update an existing event. This always edits the whole series, never a single instance.")]
    async fn update_event(&self, Parameters(req): Parameters<UpdateEventReq>) -> Result<CallToolResult, McpError> {
        let patch = EventPatch {
            summary: req.summary,
            start: req.start,
            end: req.end,
            location: req.location,
            description: req.description,
            rrule: req.rrule,
        };
        let mut event = self.client.get_event(&req.calendar, &req.uid).await.map_err(map_err)?;
        event.apply_patch(patch);
        event.is_instance = false;
        self.client.put_event(&req.calendar, &event).await.map_err(map_err)?;
        ok_json(&event)
    }

    #[tool(description = "Delete an event by UID.")]
    async fn delete_event(&self, Parameters(req): Parameters<GetByUidReq>) -> Result<CallToolResult, McpError> {
        self.client.delete_event(&req.calendar, &req.uid).await.map_err(map_err)?;
        ok_json(&serde_json::json!({ "deleted": req.uid }))
    }

    #[tool(description = "List tasks (VTODOs) in a calendar.")]
    async fn list_tasks(&self, Parameters(req): Parameters<CalendarRef>) -> Result<CallToolResult, McpError> {
        let todos = self.client.list_todos(&req.calendar).await.map_err(map_err)?;
        ok_json(&todos)
    }

    #[tool(description = "Get a single task (VTODO) by UID.")]
    async fn get_task(&self, Parameters(req): Parameters<GetByUidReq>) -> Result<CallToolResult, McpError> {
        let todo = self.client.get_todo(&req.calendar, &req.uid).await.map_err(map_err)?;
        ok_json(&todo)
    }

    #[tool(description = "Create a new task.")]
    async fn create_task(&self, Parameters(req): Parameters<CreateTaskReq>) -> Result<CallToolResult, McpError> {
        let todo = Todo {
            uid: new_uid(),
            href: None,
            etag: None,
            summary: req.summary,
            due: req.due,
            status: req.status,
            description: req.description,
            priority: req.priority,
        };
        self.client.put_todo(&req.calendar, &todo).await.map_err(map_err)?;
        ok_json(&todo)
    }

    #[tool(description = "Update an existing task.")]
    async fn update_task(&self, Parameters(req): Parameters<UpdateTaskReq>) -> Result<CallToolResult, McpError> {
        let patch = TodoPatch {
            summary: req.summary,
            due: req.due,
            status: req.status,
            description: req.description,
            priority: req.priority,
        };
        let mut todo = self.client.get_todo(&req.calendar, &req.uid).await.map_err(map_err)?;
        todo.apply_patch(patch);
        self.client.put_todo(&req.calendar, &todo).await.map_err(map_err)?;
        ok_json(&todo)
    }

    #[tool(description = "Delete a task by UID.")]
    async fn delete_task(&self, Parameters(req): Parameters<GetByUidReq>) -> Result<CallToolResult, McpError> {
        self.client.delete_todo(&req.calendar, &req.uid).await.map_err(map_err)?;
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

        async fn list_events(&self, _cal_href: &str, _start: DateTime<Utc>, _end: DateTime<Utc>) -> Result<Vec<Event>> {
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
                location: None,
                description: None,
                rrule: None,
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
            Ok(vec![])
        }

        async fn get_todo(&self, _cal_href: &str, uid: &str) -> Result<Todo> {
            Ok(Todo {
                uid: uid.to_string(),
                href: Some(format!("/cal/{uid}.ics")),
                etag: Some("\"t1\"".into()),
                summary: "Original task".into(),
                due: None,
                status: None,
                description: None,
                priority: None,
            })
        }

        async fn put_todo(&self, _cal_href: &str, _td: &Todo) -> Result<()> {
            Ok(())
        }

        async fn delete_todo(&self, _cal_href: &str, _uid: &str) -> Result<()> {
            Ok(())
        }
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
        assert!(text.contains("Work"), "expected calendar name in result, got: {text}");
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
        };
        let result = server.update_event(Parameters(req)).await.unwrap();
        let text = result_text(&result);
        assert!(text.contains("New"), "expected patched summary in result, got: {text}");
        // The original summary from MockClient::get_event must be gone - proves the
        // patch replaced it rather than the mock's canned value leaking through.
        assert!(!text.contains("Original summary"), "unpatched summary leaked through: {text}");
    }
}
