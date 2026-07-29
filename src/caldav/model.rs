use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Calendar {
    /// Collection href relative to the CalDAV base, e.g. "/dav/calendars/user/x/abcd/".
    pub href: String,
    pub display_name: String,
    pub color: Option<String>,
    /// Which components the collection accepts, e.g. ["VEVENT","VTODO"].
    pub components: Vec<String>,
    pub ctag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub uid: String,
    /// Resource href for this object (for updates/deletes), if known.
    pub href: Option<String>,
    pub etag: Option<String>,
    pub summary: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub location: Option<String>,
    pub description: Option<String>,
    /// Raw RRULE string if the event recurs, e.g. "FREQ=WEEKLY;BYDAY=MO".
    pub rrule: Option<String>,
    /// True when this Event is one expanded instance of a recurring series.
    pub is_instance: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Todo {
    pub uid: String,
    pub href: Option<String>,
    pub etag: Option<String>,
    pub summary: String,
    pub due: Option<DateTime<Utc>>,
    /// NEEDS-ACTION | IN-PROCESS | COMPLETED | CANCELLED
    pub status: Option<String>,
    pub description: Option<String>,
    pub priority: Option<u8>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventPatch {
    pub summary: Option<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub location: Option<String>,
    pub description: Option<String>,
    pub rrule: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TodoPatch {
    pub summary: Option<String>,
    pub due: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub priority: Option<u8>,
}

impl Event {
    /// Overlay a partial patch onto this event. Fields left `None` in `p` are
    /// left unchanged. Does not touch `uid`, `href`, `etag`, or `is_instance` -
    /// callers that need to force a whole-series edit should set `is_instance`
    /// themselves after applying the patch.
    pub fn apply_patch(&mut self, p: EventPatch) {
        if let Some(v) = p.summary {
            self.summary = v;
        }
        if let Some(v) = p.start {
            self.start = v;
        }
        if let Some(v) = p.end {
            self.end = v;
        }
        if p.location.is_some() {
            self.location = p.location;
        }
        if p.description.is_some() {
            self.description = p.description;
        }
        if p.rrule.is_some() {
            self.rrule = p.rrule;
        }
    }
}

impl Todo {
    /// Overlay a partial patch onto this task. Fields left `None` in `p` are
    /// left unchanged. Does not touch `uid`, `href`, or `etag`.
    pub fn apply_patch(&mut self, p: TodoPatch) {
        if let Some(v) = p.summary {
            self.summary = v;
        }
        if p.due.is_some() {
            self.due = p.due;
        }
        if p.status.is_some() {
            self.status = p.status;
        }
        if p.description.is_some() {
            self.description = p.description;
        }
        if p.priority.is_some() {
            self.priority = p.priority;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_event() -> Event {
        Event {
            uid: "evt-1".into(),
            href: Some("/cal/evt-1.ics".into()),
            etag: Some("\"e1\"".into()),
            summary: "Standup".into(),
            start: DateTime::parse_from_rfc3339("2026-08-03T09:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            end: DateTime::parse_from_rfc3339("2026-08-03T09:15:00Z")
                .unwrap()
                .with_timezone(&Utc),
            location: Some("Room 1".into()),
            description: Some("Daily sync".into()),
            rrule: Some("FREQ=DAILY".into()),
            is_instance: true,
        }
    }

    fn full_todo() -> Todo {
        Todo {
            uid: "todo-1".into(),
            href: Some("/cal/todo-1.ics".into()),
            etag: Some("\"t1\"".into()),
            summary: "Buy milk".into(),
            due: Some(
                DateTime::parse_from_rfc3339("2026-08-03T09:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            status: Some("NEEDS-ACTION".into()),
            description: Some("2%".into()),
            priority: Some(5),
        }
    }

    #[test]
    fn event_apply_patch_updates_only_set_fields() {
        let mut ev = full_event();
        let original = ev.clone();
        ev.apply_patch(EventPatch {
            summary: Some("New summary".into()),
            ..Default::default()
        });

        assert_eq!(ev.summary, "New summary");
        // Everything else, including the concurrency-guard fields, is untouched.
        assert_eq!(ev.uid, original.uid);
        assert_eq!(ev.href, original.href);
        assert_eq!(ev.etag, original.etag);
        assert_eq!(ev.start, original.start);
        assert_eq!(ev.end, original.end);
        assert_eq!(ev.location, original.location);
        assert_eq!(ev.description, original.description);
        assert_eq!(ev.rrule, original.rrule);
        assert_eq!(ev.is_instance, original.is_instance);
    }

    #[test]
    fn todo_apply_patch_updates_only_set_fields() {
        let mut td = full_todo();
        let original = td.clone();
        td.apply_patch(TodoPatch {
            summary: Some("Buy oat milk".into()),
            ..Default::default()
        });

        assert_eq!(td.summary, "Buy oat milk");
        // Everything else, including the concurrency-guard fields, is untouched.
        assert_eq!(td.uid, original.uid);
        assert_eq!(td.href, original.href);
        assert_eq!(td.etag, original.etag);
        assert_eq!(td.due, original.due);
        assert_eq!(td.status, original.status);
        assert_eq!(td.description, original.description);
        assert_eq!(td.priority, original.priority);
    }
}
