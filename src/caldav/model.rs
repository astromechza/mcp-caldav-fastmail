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
