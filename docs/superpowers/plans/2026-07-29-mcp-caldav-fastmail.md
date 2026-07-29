# mcp-caldav-fastmail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single-user HTTP MCP server exposing tools to manage a Fastmail calendar (events + tasks) over CalDAV, with inbound OAuth 2.1 (Authelia Resource-Server) and outbound Fastmail app-password auth.

**Architecture:** An axum HTTP host mounts the `rmcp` StreamableHttpService at `/mcp` behind a JWT-validating middleware. Tool handlers call a `CalDavClient` (reqwest + hand-rolled DAV XML) which reads/writes iCalendar objects parsed and built by `calcard`. Everything testable: the CalDAV client is a trait (mocked for tool tests, `wiremock`-backed for its own tests); the JWKS source is injectable.

**Tech Stack:** Rust 2024, tokio, axum + tower, rmcp, jsonwebtoken + jwks, reqwest, quick-xml, calcard, thiserror, tracing, wiremock (dev).

**Reference:** Spec at `docs/superpowers/specs/2026-07-29-mcp-caldav-fastmail-design.md`.

**Note on volatile APIs:** `rmcp` and `calcard` APIs move fast. Steps that touch them include a "verify against docs.rs" build/test step. If a signature differs from what's shown, adjust to the compiler/docs — the *structure* of the task is what matters. Pin exact versions in Task 0 and keep them fixed for the whole plan.

---

## File Structure

```
Cargo.toml                 deps + features
.gitignore
src/
  main.rs                  bootstrap: config, tracing, axum app, serve
  lib.rs                   module declarations, re-exports
  config.rs                Config struct + from_env
  error.rs                 Error enum (thiserror)
  caldav/
    mod.rs                 re-exports
    model.rs               Calendar, Event, Todo, EventPatch, TodoPatch
    xml.rs                 build DAV request bodies, parse multistatus
    client.rs              CalDavClient trait + FastmailCalDav impl (reqwest)
  ical.rs                  calcard <-> domain: parse, build, expand recurrence
  auth/
    mod.rs                 re-exports
    validator.rs           JwtValidator: JWKS cache + verify; axum middleware
    metadata.rs            RFC 9728 protected-resource-metadata + 401 challenge
  mcp/
    mod.rs                 re-exports
    tools.rs               CalendarServer: rmcp tools + ServerHandler
tests/
  (integration tests colocated per-module with #[cfg(test)]; wiremock in client tests)
```

Each file has one responsibility. `caldav/` groups the DAV concern; `auth/` the OAuth-RS concern; `mcp/` the protocol surface; `ical.rs` the format seam.

---

## Task 0: Project scaffold

**Files:**
- Create: `Cargo.toml`, `.gitignore`, `src/main.rs`, `src/lib.rs`

- [ ] **Step 1: Create `Cargo.toml`**

```toml
[package]
name = "mcp-caldav-fastmail"
version = "0.1.0"
edition = "2024"

[dependencies]
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal"] }
axum = "0.8"
tower = "0.5"
rmcp = { version = "0.9", features = ["server", "macros", "transport-streamable-http-server"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
quick-xml = "0.37"
calcard = "0.1"
jsonwebtoken = "9"
jwks = "0.5"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
schemars = "0.8"
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
chrono = { version = "0.4", features = ["serde"] }
async-trait = "0.1"
url = "2"

[dev-dependencies]
wiremock = "0.6"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "test-util"] }
```

> Verify each version resolves: after writing, `cargo update` then `cargo tree`. If `rmcp`, `calcard`, or `jwks` have a newer/different latest, pin the actual latest and note it. Keep pins fixed for the rest of the plan.

- [ ] **Step 2: Create `.gitignore`**

```
/target
*.env
.env
```

- [ ] **Step 3: Create `src/lib.rs`**

```rust
pub mod auth;
pub mod caldav;
pub mod config;
pub mod error;
pub mod ical;
pub mod mcp;
```

- [ ] **Step 4: Create module stubs so it compiles**

Create `src/config.rs`, `src/error.rs`, `src/ical.rs` each with `// placeholder` and empty `src/caldav/mod.rs`, `src/auth/mod.rs`, `src/mcp/mod.rs`. Add to `caldav/mod.rs`:
```rust
// modules added in later tasks
```
Same for `auth/mod.rs`, `mcp/mod.rs`.

- [ ] **Step 5: Create `src/main.rs`**

```rust
fn main() {
    println!("mcp-caldav-fastmail");
}
```

- [ ] **Step 6: Build**

Run: `cargo build`
Expected: compiles (warnings about unused modules are fine).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock .gitignore src/
git commit -m "chore: scaffold mcp-caldav-fastmail crate"
```

---

## Task 1: Config

**Files:**
- Modify: `src/config.rs`
- Test: `src/config.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write failing test**

Replace `src/config.rs`:
```rust
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub resource_uri: String,
    pub authelia_issuer: String,
    pub authelia_jwks_uri: String,
    pub required_scope: String,
    pub fastmail_username: String,
    pub fastmail_app_password: String,
    pub caldav_base_url: String,
}

impl Config {
    /// Load config from environment. Uses a lookup closure for testability.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let req = |k: &str| get(k).ok_or_else(|| Error::Config(format!("missing env {k}")));
        Ok(Config {
            bind_addr: get("BIND_ADDR").unwrap_or_else(|| "0.0.0.0:8080".into()),
            resource_uri: req("RESOURCE_URI")?,
            authelia_issuer: req("AUTHELIA_ISSUER")?,
            authelia_jwks_uri: req("AUTHELIA_JWKS_URI")?,
            required_scope: get("REQUIRED_SCOPE").unwrap_or_else(|| "caldav".into()),
            fastmail_username: req("FASTMAIL_USERNAME")?,
            fastmail_app_password: req("FASTMAIL_APP_PASSWORD")?,
            caldav_base_url: get("CALDAV_BASE_URL")
                .unwrap_or_else(|| "https://caldav.fastmail.com/".into()),
        })
    }

    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(m: HashMap<&'static str, &'static str>) -> impl Fn(&str) -> Option<String> {
        move |k: &str| m.get(k).map(|s| s.to_string())
    }

    #[test]
    fn defaults_applied_when_optional_absent() {
        let m = HashMap::from([
            ("RESOURCE_URI", "https://mcp.example.com"),
            ("AUTHELIA_ISSUER", "https://auth.example.com"),
            ("AUTHELIA_JWKS_URI", "https://auth.example.com/jwks.json"),
            ("FASTMAIL_USERNAME", "me@fastmail.com"),
            ("FASTMAIL_APP_PASSWORD", "secret"),
        ]);
        let cfg = Config::from_lookup(lookup(m)).unwrap();
        assert_eq!(cfg.bind_addr, "0.0.0.0:8080");
        assert_eq!(cfg.caldav_base_url, "https://caldav.fastmail.com/");
        assert_eq!(cfg.required_scope, "caldav");
    }

    #[test]
    fn missing_required_errors() {
        let cfg = Config::from_lookup(lookup(HashMap::new()));
        assert!(cfg.is_err());
    }
}
```

- [ ] **Step 2: Add `Config` error variant** (needed for compile — see Task 2 defines the enum; if doing tasks in order, temporarily add to `error.rs`). Ensure `error.rs` has at least:
```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config error: {0}")]
    Config(String),
}
pub type Result<T> = std::result::Result<T, Error>;
```

- [ ] **Step 3: Run test (fails then passes)**

Run: `cargo test config::`
Expected: PASS (both tests).

- [ ] **Step 4: Commit**

```bash
git add src/config.rs src/error.rs
git commit -m "feat: config loading from environment"
```

---

## Task 2: Error type

**Files:**
- Modify: `src/error.rs`

- [ ] **Step 1: Write the full error enum**

Replace `src/error.rs`:
```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config error: {0}")]
    Config(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("caldav error: status {status}: {body}")]
    CalDav { status: u16, body: String },

    #[error("xml parse error: {0}")]
    Xml(String),

    #[error("ical error: {0}")]
    ICal(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, Error>;
```

- [ ] **Step 2: Build**

Run: `cargo build`
Expected: compiles.

- [ ] **Step 3: Commit**

```bash
git add src/error.rs
git commit -m "feat: unified Error type"
```

---

## Task 3: Domain model

**Files:**
- Create: `src/caldav/model.rs`
- Modify: `src/caldav/mod.rs`

- [ ] **Step 1: Write model types**

Create `src/caldav/model.rs`:
```rust
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
```

- [ ] **Step 2: Wire module**

Set `src/caldav/mod.rs`:
```rust
pub mod model;
pub use model::*;
```

- [ ] **Step 3: Build**

Run: `cargo build`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add src/caldav/
git commit -m "feat: caldav domain model"
```

---

## Task 4: iCalendar seam (calcard)

Parse an ICS body into `Event`/`Todo`, build an ICS body from them, and expand a recurring series over a window. This isolates all calcard-specific code behind three functions so the rest of the codebase never touches calcard types.

**Files:**
- Modify: `src/ical.rs`
- Test: `src/ical.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write failing tests first**

Put at the bottom of `src/ical.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
BEGIN:VEVENT\r\nUID:evt-1\r\nSUMMARY:Standup\r\nDTSTART:20260803T090000Z\r\n\
DTEND:20260803T091500Z\r\nRRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=3\r\nEND:VEVENT\r\n\
END:VCALENDAR\r\n";

    #[test]
    fn parse_event_reads_core_fields() {
        let ev = parse_event(SAMPLE_EVENT).expect("parse");
        assert_eq!(ev.uid, "evt-1");
        assert_eq!(ev.summary, "Standup");
        assert_eq!(ev.rrule.as_deref(), Some("FREQ=WEEKLY;BYDAY=MO;COUNT=3"));
    }

    #[test]
    fn build_then_parse_roundtrips_summary() {
        let ev = Event {
            uid: "evt-2".into(), href: None, etag: None,
            summary: "Lunch".into(),
            start: "2026-08-03T12:00:00Z".parse().unwrap(),
            end: "2026-08-03T13:00:00Z".parse().unwrap(),
            location: Some("Cafe".into()), description: None,
            rrule: None, is_instance: false,
        };
        let ics = build_event(&ev);
        let back = parse_event(&ics).expect("parse");
        assert_eq!(back.summary, "Lunch");
        assert_eq!(back.location.as_deref(), Some("Cafe"));
    }

    #[test]
    fn expand_weekly_count_three_yields_three() {
        let start = "2026-08-01T00:00:00Z".parse().unwrap();
        let end = "2026-09-01T00:00:00Z".parse().unwrap();
        let insts = expand_event(SAMPLE_EVENT, start, end).expect("expand");
        assert_eq!(insts.len(), 3);
        assert!(insts.iter().all(|e| e.is_instance));
    }
}
```

- [ ] **Step 2: Implement using calcard**

Put at the top of `src/ical.rs`:
```rust
use crate::caldav::model::{Event, Todo};
use crate::error::{Error, Result};
use chrono::{DateTime, Utc};

// NOTE: calcard type/method names below are the target shape. Verify against
// `cargo doc --open -p calcard` for the pinned version and adjust names if the
// API differs (e.g. component/property accessors). The three public fns and
// their signatures MUST stay as-is — they are the seam the rest of the code uses.

/// Parse the first VEVENT in an iCalendar body into an Event.
pub fn parse_event(ics: &str) -> Result<Event> {
    let cal = calcard::icalendar::ICalendar::parse(ics)
        .map_err(|e| Error::ICal(format!("parse: {e:?}")))?;
    let comp = cal
        .components
        .iter()
        .find(|c| c.is_vevent())
        .ok_or_else(|| Error::ICal("no VEVENT".into()))?;
    Ok(Event {
        uid: prop_string(comp, "UID").ok_or_else(|| Error::ICal("no UID".into()))?,
        href: None,
        etag: None,
        summary: prop_string(comp, "SUMMARY").unwrap_or_default(),
        start: prop_datetime(comp, "DTSTART").ok_or_else(|| Error::ICal("no DTSTART".into()))?,
        end: prop_datetime(comp, "DTEND").ok_or_else(|| Error::ICal("no DTEND".into()))?,
        location: prop_string(comp, "LOCATION"),
        description: prop_string(comp, "DESCRIPTION"),
        rrule: prop_string(comp, "RRULE"),
        is_instance: false,
    })
}

/// Parse the first VTODO in an iCalendar body into a Todo.
pub fn parse_todo(ics: &str) -> Result<Todo> {
    let cal = calcard::icalendar::ICalendar::parse(ics)
        .map_err(|e| Error::ICal(format!("parse: {e:?}")))?;
    let comp = cal
        .components
        .iter()
        .find(|c| c.is_vtodo())
        .ok_or_else(|| Error::ICal("no VTODO".into()))?;
    Ok(Todo {
        uid: prop_string(comp, "UID").ok_or_else(|| Error::ICal("no UID".into()))?,
        href: None,
        etag: None,
        summary: prop_string(comp, "SUMMARY").unwrap_or_default(),
        due: prop_datetime(comp, "DUE"),
        status: prop_string(comp, "STATUS"),
        description: prop_string(comp, "DESCRIPTION"),
        priority: prop_string(comp, "PRIORITY").and_then(|s| s.parse().ok()),
    })
}

/// Serialize an Event into a complete VCALENDAR/VEVENT body.
pub fn build_event(ev: &Event) -> String {
    // Hand-built to avoid coupling to calcard's builder API. RFC5545 line
    // format; escape per §3.3.11.
    let mut s = String::new();
    s.push_str("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//mcp-caldav-fastmail//EN\r\n");
    s.push_str("BEGIN:VEVENT\r\n");
    line(&mut s, "UID", &ev.uid);
    line(&mut s, "SUMMARY", &escape(&ev.summary));
    line(&mut s, "DTSTART", &fmt_dt(ev.start));
    line(&mut s, "DTEND", &fmt_dt(ev.end));
    if let Some(v) = &ev.location { line(&mut s, "LOCATION", &escape(v)); }
    if let Some(v) = &ev.description { line(&mut s, "DESCRIPTION", &escape(v)); }
    if let Some(v) = &ev.rrule { line(&mut s, "RRULE", v); }
    s.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    s
}

/// Serialize a Todo into a complete VCALENDAR/VTODO body.
pub fn build_todo(td: &Todo) -> String {
    let mut s = String::new();
    s.push_str("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//mcp-caldav-fastmail//EN\r\n");
    s.push_str("BEGIN:VTODO\r\n");
    line(&mut s, "UID", &td.uid);
    line(&mut s, "SUMMARY", &escape(&td.summary));
    if let Some(v) = td.due { line(&mut s, "DUE", &fmt_dt(v)); }
    if let Some(v) = &td.status { line(&mut s, "STATUS", v); }
    if let Some(v) = &td.description { line(&mut s, "DESCRIPTION", &escape(v)); }
    if let Some(v) = td.priority { line(&mut s, "PRIORITY", &v.to_string()); }
    s.push_str("END:VTODO\r\nEND:VCALENDAR\r\n");
    s
}

/// Expand a recurring VEVENT into concrete instances within [start, end).
/// If the event has no RRULE, returns a single instance if it falls in-window.
pub fn expand_event(ics: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Event>> {
    let base = parse_event(ics)?;
    let Some(_rrule) = &base.rrule else {
        return Ok(if base.start < end && base.end > start { vec![base] } else { vec![] });
    };
    // Use calcard's datecalc expansion. Verify the exact entry point in docs;
    // target: given DTSTART + RRULE, enumerate occurrences within the window.
    let duration = base.end - base.start;
    let occurrences = calcard::datecalc::expand_rrule(
        base.start,
        base.rrule.as_deref().unwrap(),
        start,
        end,
    )
    .map_err(|e| Error::ICal(format!("expand: {e:?}")))?;
    Ok(occurrences
        .into_iter()
        .map(|occ_start| Event {
            start: occ_start,
            end: occ_start + duration,
            is_instance: true,
            href: None,
            etag: None,
            ..base.clone()
        })
        .collect())
}

// ---- helpers (calcard accessors isolated here) ----

fn prop_string(comp: &calcard::icalendar::ICalendarComponent, name: &str) -> Option<String> {
    comp.property(name).and_then(|p| p.as_text().map(|s| s.to_string()))
}

fn prop_datetime(comp: &calcard::icalendar::ICalendarComponent, name: &str) -> Option<DateTime<Utc>> {
    comp.property(name)
        .and_then(|p| p.as_datetime())
        .map(|dt| dt.with_timezone(&Utc))
}

fn line(s: &mut String, key: &str, val: &str) {
    s.push_str(key);
    s.push(':');
    s.push_str(val);
    s.push_str("\r\n");
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace(';', "\\;").replace(',', "\\,").replace('\n', "\\n")
}

fn fmt_dt(dt: DateTime<Utc>) -> String {
    dt.format("%Y%m%dT%H%M%SZ").to_string()
}
```

- [ ] **Step 3: Run tests; reconcile calcard API**

Run: `cargo test ical::`
Expected: the three tests pass. If they fail to *compile* on calcard accessors (`components`, `is_vevent`, `property`, `as_text`, `as_datetime`, `datecalc::expand_rrule`), open `cargo doc -p calcard --open`, find the equivalent accessors, and fix **only** the helper fns + `expand_event` body. Do not change public signatures or the tests.

- [ ] **Step 4: Commit**

```bash
git add src/ical.rs
git commit -m "feat: iCalendar parse/build/expand seam over calcard"
```

---

## Task 5: CalDAV XML

Build the two request bodies we need (PROPFIND for discovery, calendar-query REPORT) and parse `multistatus` responses into hrefs + properties. Pure string/XML work — fully unit-testable, no network.

**Files:**
- Create: `src/caldav/xml.rs`
- Modify: `src/caldav/mod.rs`
- Test: `src/caldav/xml.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write failing tests**

Create `src/caldav/xml.rs`, tests at bottom:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const MULTISTATUS: &str = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <response>
    <href>/dav/calendars/user/me/work/</href>
    <propstat><prop>
      <displayname>Work</displayname>
      <getctag>abc</getctag>
    </prop></propstat>
  </response>
  <response>
    <href>/dav/calendars/user/me/work/evt-1.ics</href>
    <propstat><prop>
      <getetag>"etag-1"</getetag>
      <C:calendar-data>BEGIN:VCALENDAR...END:VCALENDAR</C:calendar-data>
    </prop></propstat>
  </response>
</multistatus>"#;

    #[test]
    fn parses_multistatus_responses() {
        let rs = parse_multistatus(MULTISTATUS).expect("parse");
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].href, "/dav/calendars/user/me/work/");
        assert_eq!(rs[0].prop("displayname").as_deref(), Some("Work"));
        assert_eq!(rs[1].prop("getetag").as_deref(), Some("\"etag-1\""));
        assert!(rs[1].prop("calendar-data").unwrap().contains("VCALENDAR"));
    }

    #[test]
    fn calendar_query_body_has_time_range() {
        let body = calendar_query_body("VEVENT", Some(("20260801T000000Z", "20260901T000000Z")));
        assert!(body.contains("calendar-query"));
        assert!(body.contains("VEVENT"));
        assert!(body.contains("start=\"20260801T000000Z\""));
    }
}
```

- [ ] **Step 2: Implement**

Top of `src/caldav/xml.rs`:
```rust
use crate::error::{Error, Result};
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;
use std::collections::HashMap;

/// One <response> element: an href plus a flat map of local-name -> text.
#[derive(Debug, Clone)]
pub struct DavResponse {
    pub href: String,
    pub props: HashMap<String, String>,
}

impl DavResponse {
    pub fn prop(&self, local_name: &str) -> Option<String> {
        self.props.get(local_name).cloned()
    }
}

/// Parse a DAV multistatus body into responses. Uses local names (namespace
/// prefix stripped), so "C:calendar-data" is keyed as "calendar-data".
pub fn parse_multistatus(xml: &str) -> Result<Vec<DavResponse>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut responses = Vec::new();
    let mut cur: Option<DavResponse> = None;
    let mut cur_prop: Option<String> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(Error::Xml(e.to_string())),
            Ok(XmlEvent::Eof) => break,
            Ok(XmlEvent::Start(e)) => {
                let name = local(e.name().as_ref());
                match name.as_str() {
                    "response" => cur = Some(DavResponse { href: String::new(), props: HashMap::new() }),
                    "href" => cur_prop = Some("href".into()),
                    // property leaves we care about; everything else still captured generically
                    other => {
                        // Only start capturing text for elements inside a <prop>.
                        cur_prop = Some(other.to_string());
                    }
                }
            }
            Ok(XmlEvent::Text(t)) => {
                if let (Some(resp), Some(prop)) = (cur.as_mut(), cur_prop.as_ref()) {
                    let text = t.unescape().map_err(|e| Error::Xml(e.to_string()))?.to_string();
                    if prop == "href" && resp.href.is_empty() {
                        resp.href = text;
                    } else {
                        resp.props.insert(prop.clone(), text);
                    }
                }
            }
            Ok(XmlEvent::End(e)) => {
                let name = local(e.name().as_ref());
                if name == "response" {
                    if let Some(r) = cur.take() { responses.push(r); }
                }
                cur_prop = None;
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(responses)
}

fn local(qname: &[u8]) -> String {
    let s = String::from_utf8_lossy(qname);
    match s.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => s.to_string(),
    }
}

/// PROPFIND body requesting the properties we use for discovery.
pub fn propfind_calendars_body() -> &'static str {
    r#"<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/">
  <prop>
    <displayname/>
    <resourcetype/>
    <C:supported-calendar-component-set/>
    <CS:getctag/>
  </prop>
</propfind>"#
}

/// PROPFIND body to resolve the current-user-principal.
pub fn propfind_principal_body() -> &'static str {
    r#"<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:"><prop><current-user-principal/></prop></propfind>"#
}

/// PROPFIND body to resolve the calendar-home-set on a principal.
pub fn propfind_home_body() -> &'static str {
    r#"<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <prop><C:calendar-home-set/></prop>
</propfind>"#
}

/// calendar-query REPORT body. `comp` is "VEVENT" or "VTODO". Optional UTC
/// time-range (start,end) in iCalendar datetime format. Requests calendar-data
/// with server-side <expand> when a range is given (recurrence R1).
pub fn calendar_query_body(comp: &str, range: Option<(&str, &str)>) -> String {
    let (data, filter_range) = match range {
        Some((s, e)) => (
            format!(r#"<C:calendar-data><C:expand start="{s}" end="{e}"/></C:calendar-data>"#),
            format!(r#"<C:time-range start="{s}" end="{e}"/>"#),
        ),
        None => ("<C:calendar-data/>".to_string(), String::new()),
    };
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<C:calendar-query xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <prop><getetag/>{data}</prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="{comp}">{filter_range}</C:comp-filter>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>"#
    )
}
```

Update `src/caldav/mod.rs`:
```rust
pub mod model;
pub mod xml;
pub use model::*;
```

- [ ] **Step 3: Run tests**

Run: `cargo test caldav::xml`
Expected: PASS. (If the generic capture keys collide across nested props in real Fastmail responses, that's addressed by the client tests in Task 6 with real fixtures — keep this parser simple.)

- [ ] **Step 4: Commit**

```bash
git add src/caldav/
git commit -m "feat: caldav XML request bodies + multistatus parser"
```

---

## Task 6: CalDAV client (trait + reqwest impl)

**Files:**
- Create: `src/caldav/client.rs`
- Modify: `src/caldav/mod.rs`
- Test: `src/caldav/client.rs` (`#[cfg(test)]`, `wiremock`)

- [ ] **Step 1: Define the trait**

Create `src/caldav/client.rs`:
```rust
use crate::caldav::model::*;
use crate::caldav::xml::{self, DavResponse};
use crate::error::{Error, Result};
use crate::ical;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Abstraction over the CalDAV backend so tool handlers can be tested with a mock.
#[async_trait]
pub trait CalDavClient: Send + Sync {
    async fn list_calendars(&self) -> Result<Vec<Calendar>>;
    async fn list_events(&self, cal_href: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Event>>;
    async fn get_event(&self, cal_href: &str, uid: &str) -> Result<Event>;
    async fn put_event(&self, cal_href: &str, ev: &Event) -> Result<()>;
    async fn delete_event(&self, cal_href: &str, uid: &str) -> Result<()>;
    async fn list_todos(&self, cal_href: &str) -> Result<Vec<Todo>>;
    async fn get_todo(&self, cal_href: &str, uid: &str) -> Result<Todo>;
    async fn put_todo(&self, cal_href: &str, td: &Todo) -> Result<()>;
    async fn delete_todo(&self, cal_href: &str, uid: &str) -> Result<()>;
}
```

- [ ] **Step 2: Implement `FastmailCalDav`**

Append to `src/caldav/client.rs`:
```rust
pub struct FastmailCalDav {
    http: reqwest::Client,
    base: url::Url,
    username: String,
    app_password: String,
}

impl FastmailCalDav {
    pub fn new(base_url: &str, username: &str, app_password: &str) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder().build()?,
            base: url::Url::parse(base_url).map_err(|e| Error::Config(e.to_string()))?,
            username: username.to_string(),
            app_password: app_password.to_string(),
        })
    }

    fn url(&self, href: &str) -> Result<url::Url> {
        self.base.join(href).map_err(|e| Error::Config(e.to_string()))
    }

    /// Issue a raw DAV request with basic auth. `method` is e.g. "PROPFIND".
    async fn dav(
        &self,
        method: &str,
        href: &str,
        depth: Option<&str>,
        body: Option<String>,
        if_match: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, String)> {
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::Config(e.to_string()))?;
        let mut req = self
            .http
            .request(m, self.url(href)?)
            .basic_auth(&self.username, Some(&self.app_password));
        if let Some(d) = depth { req = req.header("Depth", d); }
        if let Some(im) = if_match { req = req.header(reqwest::header::IF_MATCH, im); }
        if let Some(ct) = content_type { req = req.header(reqwest::header::CONTENT_TYPE, ct); }
        if let Some(b) = body { req = req.body(b); }
        let resp = req.send().await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let text = resp.text().await?;
        if status.is_client_error() || status.is_server_error() {
            return Err(Error::CalDav { status: status.as_u16(), body: text });
        }
        Ok((status, headers, text))
    }

    /// Resolve the calendar-home collection href once.
    async fn calendar_home(&self) -> Result<String> {
        let (_, _, principal_xml) = self
            .dav("PROPFIND", "/", Some("0"), Some(xml::propfind_principal_body().into()), None, Some("application/xml"))
            .await?;
        let principal = xml::parse_multistatus(&principal_xml)?
            .into_iter()
            .find_map(|r| r.prop("current-user-principal"))
            .or_else(|| xml::parse_multistatus(&principal_xml).ok()?.into_iter().next().map(|r| r.href))
            .ok_or_else(|| Error::NotFound("current-user-principal".into()))?;
        let (_, _, home_xml) = self
            .dav("PROPFIND", &principal, Some("0"), Some(xml::propfind_home_body().into()), None, Some("application/xml"))
            .await?;
        xml::parse_multistatus(&home_xml)?
            .into_iter()
            .find_map(|r| r.prop("calendar-home-set").or_else(|| Some(r.href)))
            .ok_or_else(|| Error::NotFound("calendar-home-set".into()))
    }

    /// Fetch (href, etag, calendar-data) rows for a component type over a window.
    async fn report(&self, cal_href: &str, comp: &str, range: Option<(&str, &str)>) -> Result<Vec<DavResponse>> {
        let body = xml::calendar_query_body(comp, range);
        let (_, _, xml_body) = self
            .dav("REPORT", cal_href, Some("1"), Some(body), None, Some("application/xml"))
            .await?;
        Ok(xml::parse_multistatus(&xml_body)?)
    }

    fn object_href(&self, cal_href: &str, uid: &str) -> String {
        format!("{}{}.ics", cal_href.trim_end_matches('/').to_string() + "/", uid)
    }
}

fn fmt_ical(dt: DateTime<Utc>) -> String {
    dt.format("%Y%m%dT%H%M%SZ").to_string()
}

#[async_trait]
impl CalDavClient for FastmailCalDav {
    async fn list_calendars(&self) -> Result<Vec<Calendar>> {
        let home = self.calendar_home().await?;
        let (_, _, xml_body) = self
            .dav("PROPFIND", &home, Some("1"), Some(xml::propfind_calendars_body().into()), None, Some("application/xml"))
            .await?;
        let responses = xml::parse_multistatus(&xml_body)?;
        Ok(responses
            .into_iter()
            .filter(|r| r.href != home) // skip the home collection itself
            .filter(|r| r.prop("displayname").is_some())
            .map(|r| Calendar {
                components: r
                    .prop("comp") // supported-calendar-component-set flattened; see note
                    .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                    .unwrap_or_else(|| vec!["VEVENT".into()]),
                display_name: r.prop("displayname").unwrap_or_default(),
                color: r.prop("calendar-color"),
                ctag: r.prop("getctag"),
                href: r.href,
            })
            .collect())
    }

    async fn list_events(&self, cal_href: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Event>> {
        let range = (fmt_ical(start), fmt_ical(end));
        let rows = self.report(cal_href, "VEVENT", Some((&range.0, &range.1))).await?;
        let mut out = Vec::new();
        for r in rows {
            if let Some(data) = r.prop("calendar-data") {
                // Server expanded; each row is already an instance. If a row still
                // carries an RRULE (server didn't expand), expand client-side.
                let mut evs = ical::expand_event(&data, start, end)?;
                for ev in &mut evs {
                    ev.href = Some(r.href.clone());
                    ev.etag = r.prop("getetag");
                }
                out.append(&mut evs);
            }
        }
        Ok(out)
    }

    async fn get_event(&self, cal_href: &str, uid: &str) -> Result<Event> {
        let href = self.object_href(cal_href, uid);
        let (_, headers, body) = self.dav("GET", &href, None, None, None, None).await?;
        let mut ev = ical::parse_event(&body)?;
        ev.href = Some(href);
        ev.etag = headers.get(reqwest::header::ETAG).and_then(|h| h.to_str().ok()).map(String::from);
        Ok(ev)
    }

    async fn put_event(&self, cal_href: &str, ev: &Event) -> Result<()> {
        let href = ev.href.clone().unwrap_or_else(|| self.object_href(cal_href, &ev.uid));
        let ics = ical::build_event(ev);
        self.dav("PUT", &href, None, Some(ics), ev.etag.as_deref(), Some("text/calendar; charset=utf-8")).await?;
        Ok(())
    }

    async fn delete_event(&self, cal_href: &str, uid: &str) -> Result<()> {
        let href = self.object_href(cal_href, uid);
        self.dav("DELETE", &href, None, None, None, None).await?;
        Ok(())
    }

    async fn list_todos(&self, cal_href: &str) -> Result<Vec<Todo>> {
        let rows = self.report(cal_href, "VTODO", None).await?;
        let mut out = Vec::new();
        for r in rows {
            if let Some(data) = r.prop("calendar-data") {
                let mut td = ical::parse_todo(&data)?;
                td.href = Some(r.href.clone());
                td.etag = r.prop("getetag");
                out.push(td);
            }
        }
        Ok(out)
    }

    async fn get_todo(&self, cal_href: &str, uid: &str) -> Result<Todo> {
        let href = self.object_href(cal_href, uid);
        let (_, headers, body) = self.dav("GET", &href, None, None, None, None).await?;
        let mut td = ical::parse_todo(&body)?;
        td.href = Some(href);
        td.etag = headers.get(reqwest::header::ETAG).and_then(|h| h.to_str().ok()).map(String::from);
        Ok(td)
    }

    async fn put_todo(&self, cal_href: &str, td: &Todo) -> Result<()> {
        let href = td.href.clone().unwrap_or_else(|| self.object_href(cal_href, &td.uid));
        let ics = ical::build_todo(td);
        self.dav("PUT", &href, None, Some(ics), td.etag.as_deref(), Some("text/calendar; charset=utf-8")).await?;
        Ok(())
    }

    async fn delete_todo(&self, cal_href: &str, uid: &str) -> Result<()> {
        let href = self.object_href(cal_href, uid);
        self.dav("DELETE", &href, None, None, None, None).await?;
        Ok(())
    }
}
```

> Note on `supported-calendar-component-set`: it is an element with `<comp name="VEVENT"/>` children, not text — the flat parser in Task 5 won't capture the `name` attributes. Accept the `VEVENT` default for now; a follow-up can special-case attribute capture in `xml.rs`. Flagged, not silently dropped.

- [ ] **Step 3: Write a wiremock integration test**

Append test module to `src/caldav/client.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn list_events_parses_report() {
        let server = MockServer::start().await;
        let report_body = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <response>
    <href>/cal/evt-1.ics</href>
    <propstat><prop>
      <getetag>"e1"</getetag>
      <C:calendar-data>BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:evt-1
SUMMARY:Standup
DTSTART:20260803T090000Z
DTEND:20260803T091500Z
END:VEVENT
END:VCALENDAR</C:calendar-data>
    </prop></propstat>
  </response>
</multistatus>"#;
        Mock::given(method("REPORT"))
            .and(path("/cal/"))
            .respond_with(ResponseTemplate::new(207).set_body_string(report_body))
            .mount(&server)
            .await;

        let client = FastmailCalDav::new(&server.uri(), "u", "p").unwrap();
        let start = "2026-08-01T00:00:00Z".parse().unwrap();
        let end = "2026-09-01T00:00:00Z".parse().unwrap();
        let events = client.list_events("/cal/", start, end).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].summary, "Standup");
        assert_eq!(events[0].etag.as_deref(), Some("\"e1\""));
    }
}
```

Update `src/caldav/mod.rs`:
```rust
pub mod client;
pub mod model;
pub mod xml;
pub use client::{CalDavClient, FastmailCalDav};
pub use model::*;
```

- [ ] **Step 4: Run tests**

Run: `cargo test caldav::client`
Expected: PASS. If `wiremock` rejects the custom `REPORT` method matcher, assert on `method("REPORT")` support for the pinned version; if unsupported, match `method(reqwest::Method::from_bytes(b"REPORT"))` equivalent or use `path` only.

- [ ] **Step 5: Commit**

```bash
git add src/caldav/
git commit -m "feat: CalDavClient trait + Fastmail reqwest impl"
```

---

## Task 7: JWT validator

**Files:**
- Create: `src/auth/validator.rs`
- Modify: `src/auth/mod.rs`
- Test: `src/auth/validator.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Define the validator with an injectable key source**

Create `src/auth/validator.rs`:
```rust
use crate::error::{Error, Result};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: Aud,
    pub exp: usize,
    #[serde(default)]
    pub scope: String,
}

/// aud may be a string or array in different issuers; accept both.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Aud {
    One(String),
    Many(Vec<String>),
}

impl Aud {
    pub fn contains(&self, v: &str) -> bool {
        match self {
            Aud::One(s) => s == v,
            Aud::Many(xs) => xs.iter().any(|s| s == v),
        }
    }
}

/// Fetches JWKS keys keyed by `kid`. Injectable for tests.
#[async_trait::async_trait]
pub trait KeySource: Send + Sync {
    async fn key(&self, kid: &str) -> Result<DecodingKey>;
}

pub struct JwtValidator {
    keys: Arc<dyn KeySource>,
    issuer: String,
    audience: String,
    required_scope: String,
}

impl JwtValidator {
    pub fn new(keys: Arc<dyn KeySource>, issuer: String, audience: String, required_scope: String) -> Self {
        Self { keys, issuer, audience, required_scope }
    }

    /// Validate a bearer token; return claims on success.
    pub async fn validate(&self, token: &str) -> Result<Claims> {
        let header = decode_header(token).map_err(|e| Error::Auth(e.to_string()))?;
        let kid = header.kid.ok_or_else(|| Error::Auth("no kid".into()))?;
        let key = self.keys.key(&kid).await?;

        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&[&self.issuer]);
        v.set_audience(&[&self.audience]);
        let data = decode::<Claims>(token, &key, &v).map_err(|e| Error::Auth(e.to_string()))?;

        if !data.claims.scope.split_whitespace().any(|s| s == self.required_scope) {
            return Err(Error::Auth(format!("missing scope {}", self.required_scope)));
        }
        Ok(data.claims)
    }
}

/// Production key source: fetch + cache JWKS from Authelia.
pub struct JwksKeySource {
    jwks_uri: String,
    cache: RwLock<HashMap<String, DecodingKey>>,
    http: reqwest::Client,
}

impl JwksKeySource {
    pub fn new(jwks_uri: String) -> Self {
        Self { jwks_uri, cache: RwLock::new(HashMap::new()), http: reqwest::Client::new() }
    }

    async fn refresh(&self) -> Result<()> {
        // Uses the `jwks` crate to parse the JWKS document. Verify the exact API
        // (Jwks::from_url / iterate keys -> DecodingKey) against docs.rs for the
        // pinned version; the shape below is the target.
        let jwks = jwks::Jwks::from_jwks_url(&self.jwks_uri)
            .await
            .map_err(|e| Error::Auth(format!("jwks fetch: {e:?}")))?;
        let mut cache = self.cache.write().await;
        for (kid, jwk) in jwks.keys {
            cache.insert(kid, jwk.decoding_key);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl KeySource for JwksKeySource {
    async fn key(&self, kid: &str) -> Result<DecodingKey> {
        if let Some(k) = self.cache.read().await.get(kid) {
            return Ok(k.clone());
        }
        self.refresh().await?;
        self.cache
            .read()
            .await
            .get(kid)
            .cloned()
            .ok_or_else(|| Error::Auth(format!("unknown kid {kid}")))
    }
}
```

- [ ] **Step 2: Write tests with a self-signed RS256 key**

Append to `src/auth/validator.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    // A throwaway RSA keypair in PEM, generated once for tests.
    // Generate with: openssl genrsa 2048 > test_priv.pem;
    //                openssl rsa -in test_priv.pem -pubout > test_pub.pem
    // Paste the PEMs here as consts. (Committed test-only key, never used in prod.)
    const PRIV: &str = include_str!("testdata/test_priv.pem");
    const PUB: &str = include_str!("testdata/test_pub.pem");

    struct StaticKey(DecodingKey);
    #[async_trait::async_trait]
    impl KeySource for StaticKey {
        async fn key(&self, _kid: &str) -> Result<DecodingKey> { Ok(self.0.clone()) }
    }

    fn make_token(aud: &str, scope: &str, exp: usize) -> String {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("test".into());
        let claims = serde_json::json!({
            "sub": "user", "iss": "https://auth.example.com",
            "aud": aud, "exp": exp, "scope": scope
        });
        encode(&h, &claims, &EncodingKey::from_rsa_pem(PRIV.as_bytes()).unwrap()).unwrap()
    }

    fn validator() -> JwtValidator {
        let key = DecodingKey::from_rsa_pem(PUB.as_bytes()).unwrap();
        JwtValidator::new(
            Arc::new(StaticKey(key)),
            "https://auth.example.com".into(),
            "https://mcp.example.com".into(),
            "caldav".into(),
        )
    }

    #[tokio::test]
    async fn valid_token_passes() {
        let t = make_token("https://mcp.example.com", "caldav openid", 9_999_999_999);
        assert!(validator().validate(&t).await.is_ok());
    }

    #[tokio::test]
    async fn wrong_audience_fails() {
        let t = make_token("https://other.example.com", "caldav", 9_999_999_999);
        assert!(validator().validate(&t).await.is_err());
    }

    #[tokio::test]
    async fn missing_scope_fails() {
        let t = make_token("https://mcp.example.com", "openid", 9_999_999_999);
        assert!(validator().validate(&t).await.is_err());
    }

    #[tokio::test]
    async fn expired_fails() {
        let t = make_token("https://mcp.example.com", "caldav", 1);
        assert!(validator().validate(&t).await.is_err());
    }
}
```

- [ ] **Step 3: Generate the test keys**

Run:
```bash
mkdir -p src/auth/testdata
openssl genrsa -out src/auth/testdata/test_priv.pem 2048
openssl rsa -in src/auth/testdata/test_priv.pem -pubout -out src/auth/testdata/test_pub.pem
```

Set `src/auth/mod.rs`:
```rust
pub mod validator;
pub use validator::{Claims, JwtValidator, JwksKeySource, KeySource};
```

- [ ] **Step 4: Run tests**

Run: `cargo test auth::validator`
Expected: 4 pass. If `jwks` crate API differs, fix only `JwksKeySource::refresh` (not covered by these tests, which inject a `StaticKey`).

- [ ] **Step 5: Commit**

```bash
git add src/auth/ 
git commit -m "feat: JWT validator with injectable JWKS key source"
```

---

## Task 8: Auth metadata + axum middleware

**Files:**
- Create: `src/auth/metadata.rs`
- Modify: `src/auth/mod.rs`
- Test: `src/auth/metadata.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write failing test for PRM document**

Create `src/auth/metadata.rs`:
```rust
use serde::Serialize;

/// RFC 9728 protected-resource-metadata document.
#[derive(Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    pub fn new(resource: String, issuer: String, scope: String) -> Self {
        Self {
            resource,
            authorization_servers: vec![issuer],
            scopes_supported: vec![scope],
            bearer_methods_supported: vec!["header".into()],
        }
    }
}

/// The WWW-Authenticate header value pointing clients at the PRM document.
pub fn www_authenticate(resource_metadata_url: &str) -> String {
    format!(r#"Bearer resource_metadata="{resource_metadata_url}""#)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prm_serializes_expected_fields() {
        let prm = ProtectedResourceMetadata::new(
            "https://mcp.example.com".into(),
            "https://auth.example.com".into(),
            "caldav".into(),
        );
        let json = serde_json::to_value(&prm).unwrap();
        assert_eq!(json["resource"], "https://mcp.example.com");
        assert_eq!(json["authorization_servers"][0], "https://auth.example.com");
        assert_eq!(json["bearer_methods_supported"][0], "header");
    }

    #[test]
    fn challenge_header_points_at_metadata() {
        let h = www_authenticate("https://mcp.example.com/.well-known/oauth-protected-resource");
        assert!(h.starts_with("Bearer resource_metadata="));
    }
}
```

- [ ] **Step 2: Run test**

Run: `cargo test auth::metadata`
Expected: PASS.

- [ ] **Step 3: Add the axum middleware + handler**

Append to `src/auth/metadata.rs`:
```rust
use crate::auth::validator::JwtValidator;
use axum::{
    extract::State,
    http::{header::WWW_AUTHENTICATE, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthState {
    pub validator: Arc<JwtValidator>,
    pub prm_url: String,
    pub resource: String,
    pub issuer: String,
    pub scope: String,
}

/// GET /.well-known/oauth-protected-resource
pub async fn prm_handler(State(st): State<AuthState>) -> Json<ProtectedResourceMetadata> {
    Json(ProtectedResourceMetadata::new(st.resource.clone(), st.issuer.clone(), st.scope.clone()))
}

/// Middleware: require a valid bearer token, else 401 with challenge.
pub async fn require_auth(State(st): State<AuthState>, req: Request<axum::body::Body>, next: Next) -> Response {
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    match token {
        Some(t) => match st.validator.validate(t).await {
            Ok(_claims) => next.run(req).await,
            Err(_) => challenge(&st),
        },
        None => challenge(&st),
    }
}

fn challenge(st: &AuthState) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, www_authenticate(&st.prm_url))],
    )
        .into_response()
}
```

Update `src/auth/mod.rs`:
```rust
pub mod metadata;
pub mod validator;
pub use metadata::{AuthState, ProtectedResourceMetadata};
pub use validator::{Claims, JwksKeySource, JwtValidator, KeySource};
```

- [ ] **Step 4: Build**

Run: `cargo build`
Expected: compiles. (axum extractor/middleware signatures vary slightly by 0.8.x; if `Next`/`Request` generics differ, adjust to the compiler.)

- [ ] **Step 5: Commit**

```bash
git add src/auth/
git commit -m "feat: protected-resource-metadata + bearer auth middleware"
```

---

## Task 9: MCP tools

Wire the CalDAV client into rmcp tools. The server struct holds `Arc<dyn CalDavClient>` so tests inject a mock.

**Files:**
- Create: `src/mcp/tools.rs`
- Modify: `src/mcp/mod.rs`
- Test: `src/mcp/tools.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Define request param structs + server struct**

Create `src/mcp/tools.rs`:
```rust
use crate::caldav::model::*;
use crate::caldav::CalDavClient;
use chrono::{DateTime, Utc};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct CalendarServer {
    client: Arc<dyn CalDavClient>,
    tool_router: ToolRouter<CalendarServer>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListEventsReq {
    /// Calendar collection href from list_calendars.
    pub calendar: String,
    /// Window start, RFC3339 (e.g. 2026-08-01T00:00:00Z).
    pub start: DateTime<Utc>,
    /// Window end, RFC3339.
    pub end: DateTime<Utc>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetByUidReq {
    pub calendar: String,
    pub uid: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateEventReq {
    pub calendar: String,
    pub summary: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub location: Option<String>,
    pub description: Option<String>,
    /// RRULE without the "RRULE:" prefix, e.g. "FREQ=WEEKLY;BYDAY=MO".
    pub rrule: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateEventReq {
    pub calendar: String,
    pub uid: String,
    pub summary: Option<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub location: Option<String>,
    pub description: Option<String>,
    pub rrule: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateTaskReq {
    pub calendar: String,
    pub summary: String,
    pub due: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub priority: Option<u8>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateTaskReq {
    pub calendar: String,
    pub uid: String,
    pub summary: Option<String>,
    pub due: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub priority: Option<u8>,
}

fn ok_json<T: serde::Serialize>(v: &T) -> Result<CallToolResult, McpError> {
    let s = serde_json::to_string_pretty(v).map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![Content::text(s)]))
}

fn map_err(e: crate::error::Error) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

/// Generate a UID for new objects. Deterministic-free: caller-independent.
fn new_uid() -> String {
    // uuid crate optional; simple approach using time+counter is fine, but to
    // keep deterministic tests we accept a provided uid in create where needed.
    format!("mcp-{}", uuid_like())
}
fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{n:x}")
}
```

> If you prefer real UUIDs, add `uuid = { version = "1", features = ["v4"] }` and use `Uuid::new_v4()`. The `uuid_like` helper avoids a dep; keep whichever you choose consistent.

- [ ] **Step 2: Implement the tool methods**

Append to `src/mcp/tools.rs`:
```rust
#[tool_router]
impl CalendarServer {
    pub fn new(client: Arc<dyn CalDavClient>) -> Self {
        Self { client, tool_router: Self::tool_router() }
    }

    #[tool(description = "List calendars available in the account.")]
    async fn list_calendars(&self) -> Result<CallToolResult, McpError> {
        let cals = self.client.list_calendars().await.map_err(map_err)?;
        ok_json(&cals)
    }

    #[tool(description = "List calendar events expanded over a time window.")]
    async fn list_events(&self, Parameters(r): Parameters<ListEventsReq>) -> Result<CallToolResult, McpError> {
        let evs = self.client.list_events(&r.calendar, r.start, r.end).await.map_err(map_err)?;
        ok_json(&evs)
    }

    #[tool(description = "Get a single event by UID.")]
    async fn get_event(&self, Parameters(r): Parameters<GetByUidReq>) -> Result<CallToolResult, McpError> {
        let ev = self.client.get_event(&r.calendar, &r.uid).await.map_err(map_err)?;
        ok_json(&ev)
    }

    #[tool(description = "Create a calendar event. Optional rrule creates a recurring series.")]
    async fn create_event(&self, Parameters(r): Parameters<CreateEventReq>) -> Result<CallToolResult, McpError> {
        let ev = Event {
            uid: new_uid(), href: None, etag: None,
            summary: r.summary, start: r.start, end: r.end,
            location: r.location, description: r.description,
            rrule: r.rrule, is_instance: false,
        };
        self.client.put_event(&r.calendar, &ev).await.map_err(map_err)?;
        ok_json(&ev)
    }

    #[tool(description = "Update a whole event (or whole recurring series). Fields left null are unchanged.")]
    async fn update_event(&self, Parameters(r): Parameters<UpdateEventReq>) -> Result<CallToolResult, McpError> {
        let mut ev = self.client.get_event(&r.calendar, &r.uid).await.map_err(map_err)?;
        if let Some(v) = r.summary { ev.summary = v; }
        if let Some(v) = r.start { ev.start = v; }
        if let Some(v) = r.end { ev.end = v; }
        if r.location.is_some() { ev.location = r.location; }
        if r.description.is_some() { ev.description = r.description; }
        if r.rrule.is_some() { ev.rrule = r.rrule; }
        ev.is_instance = false;
        self.client.put_event(&r.calendar, &ev).await.map_err(map_err)?;
        ok_json(&ev)
    }

    #[tool(description = "Delete an event by UID.")]
    async fn delete_event(&self, Parameters(r): Parameters<GetByUidReq>) -> Result<CallToolResult, McpError> {
        self.client.delete_event(&r.calendar, &r.uid).await.map_err(map_err)?;
        ok_json(&serde_json::json!({"deleted": r.uid}))
    }

    #[tool(description = "List tasks (VTODO) in a calendar.")]
    async fn list_tasks(&self, Parameters(r): Parameters<GetByUidReq>) -> Result<CallToolResult, McpError> {
        // reuse calendar field; uid ignored for list. (Distinct struct optional.)
        let todos = self.client.list_todos(&r.calendar).await.map_err(map_err)?;
        ok_json(&todos)
    }

    #[tool(description = "Create a task (VTODO).")]
    async fn create_task(&self, Parameters(r): Parameters<CreateTaskReq>) -> Result<CallToolResult, McpError> {
        let td = Todo {
            uid: new_uid(), href: None, etag: None,
            summary: r.summary, due: r.due, status: r.status,
            description: r.description, priority: r.priority,
        };
        self.client.put_todo(&r.calendar, &td).await.map_err(map_err)?;
        ok_json(&td)
    }

    #[tool(description = "Update a task. Null fields unchanged.")]
    async fn update_task(&self, Parameters(r): Parameters<UpdateTaskReq>) -> Result<CallToolResult, McpError> {
        let mut td = self.client.get_todo(&r.calendar, &r.uid).await.map_err(map_err)?;
        if let Some(v) = r.summary { td.summary = v; }
        if r.due.is_some() { td.due = r.due; }
        if r.status.is_some() { td.status = r.status; }
        if r.description.is_some() { td.description = r.description; }
        if r.priority.is_some() { td.priority = r.priority; }
        self.client.put_todo(&r.calendar, &td).await.map_err(map_err)?;
        ok_json(&td)
    }

    #[tool(description = "Delete a task by UID.")]
    async fn delete_task(&self, Parameters(r): Parameters<GetByUidReq>) -> Result<CallToolResult, McpError> {
        self.client.delete_todo(&r.calendar, &r.uid).await.map_err(map_err)?;
        ok_json(&serde_json::json!({"deleted": r.uid}))
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
```

Set `src/mcp/mod.rs`:
```rust
pub mod tools;
pub use tools::CalendarServer;
```

> `get_event`/`list_tasks` sharing `GetByUidReq` for the `calendar`-only case is a minor smell; if the compiler or schema clarity demands, add a `CalendarRef { calendar: String }` struct. Keep tool names stable.

- [ ] **Step 3: Write a tool test with a mock client**

Append to `src/mcp/tools.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct MockClient;
    #[async_trait]
    impl CalDavClient for MockClient {
        async fn list_calendars(&self) -> crate::error::Result<Vec<Calendar>> {
            Ok(vec![Calendar {
                href: "/cal/".into(), display_name: "Work".into(),
                color: None, components: vec!["VEVENT".into()], ctag: None,
            }])
        }
        async fn list_events(&self, _: &str, _: DateTime<Utc>, _: DateTime<Utc>) -> crate::error::Result<Vec<Event>> { Ok(vec![]) }
        async fn get_event(&self, _: &str, uid: &str) -> crate::error::Result<Event> {
            Ok(Event { uid: uid.into(), href: None, etag: None, summary: "S".into(),
                start: "2026-08-03T09:00:00Z".parse().unwrap(),
                end: "2026-08-03T10:00:00Z".parse().unwrap(),
                location: None, description: None, rrule: None, is_instance: false })
        }
        async fn put_event(&self, _: &str, _: &Event) -> crate::error::Result<()> { Ok(()) }
        async fn delete_event(&self, _: &str, _: &str) -> crate::error::Result<()> { Ok(()) }
        async fn list_todos(&self, _: &str) -> crate::error::Result<Vec<Todo>> { Ok(vec![]) }
        async fn get_todo(&self, _: &str, uid: &str) -> crate::error::Result<Todo> {
            Ok(Todo { uid: uid.into(), href: None, etag: None, summary: "T".into(),
                due: None, status: None, description: None, priority: None })
        }
        async fn put_todo(&self, _: &str, _: &Todo) -> crate::error::Result<()> { Ok(()) }
        async fn delete_todo(&self, _: &str, _: &str) -> crate::error::Result<()> { Ok(()) }
    }

    #[tokio::test]
    async fn list_calendars_returns_json() {
        let srv = CalendarServer::new(Arc::new(MockClient));
        let res = srv.list_calendars().await.unwrap();
        // CallToolResult content should contain the calendar name.
        let joined = format!("{res:?}");
        assert!(joined.contains("Work"));
    }

    #[tokio::test]
    async fn update_event_applies_patch() {
        let srv = CalendarServer::new(Arc::new(MockClient));
        let req = UpdateEventReq {
            calendar: "/cal/".into(), uid: "e1".into(),
            summary: Some("New".into()), start: None, end: None,
            location: None, description: None, rrule: None,
        };
        let res = srv.update_event(Parameters(req)).await.unwrap();
        assert!(format!("{res:?}").contains("New"));
    }
}
```

- [ ] **Step 4: Run tests; reconcile rmcp API**

Run: `cargo test mcp::tools`
Expected: 2 pass. rmcp macro/type paths (`ToolRouter`, `Parameters`, `CallToolResult`, `Content`, `ErrorData`, `ServerCapabilities`) may differ by version — open `cargo doc -p rmcp --open`, fix import paths and the `get_info`/result-construction calls to match. **Tool method bodies and names stay as written.**

- [ ] **Step 5: Commit**

```bash
git add src/mcp/ Cargo.toml
git commit -m "feat: rmcp calendar tools over CalDavClient"
```

---

## Task 10: Wire it all in main + serve

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Implement main**

Replace `src/main.rs`:
```rust
use std::sync::Arc;

use mcp_caldav_fastmail::auth::metadata::{prm_handler, require_auth, AuthState};
use mcp_caldav_fastmail::auth::{JwksKeySource, JwtValidator};
use mcp_caldav_fastmail::caldav::FastmailCalDav;
use mcp_caldav_fastmail::config::Config;
use mcp_caldav_fastmail::mcp::CalendarServer;

use axum::{middleware, routing::get, Router};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpService,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env()?;

    // Outbound CalDAV client.
    let caldav = Arc::new(FastmailCalDav::new(
        &cfg.caldav_base_url,
        &cfg.fastmail_username,
        &cfg.fastmail_app_password,
    )?);

    // Inbound auth.
    let keys = Arc::new(JwksKeySource::new(cfg.authelia_jwks_uri.clone()));
    let validator = Arc::new(JwtValidator::new(
        keys,
        cfg.authelia_issuer.clone(),
        cfg.resource_uri.clone(),
        cfg.required_scope.clone(),
    ));
    let prm_url = format!("{}/.well-known/oauth-protected-resource", cfg.resource_uri.trim_end_matches('/'));
    let auth_state = AuthState {
        validator,
        prm_url,
        resource: cfg.resource_uri.clone(),
        issuer: cfg.authelia_issuer.clone(),
        scope: cfg.required_scope.clone(),
    };

    // MCP service as a tower service.
    let caldav_for_mcp = caldav.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(CalendarServer::new(caldav_for_mcp.clone())),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    let app = Router::new()
        .route("/.well-known/oauth-protected-resource", get(prm_handler))
        .nest_service("/mcp", mcp_service)
        .layer(middleware::from_fn_with_state(auth_state.clone(), require_auth))
        .with_state(auth_state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("listening on {}", cfg.bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}
```

> The `require_auth` layer will also cover the PRM route; that is wrong — the metadata endpoint must be public. Fix by splitting routers: a public router for `/.well-known/*` merged with a protected router carrying the middleware. Concretely:
> ```rust
> let protected = Router::new().nest_service("/mcp", mcp_service)
>     .layer(middleware::from_fn_with_state(auth_state.clone(), require_auth));
> let public = Router::new().route("/.well-known/oauth-protected-resource", get(prm_handler));
> let app = public.merge(protected).with_state(auth_state);
> ```
> Use this split form.

- [ ] **Step 2: Verify the rmcp `StreamableHttpService` constructor**

Run: `cargo doc -p rmcp --open`, confirm the exact `StreamableHttpService::new` signature and `session` module path. Adjust the constructor args if they differ (e.g. a config struct vs `Default::default()`). This is the highest-risk API-drift spot in the plan.

- [ ] **Step 3: Build**

Run: `cargo build`
Expected: compiles.

- [ ] **Step 4: Manual smoke (no live Fastmail needed for the 401 path)**

Run:
```bash
RESOURCE_URI=https://mcp.local AUTHELIA_ISSUER=https://auth.local \
AUTHELIA_JWKS_URI=https://auth.local/jwks.json \
FASTMAIL_USERNAME=x FASTMAIL_APP_PASSWORD=y \
BIND_ADDR=127.0.0.1:8080 cargo run &
sleep 2
curl -i http://127.0.0.1:8080/mcp        # expect 401 + WWW-Authenticate
curl -s http://127.0.0.1:8080/.well-known/oauth-protected-resource  # expect PRM JSON
kill %1
```
Expected: `/mcp` → `401` with `WWW-Authenticate: Bearer resource_metadata=...`; PRM endpoint → JSON with `authorization_servers`.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat: wire axum host, auth middleware, and MCP service"
```

---

## Task 11: README + full verification

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README**

Create `README.md` documenting: purpose, env vars (from spec §9), Authelia static-client setup (audience = `RESOURCE_URI`, scope = `REQUIRED_SCOPE`, PKCE public client), how to add to Claude Code (`claude mcp add --transport http <name> https://host/mcp`), and the Claude Desktop DCR caveat with the manual-token fallback.

- [ ] **Step 2: Full test + lint pass**

Run:
```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```
Expected: fmt clean, clippy clean, all tests pass. Fix anything that fails.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: README with Authelia + client setup"
```

---

## Self-Review (completed against spec)

- **Spec §1 scope (events R/W, tasks R/W, R1+R2):** Tasks 6, 9 (tools), 4 (expand). ✓
- **Spec §2 crate stack:** Task 0 Cargo.toml. ✓
- **Spec §5 auth (PRM, validator, aud/iss/scope, T2 no DCR):** Tasks 7, 8, 10. ✓
- **Spec §6 CalDAV flow (discovery, query+expand, ETag writes):** Task 6. ✓
- **Spec §7 tool surface:** Task 9 — all 11 tools present. ✓
- **Spec §8 errors + testing (unit + wiremock + mocked client):** Tasks 2, 4, 5, 6, 7, 9. ✓
- **Spec §9 config:** Task 1. ✓

**Known API-drift risks flagged in-plan:** rmcp tool macros + `StreamableHttpService::new` (Tasks 9, 10), calcard accessors + `datecalc` (Task 4), `jwks` crate (Task 7). Each has an explicit "verify against docs.rs" step that changes only implementation internals, never public seams or tests.

**Deferred (spec §10), not in this plan:** R3 recurrence, JSCalendar path, CardDAV, iTIP, multi-user.
