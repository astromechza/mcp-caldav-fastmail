//! Isolates the iCalendar (RFC5545) format concern behind a small, stable API.
//!
//! This is the ONLY module allowed to touch `calcard` types. Everything else in the
//! codebase works with the domain types in `crate::caldav::model`.
//!
//! calcard 0.1.3 models a parsed document as an `ICalendar` with a flat `Vec` of
//! `ICalendarComponent`s (linked via `component_ids` for nesting, e.g. VCALENDAR ->
//! VEVENT). Each component has a `Vec<ICalendarEntry>` keyed by the `ICalendarProperty`
//! enum, not string property names. There is no simple `.property("UID").as_text()`
//! shortcut for arbitrary strings - properties are matched against `ICalendarProperty`
//! variants and values are extracted via `ICalendarValue` pattern matching (or the
//! `as_text()` / `as_integer()` helpers calcard provides on `ICalendarValue`).
//!
//! Recurrence expansion is provided natively by calcard: `ICalendar::expand_dates`
//! (in `calcard::icalendar::dates`) walks all time-range components, expands RRULE
//! (via calcard's own `datecalc` module - a full RFC5545 recurrence engine), and
//! returns concrete occurrences. We use that directly rather than pulling in the
//! external `rrule` crate.

use calcard::{
    common::{timezone::Tz, DateTimeResult},
    icalendar::{ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarProperty, ICalendarValue},
    Entry, Parser,
};
use chrono::{DateTime, TimeZone, Utc};
use std::str::FromStr;

use crate::caldav::model::{Event, Todo};
use crate::error::{Error, Result};

/// Parse an .ics document and return the first VEVENT it contains as an [`Event`].
///
/// The returned `Event` has `href`/`etag` unset and `is_instance = false` - those are
/// filled in by the caller (the CalDAV layer knows about resource hrefs/etags, this
/// module does not).
pub fn parse_event(ics: &str) -> Result<Event> {
    let ical = parse_top_level(ics)?;
    let (_, comp) = find_component(&ical, ICalendarComponentType::VEvent)
        .ok_or_else(|| Error::ICal("no VEVENT component found".into()))?;
    event_from_component(comp)
}

/// Parse an .ics document and return the first VTODO it contains as a [`Todo`].
pub fn parse_todo(ics: &str) -> Result<Todo> {
    let ical = parse_top_level(ics)?;
    let (_, comp) = find_component(&ical, ICalendarComponentType::VTodo)
        .ok_or_else(|| Error::ICal("no VTODO component found".into()))?;
    todo_from_component(comp)
}

/// Serialize an [`Event`] as a complete VCALENDAR document wrapping a single VEVENT.
///
/// Hand-built rather than routed through calcard's builder: the builder's
/// component-id linking is designed for round-tripping/mutating an already-parsed
/// `ICalendar`, and adds no value for emitting a single fresh VEVENT. Hand-building
/// keeps this side of the seam simple and decoupled from calcard's internal
/// representation.
///
/// Note: output is intentionally not RFC5545 line-folded (no 75-octet continuation
/// wrapping) - see module-level tests for the accepted round-trip guarantee.
pub fn build_event(ev: &Event) -> String {
    let mut out = String::new();
    out.push_str("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//mcp-caldav-fastmail//EN\r\nBEGIN:VEVENT\r\n");
    write_text_line(&mut out, "UID", &ev.uid);
    write_text_line(&mut out, "SUMMARY", &ev.summary);
    write_datetime_line(&mut out, "DTSTART", ev.start);
    write_datetime_line(&mut out, "DTEND", ev.end);
    if let Some(location) = &ev.location {
        write_text_line(&mut out, "LOCATION", location);
    }
    if let Some(description) = &ev.description {
        write_text_line(&mut out, "DESCRIPTION", description);
    }
    if let Some(rrule) = &ev.rrule {
        // RRULE's value is itself a structured list of NAME=VALUE parts separated by
        // ';' - those separators are syntax, not TEXT content, so they must not be
        // escaped here.
        out.push_str("RRULE:");
        out.push_str(rrule);
        out.push_str("\r\n");
    }
    out.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    out
}

/// Serialize a [`Todo`] as a complete VCALENDAR document wrapping a single VTODO.
///
/// Note: output is intentionally not RFC5545 line-folded (no 75-octet continuation
/// wrapping) - see module-level tests for the accepted round-trip guarantee.
pub fn build_todo(td: &Todo) -> String {
    let mut out = String::new();
    out.push_str("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//mcp-caldav-fastmail//EN\r\nBEGIN:VTODO\r\n");
    write_text_line(&mut out, "UID", &td.uid);
    write_text_line(&mut out, "SUMMARY", &td.summary);
    if let Some(due) = td.due {
        write_datetime_line(&mut out, "DUE", due);
    }
    if let Some(status) = &td.status {
        // STATUS is an enumerated token, not TEXT - no escaping.
        out.push_str("STATUS:");
        out.push_str(status);
        out.push_str("\r\n");
    }
    if let Some(description) = &td.description {
        write_text_line(&mut out, "DESCRIPTION", description);
    }
    if let Some(priority) = td.priority {
        out.push_str(&format!("PRIORITY:{priority}\r\n"));
    }
    out.push_str("END:VTODO\r\nEND:VCALENDAR\r\n");
    out
}

/// Expand a VEVENT (given as raw .ics text) into concrete instances overlapping
/// `[start, end)`.
///
/// - No RRULE: yields the single base instance if it overlaps the window, else empty.
/// - RRULE present: uses calcard's `ICalendar::expand_dates` (calcard's own RFC5545
///   recurrence engine, under `calcard::datecalc`) to compute concrete occurrences,
///   keeping only those whose DTSTART falls within `[start, end)`. Each returned
///   instance has `is_instance = true`, inherits SUMMARY/LOCATION/DESCRIPTION/RRULE
///   from the base event, and has `end = occurrence_start + (base.end - base.start)`.
pub fn expand_event(ics: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Event>> {
    let base = parse_event(ics)?;

    if base.rrule.is_none() {
        return if base.start < end && base.end > start {
            Ok(vec![base])
        } else {
            Ok(vec![])
        };
    }

    let ical = parse_top_level(ics)?;
    let (comp_id, _) = find_component(&ical, ICalendarComponentType::VEvent)
        .ok_or_else(|| Error::ICal("no VEVENT component found".into()))?;

    // Limit bounds the number of occurrences calcard will generate; expand_dates has
    // no notion of an end date itself. 10_000 comfortably covers any realistic
    // bounded (COUNT/UNTIL) series and gives a generous window for unbounded ones.
    let expanded = ical.expand_dates(Utc, 10_000);
    if !expanded.errors.is_empty() {
        tracing::warn!(
            errors = ?expanded.errors,
            "iCalendar recurrence expansion reported errors for one or more components"
        );
    }

    let duration = base.end - base.start;
    let mut out = Vec::new();
    for occurrence in expanded.events {
        if occurrence.comp_id as usize != comp_id {
            continue;
        }
        let (start_ts, _) = occurrence.timestamps();
        let occ_start = DateTime::<Utc>::from_timestamp(start_ts, 0)
            .ok_or_else(|| Error::ICal("expanded occurrence had an invalid timestamp".into()))?;
        // Overlap check (not just "starts in window"): an instance that starts just
        // before `start` but whose duration carries it into the window still counts.
        if occ_start < end && occ_start + duration > start {
            out.push(Event {
                uid: base.uid.clone(),
                href: None,
                etag: None,
                summary: base.summary.clone(),
                start: occ_start,
                end: occ_start + duration,
                location: base.location.clone(),
                description: base.description.clone(),
                rrule: base.rrule.clone(),
                is_instance: true,
            });
        }
    }
    out.sort_by(|a, b| a.start.cmp(&b.start));
    Ok(out)
}

// --- internal helpers -------------------------------------------------------------

fn parse_top_level(ics: &str) -> Result<ICalendar> {
    let mut parser = Parser::new(ics);
    match parser.entry() {
        Entry::ICalendar(ical) => Ok(ical),
        other => Err(Error::ICal(format!("expected a VCALENDAR document, got {other:?}"))),
    }
}

fn find_component(
    ical: &ICalendar,
    component_type: ICalendarComponentType,
) -> Option<(usize, &ICalendarComponent)> {
    ical.components
        .iter()
        .enumerate()
        .find(|(_, c)| c.component_type == component_type)
}

fn text_prop(comp: &ICalendarComponent, prop: ICalendarProperty) -> Option<String> {
    comp.property(&prop)
        .and_then(|entry| entry.values.first())
        .and_then(|value| value.as_text())
        .map(|s| s.to_string())
}

fn datetime_prop(comp: &ICalendarComponent, prop: ICalendarProperty) -> Option<DateTime<Utc>> {
    let entry = comp.property(&prop)?;
    let ICalendarValue::PartialDateTime(pdt) = entry.values.first()? else {
        return None;
    };
    let result = pdt.to_date_time()?;
    // entry.tz_id() reads the TZID= parameter off this specific property (e.g.
    // "DTSTART;TZID=Europe/London:..."), which to_date_time()/DateTimeResult alone
    // knows nothing about - PartialDateTime only carries an explicit numeric
    // UTC offset (from a "Z" or "+HHMM" suffix) in `result.offset`, never a TZID.
    date_time_result_to_utc(&result, entry.tz_id())
}

fn rrule_prop(comp: &ICalendarComponent) -> Option<String> {
    comp.property(&ICalendarProperty::Rrule)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            // ICalendarRecurrenceRule implements Display, reconstructing a canonical
            // "FREQ=...;..." string from the parsed/structured representation. The
            // field order calcard emits may differ from whatever order the source
            // document used (calcard always writes FREQ, UNTIL, COUNT, INTERVAL,
            // then the BYxxx parts, then WKST) since it doesn't retain the original
            // token order - only the semantics.
            ICalendarValue::RecurrenceRule(rule) => Some(rule.to_string()),
            _ => None,
        })
}

fn priority_prop(comp: &ICalendarComponent) -> Option<u8> {
    comp.property(&ICalendarProperty::Priority)
        .and_then(|entry| entry.values.first())
        .and_then(|value| value.as_integer())
        .and_then(|i| u8::try_from(i).ok())
}

/// Resolve a parsed date/time to a concrete UTC instant, honoring an explicit TZID
/// parameter (e.g. `DTSTART;TZID=Europe/London:20260803T090000`) when present.
///
/// calcard parses the numeric fields (and any literal "Z"/"+HHMM" suffix) into
/// `PartialDateTime`/`DateTimeResult`, but does not resolve `TZID=` itself - callers
/// are expected to combine it with the entry's own `tz_id()`. This mirrors what
/// calcard's own `ICalendarComponent::build_calendar_date` + `TzResolver` do
/// internally for `expand_dates`, using calcard's `Tz` type (which already knows how
/// to parse IANA zone names, Microsoft zone names, etc. via its `FromStr` impl).
fn date_time_result_to_utc(result: &DateTimeResult, tz_id: Option<&str>) -> Option<DateTime<Utc>> {
    if let Some(offset) = result.offset {
        // An explicit numeric UTC offset (from "Z" or "+HHMM") always wins.
        return offset
            .from_local_datetime(&result.date_time)
            .single()
            .map(|dt| dt.with_timezone(&Utc));
    }

    let tz = tz_id
        .and_then(|name| Tz::from_str(name).ok())
        .unwrap_or(Tz::Floating);
    if matches!(tz, Tz::Floating) {
        // Floating (no offset, no resolvable TZID): accepted deviation, best-effort
        // treat the naive local time as if it were already UTC.
        return Some(Utc.from_utc_datetime(&result.date_time));
    }
    tz.from_local_datetime(&result.date_time)
        .single()
        .map(|dt| dt.with_timezone(&Utc))
}

fn event_from_component(comp: &ICalendarComponent) -> Result<Event> {
    let uid = text_prop(comp, ICalendarProperty::Uid)
        .ok_or_else(|| Error::ICal("VEVENT missing UID".into()))?;
    let start = datetime_prop(comp, ICalendarProperty::Dtstart)
        .ok_or_else(|| Error::ICal("VEVENT missing DTSTART".into()))?;
    let end = datetime_prop(comp, ICalendarProperty::Dtend)
        .ok_or_else(|| Error::ICal("VEVENT missing DTEND".into()))?;
    let summary = text_prop(comp, ICalendarProperty::Summary).unwrap_or_default();
    let location = text_prop(comp, ICalendarProperty::Location);
    let description = text_prop(comp, ICalendarProperty::Description);
    let rrule = rrule_prop(comp);

    Ok(Event {
        uid,
        href: None,
        etag: None,
        summary,
        start,
        end,
        location,
        description,
        rrule,
        is_instance: false,
    })
}

fn todo_from_component(comp: &ICalendarComponent) -> Result<Todo> {
    let uid = text_prop(comp, ICalendarProperty::Uid)
        .ok_or_else(|| Error::ICal("VTODO missing UID".into()))?;
    let summary = text_prop(comp, ICalendarProperty::Summary).unwrap_or_default();
    let due = datetime_prop(comp, ICalendarProperty::Due);
    let status = comp.status().map(|s| s.as_str().to_string());
    let description = text_prop(comp, ICalendarProperty::Description);
    let priority = priority_prop(comp);

    Ok(Todo {
        uid,
        href: None,
        etag: None,
        summary,
        due,
        status,
        description,
        priority,
    })
}

/// Escape a TEXT value per RFC5545 3.3.11: backslash, semicolon, comma and newline
/// are backslash-escaped.
fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            other => out.push(other),
        }
    }
    out
}

fn write_text_line(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push(':');
    out.push_str(&escape_text(value));
    out.push_str("\r\n");
}

fn write_datetime_line(out: &mut String, name: &str, value: DateTime<Utc>) {
    out.push_str(name);
    out.push(':');
    out.push_str(&value.format("%Y%m%dT%H%M%SZ").to_string());
    out.push_str("\r\n");
}

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
        // calcard parses RRULE into a structured ICalendarRecurrenceRule and we
        // reconstruct the string via its Display impl, which emits parts in a fixed
        // canonical order (FREQ, UNTIL, COUNT, INTERVAL, BY*, WKST) rather than
        // preserving the original token order. For "FREQ=WEEKLY;BYDAY=MO;COUNT=3"
        // that comes back as "FREQ=WEEKLY;COUNT=3;BYDAY=MO", so we assert on
        // containment of the semantically-important part rather than exact equality.
        let rrule = ev.rrule.as_deref().expect("rrule");
        assert!(rrule.contains("FREQ=WEEKLY"), "rrule was: {rrule}");
        assert!(rrule.contains("COUNT=3"), "rrule was: {rrule}");
        assert!(rrule.contains("BYDAY=MO"), "rrule was: {rrule}");
    }

    #[test]
    fn parse_event_resolves_tzid() {
        // 2026-08-03 is in BST (UTC+1) - London is not in an ambiguous DST
        // transition window on this date, so the offset is unambiguous.
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
BEGIN:VEVENT\r\nUID:evt-tz\r\nSUMMARY:London Meeting\r\n\
DTSTART;TZID=Europe/London:20260803T090000\r\n\
DTEND;TZID=Europe/London:20260803T100000\r\nEND:VEVENT\r\n\
END:VCALENDAR\r\n";
        let ev = parse_event(ics).expect("parse");
        assert_eq!(
            ev.start,
            "2026-08-03T08:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            ev.end,
            "2026-08-03T09:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn build_then_parse_roundtrips_summary() {
        let ev = Event {
            uid: "evt-2".into(),
            href: None,
            etag: None,
            summary: "Lunch".into(),
            start: "2026-08-03T12:00:00Z".parse().unwrap(),
            end: "2026-08-03T13:00:00Z".parse().unwrap(),
            location: Some("Cafe".into()),
            description: None,
            rrule: None,
            is_instance: false,
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
