//! CalDAV client trait and a Fastmail-flavored `reqwest` implementation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use url::Url;

use crate::caldav::model::{Calendar, Event, Todo};
use crate::caldav::xml;
use crate::error::{Error, Result};
use crate::ical;

/// Behavior needed from a CalDAV server, kept independent of the HTTP client so it can
/// be mocked in tests of higher layers.
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

/// A [`CalDavClient`] backed by Fastmail's CalDAV service (HTTP Basic auth with an
/// app password), talking to it over `reqwest`.
pub struct FastmailCalDav {
    client: reqwest::Client,
    base: Url,
    username: String,
    app_password: String,
}

const XML_CONTENT_TYPE: &str = "application/xml; charset=utf-8";
const ICAL_CONTENT_TYPE: &str = "text/calendar; charset=utf-8";

impl FastmailCalDav {
    pub fn new(base_url: &str, username: &str, app_password: &str) -> Result<Self> {
        let base = Url::parse(base_url)
            .map_err(|e| Error::Config(format!("invalid CalDAV base URL {base_url:?}: {e}")))?;
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| Error::Config(format!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            client,
            base,
            username: username.to_string(),
            app_password: app_password.to_string(),
        })
    }

    fn resolve(&self, href: &str) -> Result<Url> {
        self.base
            .join(href)
            .map_err(|e| Error::Config(format!("invalid href {href:?}: {e}")))
    }

    /// Send a CalDAV/WebDAV request and return `(status, headers, body)`. Maps 4xx/5xx
    /// responses to `Error::CalDav`. `method` supports arbitrary tokens (PROPFIND,
    /// REPORT, ...), not just the methods `reqwest::Method`'s constants cover.
    #[allow(clippy::too_many_arguments)]
    async fn dav(
        &self,
        method: &str,
        href: &str,
        depth: Option<&str>,
        body: Option<String>,
        if_match: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<(StatusCode, HeaderMap, String)> {
        let url = self.resolve(href)?;
        // Keep the original method token around (for Error::CalDav context below) -
        // `reqwest::Method::from_bytes` below shadows `method` with a parsed value.
        let method_name = method.to_string();
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::Config(format!("invalid HTTP method {method:?}: {e}")))?;

        let mut req = self
            .client
            .request(method, url)
            .basic_auth(&self.username, Some(&self.app_password));
        if let Some(d) = depth {
            req = req.header("Depth", d);
        }
        if let Some(im) = if_match {
            req = req.header("If-Match", im);
        }
        if let Some(ct) = content_type {
            req = req.header("Content-Type", ct);
        }
        if let Some(b) = body {
            req = req.body(b);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let text = resp.text().await?;

        if status.is_client_error() || status.is_server_error() {
            return Err(Error::CalDav {
                status: status.as_u16(),
                method: method_name,
                href: href.to_string(),
                body: text,
            });
        }
        Ok((status, headers, text))
    }

    /// Resolve the calendar-home-set href via the discovery chain:
    /// "/" -> current-user-principal -> calendar-home-set.
    async fn calendar_home(&self) -> Result<String> {
        let (_, _, principal_body) = self
            .dav(
                "PROPFIND",
                "/",
                Some("0"),
                Some(xml::propfind_principal_body().to_string()),
                None,
                Some(XML_CONTENT_TYPE),
            )
            .await?;
        let principal = xml::nested_href(&principal_body, "current-user-principal")?
            .ok_or_else(|| Error::NotFound("current-user-principal not found in discovery response".into()))?;

        let (_, _, home_body) = self
            .dav(
                "PROPFIND",
                &principal,
                Some("0"),
                Some(xml::propfind_home_body().to_string()),
                None,
                Some(XML_CONTENT_TYPE),
            )
            .await?;
        let home = xml::nested_href(&home_body, "calendar-home-set")?
            .ok_or_else(|| Error::NotFound("calendar-home-set not found in discovery response".into()))?;

        Ok(home)
    }

    /// The resource href for a single calendar object, e.g. cal_href "/cal/" + uid
    /// "evt-1" -> "/cal/evt-1.ics".
    fn object_href(cal_href: &str, uid: &str) -> String {
        format!("{}/{}.ics", cal_href.trim_end_matches('/'), uid)
    }
}

#[async_trait]
impl CalDavClient for FastmailCalDav {
    async fn list_calendars(&self) -> Result<Vec<Calendar>> {
        let home = self.calendar_home().await?;
        let (_, _, body) = self
            .dav(
                "PROPFIND",
                &home,
                Some("1"),
                Some(xml::propfind_calendars_body().to_string()),
                None,
                Some(XML_CONTENT_TYPE),
            )
            .await?;

        // Compare with a trailing slash trimmed on both sides rather than raw string
        // equality: `home` came from the discovery PROPFIND response while `r.href`
        // comes from this (separate) PROPFIND Depth:1 response, and servers aren't
        // guaranteed to echo the exact same absolute-vs-relative/trailing-slash
        // formatting for what is logically the same collection.
        let home_trimmed = home.trim_end_matches('/');
        let responses = xml::parse_multistatus(&body)?;
        let mut calendars = Vec::new();
        for r in responses {
            if r.href.trim_end_matches('/') == home_trimmed {
                // The home collection itself, not a calendar within it.
                continue;
            }
            let Some(display_name) = r.prop("displayname") else {
                // No displayname means this isn't a calendar collection we recognize
                // (e.g. the flat parser tripped over something else in the listing).
                continue;
            };
            let color = r.prop("calendar-color");
            let ctag = r.prop("getctag");
            calendars.push(Calendar {
                href: r.href,
                display_name,
                color,
                // The flat multistatus parser can't read the child <comp name="VEVENT"/>
                // elements of <supported-calendar-component-set> (the component name is
                // an attribute, not text) - default to VEVENT-only support rather than
                // guessing. See caldav::xml module docs for the parser's limitations.
                components: vec!["VEVENT".to_string()],
                ctag,
            });
        }
        Ok(calendars)
    }

    async fn list_events(&self, cal_href: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Event>> {
        let start_fmt = start.format("%Y%m%dT%H%M%SZ").to_string();
        let end_fmt = end.format("%Y%m%dT%H%M%SZ").to_string();
        let body = xml::calendar_query_body("VEVENT", Some((&start_fmt, &end_fmt)));
        let (_, _, resp_body) = self
            .dav("REPORT", cal_href, Some("1"), Some(body), None, Some(XML_CONTENT_TYPE))
            .await?;

        let responses = xml::parse_multistatus(&resp_body)?;
        let mut events = Vec::new();
        for r in responses {
            let Some(data) = r.prop("calendar-data") else {
                continue;
            };
            let etag = r.prop("getetag");
            let mut instances = ical::expand_event(&data, start, end)?;
            for ev in &mut instances {
                ev.href = Some(r.href.clone());
                ev.etag = etag.clone();
            }
            events.extend(instances);
        }
        Ok(events)
    }

    async fn get_event(&self, cal_href: &str, uid: &str) -> Result<Event> {
        let href = Self::object_href(cal_href, uid);
        let (_, headers, body) = self.dav("GET", &href, None, None, None, None).await?;
        let mut ev = ical::parse_event(&body)?;
        ev.href = Some(href);
        ev.etag = headers.get("ETag").and_then(|v| v.to_str().ok()).map(str::to_string);
        Ok(ev)
    }

    async fn put_event(&self, cal_href: &str, ev: &Event) -> Result<()> {
        let href = ev.href.clone().unwrap_or_else(|| Self::object_href(cal_href, &ev.uid));
        let body = ical::build_event(ev);
        self.dav(
            "PUT",
            &href,
            None,
            Some(body),
            ev.etag.as_deref(),
            Some(ICAL_CONTENT_TYPE),
        )
        .await?;
        Ok(())
    }

    async fn delete_event(&self, cal_href: &str, uid: &str) -> Result<()> {
        let href = Self::object_href(cal_href, uid);
        self.dav("DELETE", &href, None, None, None, None).await?;
        Ok(())
    }

    async fn list_todos(&self, cal_href: &str) -> Result<Vec<Todo>> {
        let body = xml::calendar_query_body("VTODO", None);
        let (_, _, resp_body) = self
            .dav("REPORT", cal_href, Some("1"), Some(body), None, Some(XML_CONTENT_TYPE))
            .await?;

        let responses = xml::parse_multistatus(&resp_body)?;
        let mut todos = Vec::new();
        for r in responses {
            let Some(data) = r.prop("calendar-data") else {
                continue;
            };
            let mut td = ical::parse_todo(&data)?;
            td.href = Some(r.href.clone());
            td.etag = r.prop("getetag");
            todos.push(td);
        }
        Ok(todos)
    }

    async fn get_todo(&self, cal_href: &str, uid: &str) -> Result<Todo> {
        let href = Self::object_href(cal_href, uid);
        let (_, headers, body) = self.dav("GET", &href, None, None, None, None).await?;
        let mut td = ical::parse_todo(&body)?;
        td.href = Some(href);
        td.etag = headers.get("ETag").and_then(|v| v.to_str().ok()).map(str::to_string);
        Ok(td)
    }

    async fn put_todo(&self, cal_href: &str, td: &Todo) -> Result<()> {
        let href = td.href.clone().unwrap_or_else(|| Self::object_href(cal_href, &td.uid));
        let body = ical::build_todo(td);
        self.dav(
            "PUT",
            &href,
            None,
            Some(body),
            td.etag.as_deref(),
            Some(ICAL_CONTENT_TYPE),
        )
        .await?;
        Ok(())
    }

    async fn delete_todo(&self, cal_href: &str, uid: &str) -> Result<()> {
        let href = Self::object_href(cal_href, uid);
        self.dav("DELETE", &href, None, None, None, None).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client_for(server: &MockServer) -> FastmailCalDav {
        FastmailCalDav::new(&server.uri(), "anth@benmeier.fastmail.com", "app-password").expect("client")
    }

    #[tokio::test]
    async fn list_calendars_walks_full_discovery_chain() {
        let server = MockServer::start().await;

        // Step 1: PROPFIND "/" -> current-user-principal (nested href).
        let principal_body = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:">
  <response>
    <href>/</href>
    <propstat><prop>
      <current-user-principal>
        <href>/dav/principals/user/me/</href>
      </current-user-principal>
    </prop></propstat>
  </response>
</multistatus>"#;
        Mock::given(method("PROPFIND"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(207).set_body_string(principal_body))
            .mount(&server)
            .await;

        // Step 2: PROPFIND on the principal -> calendar-home-set (nested href).
        let home_body = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <response>
    <href>/dav/principals/user/me/</href>
    <propstat><prop>
      <C:calendar-home-set>
        <href>/dav/calendars/user/me/</href>
      </C:calendar-home-set>
    </prop></propstat>
  </response>
</multistatus>"#;
        Mock::given(method("PROPFIND"))
            .and(path("/dav/principals/user/me/"))
            .respond_with(ResponseTemplate::new(207).set_body_string(home_body))
            .mount(&server)
            .await;

        // Step 3: PROPFIND on the calendar-home -> the list of calendars.
        let calendars_body = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:CS="http://calendarserver.org/ns/">
  <response>
    <href>/dav/calendars/user/me/</href>
    <propstat><prop>
      <displayname>me</displayname>
    </prop></propstat>
  </response>
  <response>
    <href>/dav/calendars/user/me/work/</href>
    <propstat><prop>
      <displayname>Work</displayname>
      <CS:getctag>ctag-1</CS:getctag>
    </prop></propstat>
  </response>
  <response>
    <href>/dav/calendars/user/me/home/</href>
    <propstat><prop>
      <displayname>Home</displayname>
      <CS:getctag>ctag-2</CS:getctag>
    </prop></propstat>
  </response>
</multistatus>"#;
        Mock::given(method("PROPFIND"))
            .and(path("/dav/calendars/user/me/"))
            .respond_with(ResponseTemplate::new(207).set_body_string(calendars_body))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let calendars = client.list_calendars().await.expect("list_calendars");

        assert_eq!(calendars.len(), 2, "home collection itself must be skipped: {calendars:?}");
        assert_eq!(calendars[0].display_name, "Work");
        assert_eq!(calendars[0].href, "/dav/calendars/user/me/work/");
        assert_eq!(calendars[0].ctag.as_deref(), Some("ctag-1"));
        assert_eq!(calendars[1].display_name, "Home");
        assert_eq!(calendars[1].href, "/dav/calendars/user/me/home/");
    }

    #[tokio::test]
    async fn list_events_parses_report_body() {
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

        let client = client_for(&server);
        let start = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap();
        let events = client.list_events("/cal/", start, end).await.expect("list_events");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].summary, "Standup");
        assert_eq!(events[0].uid, "evt-1");
        assert_eq!(events[0].etag.as_deref(), Some("\"e1\""));
        assert_eq!(events[0].href.as_deref(), Some("/cal/evt-1.ics"));
    }

    #[tokio::test]
    async fn put_event_sends_if_match_etag() {
        let server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/cal/evt-1.ics"))
            .and(header("If-Match", "\"e1\""))
            .and(body_string_contains("SUMMARY:Standup"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let ev = Event {
            uid: "evt-1".into(),
            href: None,
            etag: Some("\"e1\"".into()),
            summary: "Standup".into(),
            start: Utc.with_ymd_and_hms(2026, 8, 3, 9, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 8, 3, 9, 15, 0).unwrap(),
            location: None,
            description: None,
            rrule: None,
            is_instance: false,
        };

        client.put_event("/cal/", &ev).await.expect("put_event");
        // wiremock panics on drop if the mount's expectations aren't met, but we also
        // want an explicit assertion that the request landed as configured, so re-mount
        // isn't needed - the .and(header(...)) above is what proves If-Match was sent.
    }

    #[tokio::test]
    async fn get_event_reads_body_and_etag_header() {
        let server = MockServer::start().await;

        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:evt-9\r\n\
SUMMARY:Lunch\r\nDTSTART:20260803T120000Z\r\nDTEND:20260803T130000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        Mock::given(method("GET"))
            .and(path("/cal/evt-9.ics"))
            .respond_with(ResponseTemplate::new(200).set_body_string(ics).insert_header("ETag", "\"e9\""))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let ev = client.get_event("/cal/", "evt-9").await.expect("get_event");
        assert_eq!(ev.uid, "evt-9");
        assert_eq!(ev.summary, "Lunch");
        assert_eq!(ev.etag.as_deref(), Some("\"e9\""));
        assert_eq!(ev.href.as_deref(), Some("/cal/evt-9.ics"));
    }

    #[tokio::test]
    async fn delete_event_hits_object_href() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/cal/evt-1.ics"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.delete_event("/cal/", "evt-1").await.expect("delete_event");
    }

    #[tokio::test]
    async fn list_todos_parses_report_body() {
        let server = MockServer::start().await;

        let report_body = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <response>
    <href>/cal/todo-1.ics</href>
    <propstat><prop>
      <getetag>"t1"</getetag>
      <C:calendar-data>BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VTODO
UID:todo-1
SUMMARY:Buy milk
END:VTODO
END:VCALENDAR</C:calendar-data>
    </prop></propstat>
  </response>
</multistatus>"#;
        Mock::given(method("REPORT"))
            .and(path("/cal/"))
            .respond_with(ResponseTemplate::new(207).set_body_string(report_body))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let todos = client.list_todos("/cal/").await.expect("list_todos");

        assert_eq!(todos.len(), 1);
        assert_eq!(todos[0].uid, "todo-1");
        assert_eq!(todos[0].summary, "Buy milk");
        assert_eq!(todos[0].etag.as_deref(), Some("\"t1\""));
    }

    #[tokio::test]
    async fn get_todo_reads_body_and_etag_header() {
        let server = MockServer::start().await;

        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:todo-9\r\n\
SUMMARY:Buy milk\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        Mock::given(method("GET"))
            .and(path("/cal/todo-9.ics"))
            .respond_with(ResponseTemplate::new(200).set_body_string(ics).insert_header("ETag", "\"t9\""))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let td = client.get_todo("/cal/", "todo-9").await.expect("get_todo");
        assert_eq!(td.uid, "todo-9");
        assert_eq!(td.summary, "Buy milk");
        assert_eq!(td.etag.as_deref(), Some("\"t9\""));
        assert_eq!(td.href.as_deref(), Some("/cal/todo-9.ics"));
    }

    #[tokio::test]
    async fn put_todo_sends_if_match_and_ical_content_type() {
        let server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/cal/todo-1.ics"))
            .and(header("If-Match", "\"t1\""))
            .and(header("Content-Type", "text/calendar; charset=utf-8"))
            .and(body_string_contains("SUMMARY:Buy milk"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let td = Todo {
            uid: "todo-1".into(),
            href: None,
            etag: Some("\"t1\"".into()),
            summary: "Buy milk".into(),
            due: None,
            status: None,
            description: None,
            priority: None,
        };

        client.put_todo("/cal/", &td).await.expect("put_todo");
        // The .and(header(...)) matchers above are the real assertion: they prove both
        // If-Match and the correct calendar content-type were sent, mirroring the
        // event-side put test so a copy-paste slip between the two paths is caught.
    }

    #[tokio::test]
    async fn delete_todo_hits_object_href() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/cal/todo-1.ics"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.delete_todo("/cal/", "todo-1").await.expect("delete_todo");
    }

    #[tokio::test]
    async fn get_event_error_response_maps_to_caldav_error_with_context() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/cal/missing.ics"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.get_event("/cal/", "missing").await.expect_err("expected error");
        match err {
            Error::CalDav { status, method, href, body } => {
                assert_eq!(status, 404);
                assert_eq!(method, "GET");
                assert_eq!(href, "/cal/missing.ics");
                assert_eq!(body, "Not Found");
            }
            other => panic!("expected Error::CalDav, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn put_event_server_error_maps_to_caldav_error_with_context() {
        let server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/cal/evt-1.ics"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let ev = Event {
            uid: "evt-1".into(),
            href: None,
            etag: None,
            summary: "Standup".into(),
            start: Utc.with_ymd_and_hms(2026, 8, 3, 9, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 8, 3, 9, 15, 0).unwrap(),
            location: None,
            description: None,
            rrule: None,
            is_instance: false,
        };
        let err = client.put_event("/cal/", &ev).await.expect_err("expected error");
        match err {
            Error::CalDav { status, method, href, body } => {
                assert_eq!(status, 500);
                assert_eq!(method, "PUT");
                assert_eq!(href, "/cal/evt-1.ics");
                assert_eq!(body, "boom");
            }
            other => panic!("expected Error::CalDav, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn calendar_home_missing_principal_is_not_found() {
        let server = MockServer::start().await;

        // The principal PROPFIND response has no <current-user-principal> at all.
        let empty_body = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:">
  <response>
    <href>/</href>
    <propstat><prop></prop></propstat>
  </response>
</multistatus>"#;
        Mock::given(method("PROPFIND"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(207).set_body_string(empty_body))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.list_calendars().await.expect_err("expected error");
        assert!(matches!(err, Error::NotFound(_)), "expected Error::NotFound, got {err:?}");
    }

    #[test]
    fn object_href_joins_collection_and_uid_exactly_once() {
        assert_eq!(FastmailCalDav::object_href("/cal/", "evt-1"), "/cal/evt-1.ics");
        assert_eq!(FastmailCalDav::object_href("/cal", "evt-1"), "/cal/evt-1.ics");
    }
}
