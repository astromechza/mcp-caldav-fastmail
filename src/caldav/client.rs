//! CalDAV client trait and a Fastmail-flavored `reqwest` implementation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use reqwest::header::HeaderMap;
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
    async fn list_events(
        &self,
        cal_href: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<Event>>;
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
            .timeout(std::time::Duration::from_secs(30))
            // Pin to compiled-in Mozilla roots so cert verification never
            // touches the filesystem -- see `crate::tls` for why.
            .tls_certs_only(crate::tls::webpki_roots()?)
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
        let url = self
            .base
            .join(href)
            .map_err(|e| Error::Config(format!("invalid href {href:?}: {e}")))?;
        // SSRF guard: `Url::join` treats an absolute URL or a scheme-relative
        // `//host/...` href as an override, which could redirect a request
        // (carrying the Fastmail Basic-auth credentials) to an attacker-chosen
        // origin. hrefs come from tool inputs (calendar/uid) and server
        // responses, so pin every resolved URL to the configured base origin.
        if url.origin() != self.base.origin() {
            return Err(Error::CalDav {
                status: 0,
                method: "RESOLVE".into(),
                href: href.to_string(),
                body: "refusing href that resolves to a different origin than the CalDAV base"
                    .into(),
            });
        }
        Ok(url)
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
    /// "/dav/" -> current-user-principal -> calendar-home-set.
    ///
    /// Fastmail's CalDAV context lives under `/dav/` (a PROPFIND on `/` returns
    /// nginx 404; `/.well-known/caldav` 301-redirects to `/dav/calendars`).
    async fn calendar_home(&self) -> Result<String> {
        let (_, _, principal_body) = self
            .dav(
                "PROPFIND",
                "/dav/",
                Some("0"),
                Some(xml::propfind_principal_body().to_string()),
                None,
                Some(XML_CONTENT_TYPE),
            )
            .await?;
        let principal =
            xml::nested_href(&principal_body, "current-user-principal")?.ok_or_else(|| {
                Error::NotFound("current-user-principal not found in discovery response".into())
            })?;

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
        let home = xml::nested_href(&home_body, "calendar-home-set")?.ok_or_else(|| {
            Error::NotFound("calendar-home-set not found in discovery response".into())
        })?;

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

        // `home` came from the discovery PROPFIND response while `r.href` comes from
        // this (separate) PROPFIND Depth:1 response, so trailing-slash formatting
        // might differ even for the logically same collection - kept as a
        // belt-and-suspenders check alongside the resourcetype filter below, which
        // is what actually distinguishes real calendars now.
        let home_trimmed = home.trim_end_matches('/');
        let responses = xml::parse_multistatus(&body)?;
        let mut calendars = Vec::new();
        for r in responses {
            if r.href.trim_end_matches('/') == home_trimmed {
                // The home collection itself, not a calendar within it.
                continue;
            }
            // Only resourcetype "calendar" is a real user calendar. This excludes
            // the home container (resourcetype "collection" only) and scheduling
            // collections (resourcetype "collection schedule-inbox" /
            // "collection schedule-outbox"), which otherwise look just like a
            // calendar (they carry a displayname too).
            let is_calendar = r
                .prop("resourcetype")
                .is_some_and(|rt| rt.split_whitespace().any(|tok| tok == "calendar"));
            if !is_calendar {
                continue;
            }
            let Some(display_name) = r.prop("displayname") else {
                continue;
            };
            let color = r.prop("calendar-color");
            let ctag = r.prop("getctag");
            let components = match r.prop("supported-calendar-component-set") {
                Some(set) if !set.trim().is_empty() => {
                    set.split_whitespace().map(str::to_string).collect()
                }
                _ => vec!["VEVENT".to_string()],
            };
            calendars.push(Calendar {
                href: r.href,
                display_name,
                color,
                components,
                ctag,
            });
        }
        Ok(calendars)
    }

    async fn list_events(
        &self,
        cal_href: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<Event>> {
        let start_fmt = start.format("%Y%m%dT%H%M%SZ").to_string();
        let end_fmt = end.format("%Y%m%dT%H%M%SZ").to_string();
        let body = xml::calendar_query_body("VEVENT", Some((&start_fmt, &end_fmt)));
        let (_, _, resp_body) = self
            .dav(
                "REPORT",
                cal_href,
                Some("1"),
                Some(body),
                None,
                Some(XML_CONTENT_TYPE),
            )
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
        ev.etag = headers
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        Ok(ev)
    }

    async fn put_event(&self, cal_href: &str, ev: &Event) -> Result<()> {
        let href = ev
            .href
            .clone()
            .unwrap_or_else(|| Self::object_href(cal_href, &ev.uid));
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
            .dav(
                "REPORT",
                cal_href,
                Some("1"),
                Some(body),
                None,
                Some(XML_CONTENT_TYPE),
            )
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
        td.etag = headers
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        Ok(td)
    }

    async fn put_todo(&self, cal_href: &str, td: &Todo) -> Result<()> {
        let href = td
            .href
            .clone()
            .unwrap_or_else(|| Self::object_href(cal_href, &td.uid));
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
        FastmailCalDav::new(&server.uri(), "anth@benmeier.fastmail.com", "app-password")
            .expect("client")
    }

    #[test]
    fn resolve_pins_to_base_origin() {
        let c = FastmailCalDav::new("https://caldav.fastmail.com/", "u", "p").unwrap();
        // Same-origin path-absolute and relative hrefs resolve fine.
        assert!(c.resolve("/dav/calendars/user/x/evt.ics").is_ok());
        assert!(c.resolve("dav/x.ics").is_ok());
        // Same-origin absolute URL (as a server might echo) is allowed.
        assert!(c.resolve("https://caldav.fastmail.com/dav/x.ics").is_ok());
        // SSRF vectors must be rejected: absolute off-origin + scheme-relative host.
        assert!(c.resolve("https://evil.example/steal").is_err());
        assert!(c.resolve("//evil.example/steal").is_err());
        assert!(c.resolve("http://caldav.fastmail.com/x").is_err()); // scheme change
    }

    #[tokio::test]
    async fn list_calendars_walks_full_discovery_chain() {
        let server = MockServer::start().await;

        // Step 1: PROPFIND "/dav/" -> current-user-principal (nested href).
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
            .and(path("/dav/"))
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

        // Step 3: PROPFIND on the calendar-home -> the list of calendars. This
        // mirrors real Fastmail Depth:1 output: the home container itself
        // (resourcetype "collection" only), a real calendar (resourcetype
        // "collection calendar" with a component-set), and a scheduling
        // collection (resourcetype "collection schedule-inbox") that must be
        // skipped even though it also carries a displayname.
        let calendars_body = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/">
  <response>
    <href>/dav/calendars/user/me/</href>
    <propstat><prop>
      <displayname><![CDATA[me]]></displayname>
      <resourcetype><collection/></resourcetype>
    </prop></propstat>
  </response>
  <response>
    <href>/dav/calendars/user/me/work/</href>
    <propstat><prop>
      <displayname><![CDATA[Work]]></displayname>
      <resourcetype><collection/><C:calendar/></resourcetype>
      <C:supported-calendar-component-set>
        <C:comp name="VEVENT"/>
        <C:comp name="VTODO"/>
      </C:supported-calendar-component-set>
      <CS:getctag>ctag-1</CS:getctag>
    </prop></propstat>
  </response>
  <response>
    <href>/dav/calendars/user/me/home/</href>
    <propstat><prop>
      <displayname><![CDATA[Home]]></displayname>
      <resourcetype><collection/><C:calendar/></resourcetype>
      <C:supported-calendar-component-set>
        <C:comp name="VEVENT"/>
      </C:supported-calendar-component-set>
      <CS:getctag>ctag-2</CS:getctag>
    </prop></propstat>
  </response>
  <response>
    <href>/dav/calendars/user/me/Inbox/</href>
    <propstat><prop>
      <displayname><![CDATA[Inbox]]></displayname>
      <resourcetype><collection/><C:schedule-inbox/></resourcetype>
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

        assert_eq!(
            calendars.len(),
            2,
            "home collection and scheduling collection must be skipped: {calendars:?}"
        );
        assert_eq!(calendars[0].display_name, "Work");
        assert_eq!(calendars[0].href, "/dav/calendars/user/me/work/");
        assert_eq!(calendars[0].ctag.as_deref(), Some("ctag-1"));
        assert_eq!(
            calendars[0].components,
            vec!["VEVENT".to_string(), "VTODO".to_string()]
        );
        assert_eq!(calendars[1].display_name, "Home");
        assert_eq!(calendars[1].href, "/dav/calendars/user/me/home/");
        assert_eq!(calendars[1].components, vec!["VEVENT".to_string()]);
    }

    #[tokio::test]
    async fn list_calendars_skips_scheduling_collections() {
        // Focused regression test for the resourcetype-based filter: a
        // schedule-inbox/schedule-outbox collection must never be treated as a
        // user calendar, even though it carries a displayname like real Fastmail
        // data does.
        let server = MockServer::start().await;

        let principal_body = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:">
  <response>
    <href>/</href>
    <propstat><prop>
      <current-user-principal><href>/dav/principals/user/me/</href></current-user-principal>
    </prop></propstat>
  </response>
</multistatus>"#;
        Mock::given(method("PROPFIND"))
            .and(path("/dav/"))
            .respond_with(ResponseTemplate::new(207).set_body_string(principal_body))
            .mount(&server)
            .await;

        let home_body = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <response>
    <href>/dav/principals/user/me/</href>
    <propstat><prop>
      <C:calendar-home-set><href>/dav/calendars/user/me/</href></C:calendar-home-set>
    </prop></propstat>
  </response>
</multistatus>"#;
        Mock::given(method("PROPFIND"))
            .and(path("/dav/principals/user/me/"))
            .respond_with(ResponseTemplate::new(207).set_body_string(home_body))
            .mount(&server)
            .await;

        let calendars_body = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <response>
    <href>/dav/calendars/user/me/Outbox/</href>
    <propstat><prop>
      <displayname><![CDATA[Outbox]]></displayname>
      <resourcetype><collection/><C:schedule-outbox/></resourcetype>
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
        assert!(
            calendars.is_empty(),
            "schedule-outbox must not be returned as a calendar: {calendars:?}"
        );
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
        let events = client
            .list_events("/cal/", start, end)
            .await
            .expect("list_events");

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
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(ics)
                    .insert_header("ETag", "\"e9\""),
            )
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
        client
            .delete_event("/cal/", "evt-1")
            .await
            .expect("delete_event");
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
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(ics)
                    .insert_header("ETag", "\"t9\""),
            )
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
        client
            .delete_todo("/cal/", "todo-1")
            .await
            .expect("delete_todo");
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
        let err = client
            .get_event("/cal/", "missing")
            .await
            .expect_err("expected error");
        match err {
            Error::CalDav {
                status,
                method,
                href,
                body,
            } => {
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
        let err = client
            .put_event("/cal/", &ev)
            .await
            .expect_err("expected error");
        match err {
            Error::CalDav {
                status,
                method,
                href,
                body,
            } => {
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
            .and(path("/dav/"))
            .respond_with(ResponseTemplate::new(207).set_body_string(empty_body))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.list_calendars().await.expect_err("expected error");
        assert!(
            matches!(err, Error::NotFound(_)),
            "expected Error::NotFound, got {err:?}"
        );
    }

    #[test]
    fn object_href_joins_collection_and_uid_exactly_once() {
        assert_eq!(
            FastmailCalDav::object_href("/cal/", "evt-1"),
            "/cal/evt-1.ics"
        );
        assert_eq!(
            FastmailCalDav::object_href("/cal", "evt-1"),
            "/cal/evt-1.ics"
        );
    }
}
