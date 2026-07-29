use crate::error::{Error, Result};
use quick_xml::Reader;
use quick_xml::events::Event as XmlEvent;
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
                    "response" => {
                        cur = Some(DavResponse {
                            href: String::new(),
                            props: HashMap::new(),
                        })
                    }
                    "href" => cur_prop = Some("href".into()),
                    other => {
                        cur_prop = Some(other.to_string());
                    }
                }
            }
            Ok(XmlEvent::Text(t)) => {
                if let (Some(resp), Some(prop)) = (cur.as_mut(), cur_prop.as_ref()) {
                    let text = t
                        .unescape()
                        .map_err(|e| Error::Xml(e.to_string()))?
                        .to_string();
                    if prop == "href" && resp.href.is_empty() {
                        resp.href = text;
                    } else {
                        resp.props.insert(prop.clone(), text);
                    }
                }
            }
            // CDATA sections carry literal text (no entity unescaping). Fastmail
            // wraps property values like <displayname> in CDATA, so this arm is
            // needed or those props read as absent.
            Ok(XmlEvent::CData(t)) => {
                if let (Some(resp), Some(prop)) = (cur.as_mut(), cur_prop.as_ref()) {
                    let text = String::from_utf8_lossy(&t.into_inner()).into_owned();
                    if prop == "href" && resp.href.is_empty() {
                        resp.href = text;
                    } else {
                        resp.props.insert(prop.clone(), text);
                    }
                }
            }
            Ok(XmlEvent::End(e)) => {
                let name = local(e.name().as_ref());
                if name == "response"
                    && let Some(r) = cur.take()
                {
                    responses.push(r);
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

/// Extract the text of a nested `<href>` element inside a named container property.
///
/// Some DAV properties (`current-user-principal`, `calendar-home-set`) have a value
/// that is itself a single nested `<href>...</href>`, e.g.:
/// ```xml
/// <current-user-principal><href>/dav/principals/user/me/</href></current-user-principal>
/// ```
/// [`parse_multistatus`] is a flat local-name parser and cannot represent this
/// unambiguously (the container's own text is empty, and the inner `<href>` text
/// collides with the response's own outer `<href>` under the same `"href"` key - see
/// module docs). This is a small, dedicated pass that walks the raw XML looking
/// specifically for `<container_local_name><href>...</href></container_local_name>`
/// and returns the inner text of the first such match.
pub fn nested_href(xml: &str, container_local_name: &str) -> Result<Option<String>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut depth: u32 = 0; // > 0 while inside the target container
    let mut in_href = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(Error::Xml(e.to_string())),
            Ok(XmlEvent::Eof) => break,
            Ok(XmlEvent::Start(e)) => {
                let name = local(e.name().as_ref());
                if name == container_local_name {
                    depth += 1;
                } else if depth > 0 && name == "href" {
                    in_href = true;
                }
            }
            Ok(XmlEvent::Text(t)) if depth > 0 && in_href => {
                let text = t
                    .unescape()
                    .map_err(|e| Error::Xml(e.to_string()))?
                    .to_string();
                return Ok(Some(text));
            }
            Ok(XmlEvent::End(e)) => {
                let name = local(e.name().as_ref());
                if name == container_local_name {
                    depth = depth.saturating_sub(1);
                } else if name == "href" {
                    in_href = false;
                }
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(None)
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
/// time-range (start,end). Requests calendar-data with server-side <expand>
/// when a range is given (recurrence R1).
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

    const PRINCIPAL_MULTISTATUS: &str = r#"<?xml version="1.0"?>
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

    const HOME_MULTISTATUS: &str = r#"<?xml version="1.0"?>
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

    #[test]
    fn nested_href_extracts_current_user_principal() {
        let href = nested_href(PRINCIPAL_MULTISTATUS, "current-user-principal").expect("parse");
        assert_eq!(href.as_deref(), Some("/dav/principals/user/me/"));
    }

    #[test]
    fn nested_href_extracts_calendar_home_set() {
        let href = nested_href(HOME_MULTISTATUS, "calendar-home-set").expect("parse");
        assert_eq!(href.as_deref(), Some("/dav/calendars/user/me/"));
    }

    #[test]
    fn nested_href_returns_none_when_container_absent() {
        let href = nested_href(HOME_MULTISTATUS, "current-user-principal").expect("parse");
        assert_eq!(href, None);
    }
}
