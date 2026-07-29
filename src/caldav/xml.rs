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

/// Which container property (if any) we're currently inside, for the purpose of
/// collecting information about its *child elements* rather than its own text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Container {
    /// Inside <resourcetype>...</resourcetype>: collect child local names.
    ResourceType,
    /// Inside <supported-calendar-component-set>...</...>: collect each child
    /// <comp name="..."/>'s `name` attribute.
    CompSet,
}

/// Append `value` onto `props[key]`, space-separating from any existing content.
fn append_prop(props: &mut HashMap<String, String>, key: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    props
        .entry(key.to_string())
        .and_modify(|existing| {
            if !existing.is_empty() {
                existing.push(' ');
            }
            existing.push_str(value);
        })
        .or_insert_with(|| value.to_string());
}

/// Read an attribute's value by local name (namespace prefix stripped) from a
/// `BytesStart`, e.g. `name` on `<C:comp name="VEVENT"/>`.
fn attr_local(e: &quick_xml::events::BytesStart, local_name: &str) -> Option<String> {
    e.attributes().filter_map(|a| a.ok()).find_map(|a| {
        if local(a.key.as_ref()) == local_name {
            a.unescape_value().ok().map(|v| v.into_owned())
        } else {
            None
        }
    })
}

/// Parse a DAV multistatus body into responses. Uses local names (namespace
/// prefix stripped), so "C:calendar-data" is keyed as "calendar-data".
///
/// Most properties are leaf text/CDATA keyed by local element name. Two
/// properties are containers whose *children* (not their own text) carry the
/// information we need, and are handled specially:
/// - `resourcetype`: child elements like `<collection/>` / `<C:calendar/>` /
///   `<C:schedule-inbox/>` have no text - their presence IS the value. We
///   record the space-separated local names of the children, e.g.
///   "collection calendar".
/// - `supported-calendar-component-set`: each child `<C:comp name="VEVENT"/>`
///   carries its value in the `name` attribute, not text. We record the
///   space-separated attribute values, e.g. "VEVENT VTODO".
pub fn parse_multistatus(xml: &str) -> Result<Vec<DavResponse>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut responses = Vec::new();
    let mut cur: Option<DavResponse> = None;
    let mut cur_prop: Option<String> = None;
    let mut container: Option<Container> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(Error::Xml(e.to_string())),
            Ok(XmlEvent::Eof) => break,
            Ok(XmlEvent::Start(e)) => {
                let name = local(e.name().as_ref());
                if let Some(c) = container {
                    // Inside a container property: this Start is a child element,
                    // not a new leaf prop - collect it and leave cur_prop alone.
                    if let (Some(resp), Some(key)) = (cur.as_mut(), container_key(c)) {
                        collect_container_child(c, &name, &e, resp, key);
                    }
                    continue;
                }
                match name.as_str() {
                    "response" => {
                        cur = Some(DavResponse {
                            href: String::new(),
                            props: HashMap::new(),
                        })
                    }
                    "href" => cur_prop = Some("href".into()),
                    "resourcetype" => {
                        container = Some(Container::ResourceType);
                        cur_prop = None;
                    }
                    "supported-calendar-component-set" => {
                        container = Some(Container::CompSet);
                        cur_prop = None;
                    }
                    other => {
                        cur_prop = Some(other.to_string());
                    }
                }
            }
            Ok(XmlEvent::Empty(e)) => {
                let name = local(e.name().as_ref());
                if let (Some(c), Some(resp)) = (container, cur.as_mut())
                    && let Some(key) = container_key(c)
                {
                    collect_container_child(c, &name, &e, resp, key);
                }
                // An empty container element itself (e.g. a self-closing
                // <resourcetype/>) has no children to collect and isn't one of
                // the leaf props we care about here - nothing else to do.
            }
            Ok(XmlEvent::Text(t)) => {
                if container.is_none()
                    && let (Some(resp), Some(prop)) = (cur.as_mut(), cur_prop.as_ref())
                {
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
                if container.is_none()
                    && let (Some(resp), Some(prop)) = (cur.as_mut(), cur_prop.as_ref())
                {
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
                if container.is_some()
                    && (name == "resourcetype" || name == "supported-calendar-component-set")
                {
                    container = None;
                }
                cur_prop = None;
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(responses)
}

/// The props key a container's collected children are stored under.
fn container_key(c: Container) -> Option<&'static str> {
    match c {
        Container::ResourceType => Some("resourcetype"),
        Container::CompSet => Some("supported-calendar-component-set"),
    }
}

/// Collect one child element of a container property (`resourcetype` or
/// `supported-calendar-component-set`) into `resp.props[key]`. Called for both
/// `Start` and `Empty` child events, since real servers send self-closing
/// elements like `<collection/>` and `<C:comp name="VEVENT"/>`.
fn collect_container_child(
    c: Container,
    child_local_name: &str,
    e: &quick_xml::events::BytesStart,
    resp: &mut DavResponse,
    key: &str,
) {
    match c {
        Container::ResourceType => append_prop(&mut resp.props, key, child_local_name),
        Container::CompSet => {
            if child_local_name == "comp"
                && let Some(name) = attr_local(e, "name")
            {
                append_prop(&mut resp.props, key, &name);
            }
        }
    }
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

    #[test]
    fn parses_cdata_property() {
        // Regression test for the CDATA fix: Fastmail wraps displayname (and other
        // leaf props) in CDATA rather than plain text/entity-escaped text.
        let xml = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:">
  <response>
    <href>/dav/calendars/user/me/work/</href>
    <propstat><prop>
      <displayname><![CDATA[My Cal]]></displayname>
    </prop></propstat>
  </response>
</multistatus>"#;
        let rs = parse_multistatus(xml).expect("parse");
        assert_eq!(rs[0].prop("displayname").as_deref(), Some("My Cal"));
    }

    #[test]
    fn parses_resourcetype_children() {
        let xml = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <response>
    <href>/dav/calendars/user/me/work/</href>
    <propstat><prop>
      <resourcetype><collection/><C:calendar/></resourcetype>
    </prop></propstat>
  </response>
</multistatus>"#;
        let rs = parse_multistatus(xml).expect("parse");
        let rt = rs[0].prop("resourcetype").expect("resourcetype prop");
        let tokens: Vec<&str> = rt.split_whitespace().collect();
        assert!(tokens.contains(&"collection"), "resourcetype was: {rt}");
        assert!(tokens.contains(&"calendar"), "resourcetype was: {rt}");
    }

    #[test]
    fn parses_component_set() {
        let xml = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <response>
    <href>/dav/calendars/user/me/work/</href>
    <propstat><prop>
      <C:supported-calendar-component-set>
        <C:comp name="VEVENT"/>
        <C:comp name="VTODO"/>
      </C:supported-calendar-component-set>
    </prop></propstat>
  </response>
</multistatus>"#;
        let rs = parse_multistatus(xml).expect("parse");
        let comps = rs[0]
            .prop("supported-calendar-component-set")
            .expect("comp-set prop");
        let tokens: Vec<&str> = comps.split_whitespace().collect();
        assert!(tokens.contains(&"VEVENT"), "comps was: {comps}");
        assert!(tokens.contains(&"VTODO"), "comps was: {comps}");
    }
}
