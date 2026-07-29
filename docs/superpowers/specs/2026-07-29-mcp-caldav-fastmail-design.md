# mcp-caldav-fastmail — Design

**Date:** 2026-07-29
**Status:** Approved (pending spec review)

## 1. Purpose & Scope

A single-user HTTP MCP server that exposes tools for managing a Fastmail
calendar via CalDAV. It authenticates **inbound** MCP clients with OAuth 2.1
(delegated to a self-hosted Authelia), and authenticates **outbound** to
Fastmail with an app password.

The project is deliberately also a learning vehicle for the OAuth
Resource-Server pattern, so the auth layer is built properly rather than
shortcut with a static bearer token.

### In scope (v1)

- Read + write **calendar events** (VEVENT).
- Read + write **tasks** (VTODO).
- Recurrence tier **R1 + R2**:
  - **R1** — read/expand any recurring series into instances over a time
    window.
  - **R2** — create a recurring series and edit the **whole** series (set/change
    RRULE on the master).
  - **Out of scope:** per-instance overrides, this-and-future splits
    (`RECURRENCE-ID`, series splitting). That is R3 and explicitly deferred.
- Inbound OAuth via Authelia (Resource-Server pattern, topology **T2**, §5).
- Outbound Fastmail auth via app password held in server config.

### Out of scope (v1)

- Contacts / CardDAV.
- iTIP/iMIP scheduling (sending invites, RSVP handling).
- Per-instance recurrence editing (R3).
- Multi-tenant / multi-user. This is single-user.

## 2. Crate Stack

| Concern | Crate | Notes |
|---|---|---|
| MCP server | `rmcp` (official SDK) | Tower service, `nest_service("/mcp", …)` on axum. Auth is developer-owned in front of it. |
| HTTP host | `axum` + `tower` | Router, middleware layer for token validation. |
| JWT validation | `jsonwebtoken` | Verify signature, `aud`, `iss`, `exp`. |
| JWKS fetch/cache | `jwks` (or `axum-jwks`) | Fetch + cache Authelia JWKS, refresh on key rotation. |
| CalDAV HTTP | `reqwest` | Basic-auth app password to Fastmail. |
| XML | `quick-xml` | Build PROPFIND/REPORT bodies, parse `multistatus`. |
| iCalendar | `calcard` (Stalwart Labs) | Parse + build + **built-in RRULE expansion**. Chosen over `icalendar`+`rrule` for future JSCalendar/JMAP support that Fastmail is chasing. |
| Async runtime | `tokio` | |
| Logging | `tracing` + `tracing-subscriber` | |
| Errors | `thiserror` | Typed errors → MCP error mapping. |
| Config | `serde` + env (`figment` optional) | |
| Test HTTP mock | `wiremock` | Mock CalDAV server for integration tests. |

CalDAV is **hand-rolled** (no `libdav`/`fast-dav-rs` dependency); the DAV surface
needed is small. `fast-dav-rs` is used only as a reference for exact request/
response XML shapes.

## 3. Architecture

```
Claude Code / Desktop ──HTTP/OAuth──▶ [axum]
                                       ├─ auth middleware (validate Authelia JWT)
                                       ├─ GET /.well-known/oauth-protected-resource (RFC 9728)
                                       └─ /mcp  (rmcp StreamableHttpService)
                                             └─ tool handlers
                                                   └─ caldav::Client ──HTTP/app-pw──▶ Fastmail CalDAV
                                                         └─ calcard (parse/build/expand ICS)
```

## 4. Module Layout

```
src/
  main.rs        bootstrap: load config, init tracing, build axum app, serve
  config.rs      bind addr; Authelia issuer + jwks_uri + expected audience;
                 Fastmail username + app password; CalDAV base URL
  auth/
    metadata.rs  RFC 9728 protected-resource-metadata handler;
                 WWW-Authenticate header on 401
    validator.rs JWT verification: jsonwebtoken + cached JWKS;
                 checks aud / iss / exp / required scope; axum middleware
  caldav/
    client.rs    reqwest wrapper: discovery, PROPFIND / REPORT / PUT / DELETE,
                 ETag (If-Match) concurrency
    xml.rs       quick-xml: build request bodies, parse multistatus responses
    model.rs     domain structs: Calendar, Event, Todo
  ical.rs        calcard wrappers: ICS <-> domain structs, recurrence expansion
  mcp/
    tools.rs     rmcp tool registration + handlers
  error.rs       thiserror error types -> MCP error mapping
```

Note vs earlier draft: topology T2 means **no** `auth/dcr.rs` and **no**
`auth/server.rs` (facade AS). Auth is just PRM + validator.

## 5. Auth Design (Topology T2 — Direct to Authelia)

The MCP server is a pure **OAuth 2.1 Resource Server**. It holds no user
passwords and issues no tokens.

**Discovery / challenge flow:**

1. Client calls `/mcp` without a valid token → `401` with
   `WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource"`.
2. Client GETs `/.well-known/oauth-protected-resource` (RFC 9728) → JSON:
   - `resource`: this server's canonical URI
   - `authorization_servers`: `[ <Authelia issuer> ]`
   - `scopes_supported`, `bearer_methods_supported: ["header"]`
3. Client discovers Authelia's AS metadata directly, runs the OAuth 2.1 +
   PKCE authorization-code flow against Authelia, obtains an access token.
4. Client retries `/mcp` with `Authorization: Bearer <jwt>`.

**Token validation (`auth/validator.rs`), per request:**

- Fetch + cache Authelia JWKS (`jwks_uri` from config); refresh on unknown `kid`.
- Verify JWT signature (RS256).
- Verify `iss` == Authelia issuer, `aud` == this server's resource URI,
  `exp` not passed, required scope present.
- On failure → `401` + `WWW-Authenticate` challenge.

**Audience binding:** Authelia's static OIDC client for this server must be
pre-configured to issue tokens whose audience is this server's resource URI
(RFC 8707 resource indicator). Configured once in Authelia YAML.

**Known limitation:** T2 advertises no Dynamic Client Registration endpoint.
- **Claude Code** — expected to complete the flow (supports pre-configured /
  discovered client).
- **Claude Desktop** — historically requires DCR; may not complete the flow.
  Fallback for Desktop is a manually-issued token. Accepted for a single-user
  build.

## 6. CalDAV Data Flow

**Discovery (once, cached in-process):**

1. PROPFIND `current-user-principal`.
2. PROPFIND `calendar-home-set` on the principal.
3. PROPFIND the calendar-home collection → enumerate calendars with
   `displayname`, `supported-calendar-component-set` (VEVENT/VTODO), calendar
   color, `getctag`.

**Read events:** REPORT `calendar-query` with a `time-range` filter and
server-side `expand` so recurring series come back as concrete instances within
the requested window (R1).

**Read tasks:** REPORT `calendar-query` with `comp=VTODO`, filter by status/due.

**Writes:** build ICS via calcard → `PUT` to the resource href with
`If-Match: <etag>` for lost-update protection. Updates are read-modify-write:
fetch current object + ETag, mutate, PUT with the ETag. `DELETE` is
**unconditional** (delete-by-UID): a UID identifies the same logical object
across edits, so deleting it is correct regardless of intervening changes — an
`If-Match` guard there would make a benign reschedule spuriously fail the
delete, which is worse UX for an assistant. Only `PUT` is ETag-guarded.

## 7. MCP Tools (v1)

**Read**
- `list_calendars` → calendars (id, name, color, supported components)
- `list_events(calendar, start, end)` → expanded instances in window
- `get_event(calendar, uid)` → full detail incl. RRULE
- `list_tasks(calendar, filter)` → VTODOs (by status/due)
- `get_task(calendar, uid)`

**Write — events**
- `create_event(calendar, summary, start, end, tz, location?, description?, attendees?, rrule?)`
- `update_event(calendar, uid, <patch fields>)` — whole-series edit (R2)
- `delete_event(calendar, uid)`

**Write — tasks**
- `create_task(calendar, summary, due?, status?, description?, priority?)`
- `update_task(calendar, uid, <patch fields>)`
- `delete_task(calendar, uid)`

Conventions: times are RFC3339 with an explicit timezone; `update_*` are
ETag-guarded read-modify-write (etag fetched internally). `delete_*` are
unconditional delete-by-UID (see §6).

## 8. Error Handling & Testing

**Errors (`error.rs`):** one `thiserror` enum spanning CalDAV HTTP faults
(status + body), XML parse failures, ICS parse/build failures (calcard), and
auth failures. Mapped to clean MCP tool errors; full detail to `tracing`.

**Testing:**
- **Unit:** XML request-build + multistatus-parse; ICS ↔ domain round-trips via
  calcard; recurrence expansion over a window; JWT validation against a mock
  JWKS (valid, wrong-aud, expired, bad-sig).
- **Integration:** `caldav::Client` against a `wiremock` CalDAV server; MCP tool
  handlers against a trait-mocked CalDAV client.
- **No live-Fastmail tests in CI.** A manual/ignored smoke test may hit a real
  account locally.

Design for testability: `caldav::Client` behind a trait so tool handlers mock
it; JWKS source injectable so the validator is tested without a live Authelia.

## 9. Configuration

Environment (or file via `figment`):

- `BIND_ADDR` — e.g. `0.0.0.0:8080`
- `RESOURCE_URI` — this server's canonical public URI (token audience)
- `AUTHELIA_ISSUER` — issuer URL
- `AUTHELIA_JWKS_URI` — JWKS endpoint (or derived from issuer discovery)
- `REQUIRED_SCOPE` — scope the token must carry
- `FASTMAIL_USERNAME` — Fastmail account
- `FASTMAIL_APP_PASSWORD` — app password (secret; never logged, never exposed
  via any tool)
- `CALDAV_BASE_URL` — Fastmail CalDAV base (default `https://caldav.fastmail.com/`)

## 10. Deferred / Future

- R3 recurrence (per-instance overrides, this-and-future splits).
- JSCalendar / JMAP-native path (calcard already positions for this).
- CardDAV / contacts.
- iTIP scheduling.
- Multi-user + per-user credential storage (would revive facade-AS / DCR).
