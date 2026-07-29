# mcp-caldav-fastmail

A single-user HTTP [MCP](https://modelcontextprotocol.io) server that exposes
a Fastmail calendar (and tasks) to MCP clients such as Claude Code and Claude
Desktop. It authenticates **inbound** MCP clients with OAuth 2.1, delegating
token issuance to a self-hosted [Authelia](https://www.authelia.com/)
instance, and authenticates **outbound** to Fastmail's CalDAV service with an
app password. It is built for one operator's own calendar — there is no
multi-tenancy or per-user credential storage.

## Architecture

```
Claude Code / Desktop ──HTTP/OAuth──▶ [axum]
                                       ├─ auth middleware (validates Authelia JWT)
                                       ├─ GET /.well-known/oauth-protected-resource (RFC 9728)
                                       └─ /mcp  (rmcp StreamableHttpService)
                                             └─ CalDavClient ──HTTP/app-password──▶ Fastmail CalDAV
```

The server is a pure **OAuth 2.1 Resource Server**: it holds no user
passwords and issues no tokens itself. It validates bearer tokens minted by
Authelia (signature via JWKS, issuer, audience, expiry, required scope) and
otherwise gets out of the way.

This is topology **T2**: the Protected Resource Metadata (PRM) document
points directly at Authelia as the authorization server. There is no
Dynamic Client Registration (DCR) shim in front of it — see
[Known limitations](#known-limitations) for what that costs with Claude
Desktop.

## Configuration

All configuration is via environment variables (`src/config.rs`):

| Variable | Required / default | Description |
|---|---|---|
| `BIND_ADDR` | default `0.0.0.0:8080` | Address the HTTP server binds to. |
| `RESOURCE_URI` | **required** | This server's canonical public URI. Used as the `resource` in the PRM document and as the required token `aud` (audience) claim. |
| `AUTHELIA_ISSUER` | **required** | Authelia's OIDC issuer URL, checked against the token's `iss` claim. |
| `AUTHELIA_JWKS_URI` | **required** | Authelia's JWKS endpoint, used to fetch and cache the signing keys. |
| `REQUIRED_SCOPE` | default `caldav` | OAuth scope the access token must carry. |
| `FASTMAIL_USERNAME` | **required** | Fastmail account username for CalDAV basic auth. |
| `FASTMAIL_APP_PASSWORD` | **required, secret** | Fastmail app password for CalDAV basic auth. Never logged and never returned by any MCP tool. |
| `CALDAV_BASE_URL` | default `https://caldav.fastmail.com/` | Base URL for Fastmail's CalDAV service. |

## Getting a Fastmail app password

1. Log in to Fastmail, go to **Settings → Privacy & Security → Integrations → App passwords**.
2. Create a new app password scoped to **Calendars (CalDAV)** only — don't
   grant it broader access than it needs.
3. Set `FASTMAIL_USERNAME` to your Fastmail login email and
   `FASTMAIL_APP_PASSWORD` to the generated password.

## Authelia setup

Register this server as a **public** (no client secret), PKCE-only static
OIDC client in Authelia, and make sure the tokens it issues carry this
server's `RESOURCE_URI` as the audience (`aud`) — that's an RFC 8707
resource-indicator requirement, and the validator (`src/auth/validator.rs`)
will reject any token whose audience doesn't match exactly.

The exact schema keys below vary between Authelia versions — treat this as
a template to adapt against your installed version's
[OIDC provider docs](https://www.authelia.com/configuration/identity-providers/openid-connect/clients/),
not as gospel.

```yaml
# configuration.yml (excerpt)
identity_providers:
  oidc:
    clients:
      - client_id: 'mcp-caldav-fastmail'
        client_name: 'MCP CalDAV (Fastmail)'
        public: true # no client secret; PKCE required below
        authorization_policy: 'one_factor' # or 'two_factor' if you want MFA on every auth
        require_pkce: true
        pkce_challenge_method: 'S256'
        redirect_uris:
          - 'https://claude.ai/api/mcp/auth_callback' # Claude web/desktop OAuth callback
          - 'http://localhost:PORT/callback' # Claude Code local-loopback callback (port varies per run)
        grant_types:
          - 'authorization_code'
          - 'refresh_token'
        response_types:
          - 'code'
        scopes:
          - 'openid'
          - 'caldav' # must match REQUIRED_SCOPE
        # RFC 8707 resource indicator: tokens issued to this client for
        # this resource must carry aud == RESOURCE_URI exactly.
        audience:
          - 'https://your-mcp-host.example.com' # == RESOURCE_URI
        token_endpoint_auth_method: 'none' # public client, PKCE instead of a secret
```

Key points:

- **`audience` must equal `RESOURCE_URI` exactly** (scheme, host, and any
  path/trailing-slash you configured the server with) — a mismatch fails
  validation with a 401, not a helpful error message about *why*.
- `scopes` must include `REQUIRED_SCOPE` (`caldav` by default) or the
  validator rejects the token for missing scope.
- Claude Code's local redirect URI uses a loopback port chosen at flow time;
  check your Authelia version's support for wildcard/loopback redirect URIs
  rather than hardcoding one port.

## Running

```bash
export BIND_ADDR=0.0.0.0:8080
export RESOURCE_URI=https://your-mcp-host.example.com
export AUTHELIA_ISSUER=https://auth.example.com
export AUTHELIA_JWKS_URI=https://auth.example.com/jwks.json
export REQUIRED_SCOPE=caldav
export FASTMAIL_USERNAME=you@fastmail.com
export FASTMAIL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx
cargo run --release
```

Smoke checks once it's up:

```bash
# Public PRM document — no auth required, returns JSON
curl -s https://your-mcp-host.example.com/.well-known/oauth-protected-resource

# Protected endpoint without a token — 401 with a WWW-Authenticate challenge
# pointing back at the PRM document
curl -si https://your-mcp-host.example.com/mcp
```

## Connecting a client

**Claude Code:**

```bash
claude mcp add --transport http caldav https://your-mcp-host.example.com/mcp
```

Claude Code drives the OAuth 2.1 + PKCE flow against Authelia itself once it
sees the 401 challenge and discovers the PRM document.

**Claude Desktop — known limitation:** topology T2 advertises no Dynamic
Client Registration endpoint, and Claude Desktop has historically required
DCR to complete its OAuth flow automatically. The automatic connection flow
may therefore not complete in Desktop. The fallback for a single-user setup
is to obtain a bearer token out-of-band (e.g. via a manual Authelia
authorization-code exchange) and supply it directly as a static bearer
token where Desktop's client configuration allows one. This is a known,
accepted trade-off of T2 for a single-user deployment, not a bug.

## Tools

All 11 tools are registered in `src/mcp/tools.rs`:

- `list_calendars` — List all calendars available to this account.
- `list_events` — List events in a calendar within a time window.
- `get_event` — Get a single event by UID.
- `create_event` — Create a new event.
- `update_event` — Update an existing event. This always edits the whole series, never a single instance.
- `delete_event` — Delete an event by UID.
- `list_tasks` — List tasks (VTODOs) in a calendar.
- `get_task` — Get a single task (VTODO) by UID.
- `create_task` — Create a new task.
- `update_task` — Update an existing task.
- `delete_task` — Delete a task by UID.

## Known limitations

- **Recurrence tier R1 + R2 only.** Reading/expanding a recurring series into
  concrete instances, and creating/editing a whole series, are supported.
  Per-instance overrides and this-and-future splits (`RECURRENCE-ID`, series
  splitting — tier R3) are **not** implemented.
- **`list_tasks` has no server-side status/due filter.** It returns all
  VTODOs in the calendar; filtering is left to the caller.
- **Update tools use "`None` means leave unchanged" semantics.** There is no
  way to explicitly clear a field (e.g. remove a location or description) —
  only to set it to a new value or omit it.
- **Task `status` is a free string**, not validated against the
  `NEEDS-ACTION | IN-PROCESS | COMPLETED | CANCELLED` enum — callers can set
  anything.
- **Floating datetimes** (no `TZID`, no trailing `Z`) are treated as UTC
  rather than resolved against a user/system timezone.
- **Built iCalendar output is not RFC 5545 line-folded** (no 75-octet
  continuation lines). Most servers, including Fastmail, tolerate this, but
  it's a deviation from the spec.
- **Calendar component-set detection defaults to `["VEVENT"]`** for every
  calendar — the flat XML parser does not currently read
  `supported-calendar-component-set` from the PROPFIND response, so
  VTODO-only or mixed calendars are not distinguished in `list_calendars`
  output.

**Deferred (not planned for this version):** CardDAV/contacts, iTIP/iMIP
scheduling (invites, RSVPs), a JSCalendar/JMAP-native path, and multi-user
support.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

See `docs/superpowers/specs/2026-07-29-mcp-caldav-fastmail-design.md` for the
full design rationale.
