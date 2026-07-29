# mcp-caldav-fastmail

A single-user HTTP [MCP](https://modelcontextprotocol.io) server that exposes
a Fastmail calendar (and tasks) to MCP clients such as Claude Code and Claude
Desktop. It authenticates **inbound** MCP clients with a pluggable auth mode
(JWT, shared-secret token, or none), and authenticates **outbound** to
Fastmail's CalDAV service with an app password. It is built for one
operator's own calendar — there is no multi-tenancy or per-user credential
storage.

## Architecture

```
Claude Code / Desktop ──HTTP──▶ [axum]
                                 ├─ auth middleware (mode: jwt | token | none)
                                 ├─ GET /.well-known/oauth-protected-resource (RFC 9728, jwt mode only)
                                 └─ /mcp  (rmcp StreamableHttpService)
                                       └─ CalDavClient ──HTTP/app-password──▶ Fastmail CalDAV
```

The server holds no user passwords and issues no tokens itself. Inbound
authentication is selected at startup via `AUTH_MODE` and dispatched through
a single `Authenticator` (`src/auth/authn.rs`):

- **`jwt`** (default) — an OAuth 2.1 Resource Server. It validates RS256
  bearer tokens minted by an external issuer, and serves an RFC 9728
  Protected Resource Metadata (PRM) document so OAuth-aware clients can
  discover how to obtain one. Works with **any issuer that exposes a JWKS
  endpoint**, or with an offline-minted token verified against a static
  public key — see [Offline token minting](#offline-token-minting-jwt--static-public-key).
- **`token`** — a static shared-secret bearer token, checked in constant
  time. No PRM, no discovery — the client just sends the secret.
- **`none`** — no application-level auth at all, for deployments that sit
  behind an authenticating edge (e.g. a platform-gated private container).

## Configuration

All configuration is via environment variables (`src/config.rs`):

| Variable | Mode | Required / default | Description |
|---|---|---|---|
| `AUTH_MODE` | all | default `jwt` | `jwt`, `token`, or `none`. |
| `BIND_ADDR` | all | default `0.0.0.0:8080` | Address the HTTP server binds to. |
| `FASTMAIL_USERNAME` | all | **required** | Fastmail account username for CalDAV basic auth. |
| `FASTMAIL_APP_PASSWORD` | all | **required, secret** | Fastmail app password for CalDAV basic auth. Never logged and never returned by any MCP tool. |
| `CALDAV_BASE_URL` | all | default `https://caldav.fastmail.com/` | Base URL for Fastmail's CalDAV service. |
| `RESOURCE_URI` | jwt | **required** | This server's canonical public URI. Used as the `resource` in the PRM document and as the default token `aud` (audience) claim. |
| `AUTH_JWKS_URI` | jwt | one of this or `AUTH_JWT_PUBLIC_KEY` **required** | Issuer's JWKS endpoint; keys are fetched on demand and cached in memory. |
| `AUTH_JWT_PUBLIC_KEY` | jwt | one of this or `AUTH_JWKS_URI` **required** | A static RSA public key — inline PEM text or a filesystem path to a PEM file. Use this when you mint tokens offline instead of running a full OIDC issuer. |
| `AUTH_JWT_ISSUER` | jwt | optional | Expected `iss` claim. If unset, the issuer is not checked. |
| `AUTH_JWT_AUDIENCE` | jwt | optional, defaults to `RESOURCE_URI` | Expected `aud` claim. Since it always defaults to `RESOURCE_URI`, audience is effectively always checked in `jwt` mode unless you point it somewhere other than `RESOURCE_URI` on purpose. |
| `REQUIRED_SCOPE` | jwt | default `caldav` | OAuth scope the access token's `scope` claim must carry. Set `REQUIRED_SCOPE=""` to disable the check — useful for minimal offline-minted static-key tokens that don't carry a scope claim. |
| `MCP_TOKEN` | token | **required, secret** | Shared bearer secret. Compared in constant time. Use a long random value (a warning is logged if it's under 32 characters). |

`exp` (expiry) is always enforced in `jwt` mode regardless of the other
settings above. `FASTMAIL_APP_PASSWORD` and `MCP_TOKEN` are secrets and are
redacted from debug logs (`src/config.rs`'s manual `Debug` impl never prints
them).

## Getting a Fastmail app password

1. Log in to Fastmail, go to **Settings → Privacy & Security → Integrations → App passwords**.
2. Create a new app password scoped to **Calendars (CalDAV)** only — don't
   grant it broader access than it needs.
3. Set `FASTMAIL_USERNAME` to your Fastmail login email and
   `FASTMAIL_APP_PASSWORD` to the generated password.

## Authentication modes

### `jwt`

Validates RS256 JWTs from one of two key sources — set exactly one:

- `AUTH_JWKS_URI` — any OIDC/OAuth issuer that publishes a JWKS endpoint
  (Authelia, Keycloak, Auth0, your own, etc.). Keys are fetched lazily and
  cached by `kid`, so key rotation on the issuer side is picked up
  automatically without a restart.
- `AUTH_JWT_PUBLIC_KEY` — a static RSA public key (inline PEM or a path to a
  PEM file) with no issuer involved at all. You mint long-lived tokens
  offline with the matching private key, which is never deployed to the
  server. See [Offline token minting](#offline-token-minting-jwt--static-public-key)
  below.

`exp` is always enforced, and so is `aud` — `AUTH_JWT_AUDIENCE` always
defaults to `RESOURCE_URI`, so there is no env-var combination that skips
the audience check. `iss` is only checked if `AUTH_JWT_ISSUER` is set.
`REQUIRED_SCOPE` defaults to `caldav` and is only skipped if explicitly set
to an empty string (`REQUIRED_SCOPE=""`) — so a minimal `AUTH_JWT_PUBLIC_KEY`
setup with no issuer configured still requires a correctly signed,
unexpired token whose `aud` matches `RESOURCE_URI` and whose `scope` claim
carries `caldav`, unless scope checking is explicitly disabled.

The server serves the PRM document at
`/.well-known/oauth-protected-resource` (unauthenticated), and a 401 on
`/mcp` carries a `WWW-Authenticate: Bearer resource_metadata="..."` header
pointing clients at it.

### `token`

A single shared secret, `MCP_TOKEN`, compared to the presented bearer token
in constant time (`subtle::ConstantTimeEq`). There is no PRM document — a
401 just returns a bare `WWW-Authenticate: Bearer` challenge. The client
sends:

```
Authorization: Bearer <MCP_TOKEN>
```

Trade-off: no expiry, no rotation, no revocation short of changing the
value and redeploying. Treat `MCP_TOKEN` like a password — generate it with
something like `openssl rand -base64 32`, store it in a secret manager, and
rotate it manually on any suspected exposure.

### `none`

No application-level authentication at all — `/mcp` is served open. Only
use this behind a platform edge that already gates access (e.g. a Scaleway
private container reachable only via an authenticating gateway, a
VPN-only network, or similar). Startup logs a loud warning when this mode
is selected. Keep the container/network private; this mode adds no
protection of its own.

## Offline token minting (`jwt` + static public key)

For `AUTH_JWT_PUBLIC_KEY`, there's no issuer to redirect to — you mint a
token yourself and hand it to the client directly.

1. Generate a keypair (private key never leaves your machine / secret store):

   ```bash
   openssl genrsa -out mcp_priv.pem 2048
   openssl rsa -in mcp_priv.pem -pubout -out mcp_pub.pem
   ```

2. Deploy only `mcp_pub.pem` to the server, as `AUTH_JWT_PUBLIC_KEY` (either
   the file path or the inline PEM text works).

3. Mint a long-lived token with the private key. Any RS256 JWT-signing tool
   works; for example with [`step`](https://smallstep.com/docs/step-cli/):

   ```bash
   step crypto jwt sign \
     --key mcp_priv.pem \
     --alg RS256 \
     --iss https://your-mcp-host.example.com \
     --aud https://your-mcp-host.example.com \
     --exp $(date -v+10y +%s) \
     --subtle \
     sub=mcp-client > token.jwt
   ```

   `aud` is always checked and defaults to `RESOURCE_URI`, so set it to
   match (or to your explicit `AUTH_JWT_AUDIENCE`, if you set one). Only set
   `iss` if you've configured `AUTH_JWT_ISSUER` to check it — an
   unconfigured issuer check is skipped, so an extra `iss` claim is
   harmless but unnecessary. Give the token a far-future `exp`; there's no
   refresh flow in this mode, so rotation means minting a new token.

4. Connect a client with the minted token as a static bearer header:

   ```bash
   claude mcp add --transport http caldav https://your-mcp-host.example.com/mcp \
     --header "Authorization: Bearer $(cat token.jwt)"
   ```

Rotation is: generate a new keypair, redeploy the new `mcp_pub.pem`, re-mint
tokens with the new private key, and redistribute them to clients. The old
public key stops working the moment it's replaced — there's no overlap
window, so coordinate the redeploy with token redistribution.

## Running

```bash
export AUTH_MODE=jwt
export BIND_ADDR=0.0.0.0:8080
export RESOURCE_URI=https://your-mcp-host.example.com
export AUTH_JWKS_URI=https://auth.example.com/jwks.json
export AUTH_JWT_ISSUER=https://auth.example.com
export REQUIRED_SCOPE=caldav
export FASTMAIL_USERNAME=you@fastmail.com
export FASTMAIL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx
cargo run --release
```

Smoke checks once it's up (jwt mode):

```bash
# Public PRM document — no auth required, returns JSON
curl -s https://your-mcp-host.example.com/.well-known/oauth-protected-resource

# Protected endpoint without a token — 401 with a WWW-Authenticate challenge
# pointing back at the PRM document
curl -si https://your-mcp-host.example.com/mcp
```

## Connecting a client

**`jwt` mode with `AUTH_JWKS_URI`** (a real OAuth/OIDC issuer): Claude Code
drives the OAuth 2.1 + PKCE flow itself once it sees the 401 challenge and
discovers the PRM document.

```bash
claude mcp add --transport http caldav https://your-mcp-host.example.com/mcp
```

**`jwt` mode with `AUTH_JWT_PUBLIC_KEY`, or `token` mode**: there's no
issuer to redirect to, so supply the token as a static header instead (see
[Offline token minting](#offline-token-minting-jwt--static-public-key) for
how to produce a jwt-mode token):

```bash
claude mcp add --transport http caldav https://your-mcp-host.example.com/mcp \
  --header "Authorization: Bearer <token-or-MCP_TOKEN>"
```

Custom-header auth on the Claude Code side is still a relatively new,
beta-status feature — if it misbehaves, check for a client update before
assuming the server is at fault.

**Claude Desktop — known limitation:** in `jwt`/`AUTH_JWKS_URI` mode the
server advertises no Dynamic Client Registration endpoint, and Claude
Desktop has historically required DCR to complete its OAuth flow
automatically, so the automatic connection flow may not complete there. The
fallback for a single-user setup is the same static-header approach as
above (obtain a token out-of-band and supply it directly, where Desktop's
client configuration allows a static bearer token). This is a known,
accepted trade-off for a single-user deployment, not a bug.

## Breaking change: `AUTHELIA_*` → generic `AUTH_*` / `RESOURCE_URI`

Earlier versions of this server were hardcoded to Authelia and used
Authelia-specific env var names. If you're upgrading from that config,
rename:

| Old | New |
|---|---|
| `AUTHELIA_ISSUER` | `AUTH_JWT_ISSUER` |
| `AUTHELIA_JWKS_URI` | `AUTH_JWKS_URI` |
| `RESOURCE_URI` | unchanged |
| `REQUIRED_SCOPE` | unchanged |

`AUTH_MODE` defaults to `jwt`, so an existing Authelia-backed deployment
keeps working once the two renamed variables are updated — no other
behavior changes.

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
- **`token` and `none` modes have no PRM document and no OAuth discovery.**
  This is by design (there's no authorization server to describe), but it
  means clients that hard-require PRM discovery before allowing a static
  header won't work in those modes.

**Deferred (not planned for this version):** CardDAV/contacts, iTIP/iMIP
scheduling (invites, RSVPs), a JSCalendar/JMAP-native path, and multi-user
support.

## Deployment

### Build

```bash
docker build -t mcp-caldav-fastmail .
```

`podman build -t mcp-caldav-fastmail .` works identically — the `Dockerfile`
has no Docker-specific features.

The runtime image is `gcr.io/distroless/cc-debian12` (~45MB): glibc + libgcc
+ CA certificates + tzdata, no shell or package manager. It's a native glibc
build rather than static-musl-on-`scratch` because `aws-lc-sys` (BoringSSL
C/asm, pulled in via rustls) doesn't cross-compile under `musl-gcc`. TLS
roots (`webpki-root-certs`) and timezone data (`chrono-tz`) are compiled
into the binary, so trust and TZID resolution don't depend on the image
filesystem either way.

### Run

```bash
docker run -p 8080:8080 \
  -e AUTH_MODE=... \
  -e FASTMAIL_USERNAME=... \
  -e FASTMAIL_APP_PASSWORD=... \
  # ... mode-specific vars, see Configuration above ...
  mcp-caldav-fastmail
```

`token` mode example:

```bash
docker run -p 8080:8080 \
  -e AUTH_MODE=token \
  -e MCP_TOKEN="$(openssl rand -base64 32)" \
  -e FASTMAIL_USERNAME=you@fastmail.com \
  -e FASTMAIL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx \
  mcp-caldav-fastmail
```

`none` mode example (only behind an authenticating edge — see
[`none`](#none) above):

```bash
docker run -p 8080:8080 \
  -e AUTH_MODE=none \
  -e FASTMAIL_USERNAME=you@fastmail.com \
  -e FASTMAIL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx \
  mcp-caldav-fastmail
```

See [Configuration](#configuration) for the full env var table — `jwt` mode
additionally needs `RESOURCE_URI` and either `AUTH_JWKS_URI` or
`AUTH_JWT_PUBLIC_KEY`.

### Pull from GHCR

```bash
docker pull ghcr.io/astromechza/mcp-caldav-fastmail:latest
```

Available tags: `latest` and `sha-<short>` (both from every push to `main`),
and semver tags (`vX.Y.Z`, `vX.Y`) from `v*` release tags.

Note: the first publish to GHCR creates a **private** package. Until a repo
maintainer makes it public and links it to this repository (once, in the
package's GHCR settings), anonymous `docker pull` will fail with
authentication errors.

### Health check

`GET /healthz` returns `200` unauthenticated in every `AUTH_MODE` — use it
as the container/orchestrator liveness probe.

### CI/CD

- `.github/workflows/ci.yml` — runs `cargo fmt --check`, `cargo clippy -D
  warnings`, and `cargo test` on every PR and on push to `main`.
- `.github/workflows/release.yml` — builds and pushes the image to
  `ghcr.io/astromechza/mcp-caldav-fastmail` on push to `main` (`latest` +
  `sha-<short>`) and on `v*` tags (semver).

### Scaleway

Intended deployment target is a private Scaleway Serverless Container,
reachable only through an IAM-gated edge that injects `X-Auth-Token` — pair
that with `AUTH_MODE=none` since the edge already authenticates, or run
`AUTH_MODE=token`/`AUTH_MODE=jwt` for defense in depth if the edge is
bypassable. Full Terraform for this (`scaleway_container` + IAM + secret
env) is a planned follow-up, not included yet.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

See `docs/superpowers/specs/2026-07-29-mcp-caldav-fastmail-design.md` for the
full design rationale.
