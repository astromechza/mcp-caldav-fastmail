# Pluggable Inbound Auth Modes — Design

**Date:** 2026-07-29
**Status:** Approved (pending spec review)
**Builds on:** the base server (branch `feat/implementation`, PR #1).

## 1. Purpose

Make the MCP server's **inbound** authentication pluggable so the same binary
works across deployments:

- **Home / OAuth**: validate JWTs from any OIDC/JWT issuer via JWKS.
- **Public container, no server secret**: validate JWTs against a static public
  key (token minted offline; private key never deployed).
- **Simple**: a static shared bearer token (constant-time compared).
- **Behind an authenticating edge** (e.g. Scaleway private container + IAM
  `X-Auth-Token`): no app-level auth at all — trust the platform gateway.

All references to a specific IdP (previously "Authelia") are removed; config is
generic.

Outbound Fastmail auth (app password) is unchanged and required in every mode.

Deployment artifacts (Dockerfile, Scaleway Terraform) are **out of scope** here —
a separate follow-up.

## 2. Auth modes

Selected by `AUTH_MODE` (default `jwt`, preserving current behavior):

| Mode | What it does | Load-bearing check |
|---|---|---|
| `jwt` | Verify RS256 (etc.) JWT via JWKS **or** static public key | signature + `exp` (+ `iss`/`aud` if configured) |
| `token` | Constant-time compare bearer against `MCP_TOKEN` | secret equality |
| `none` | No auth middleware layered; loud startup WARN | (platform edge) |

### 2.1 `jwt` mode key source (exactly one)
- `AUTH_JWKS_URI` — fetch + cache JWKS from an issuer (rotates automatically).
- `AUTH_JWT_PUBLIC_KEY` — a static PEM public key (inline value or a file path).
  Used with an offline-minted long-lived token; the private key never reaches
  the server.

It is a config error to set neither or both.

### 2.2 Claim validation (jwt mode)
- `exp` — **always enforced.**
- `iss` — enforced **iff** `AUTH_JWT_ISSUER` is set; otherwise skipped.
- `aud` — enforced **iff** `AUTH_JWT_AUDIENCE` is set (defaults to
  `RESOURCE_URI`); otherwise skipped.

Rationale: with a static public key, the signature already proves origin, so
`iss` is largely redundant and `aud` is optional hygiene — a minimal static
setup can run on signature + `exp` alone. With a shared JWKS issuer, `aud`
meaningfully prevents cross-resource token replay and should be set. Setting
`aud` is recommended in both cases.

## 3. Crate choice

Adopt **`jwt-authorizer`** (0.15.x) for `jwt` mode. It covers both key sources
and claim validation in one maintained crate:
- `JwtAuthorizer::from_jwks_url(uri)` — JWKS path.
- `JwtAuthorizer::from_rsa_pem_file(path)` / `from_rsa_pem(bytes)` — static PEM.
- `.validation(Validation::new().iss(&[..]).aud(&[..]))` — optional iss/aud,
  `exp`/`nbf` by default.
- built-in JWKS refresh.

**Verification gate (do first):** confirm `jwt-authorizer`'s built
`Authorizer` exposes a programmatic token-check method (e.g.
`Authorizer::check_auth(&self, token: &str) -> Result<TokenData<C>>`) usable
**outside** its axum layer. We need it so our single unified middleware can call
it for `jwt` mode and constant-time-compare for `token` mode.
- If present: adopt `jwt-authorizer`; **remove** `jsonwebtoken` (direct) + `jwks`
  + `JwtValidator` + `JwksKeySource` + `KeySource` from the codebase.
- If absent (layer-only): **fallback** — keep the existing `jsonwebtoken`-based
  `JwtValidator`, and add a ~10-line `StaticKeySource { key: DecodingKey }`
  (returns the configured PEM key for any `kid`) plus optional iss/aud handling.
  Do NOT adopt `jwt-authorizer` in that case.

Add `subtle` (constant-time comparison) for `token` mode. Keep `Claims` type if
still needed for the fallback; otherwise `jwt-authorizer` supplies claims.

## 4. Architecture changes

### 4.1 `Authenticator`
Replace `AuthState.validator: Arc<JwtValidator>` with:
```
enum Authenticator {
    Jwt(Arc<JwtAuthorizerWrapper>),   // holds the built Authorizer (jwt-authorizer)
    Token(Arc<SecretToken>),          // holds the MCP_TOKEN secret
}
```
(`none` mode constructs no `Authenticator` and layers no middleware.)

`AuthState` keeps the fields the PRM handler needs (`resource`, `issuer`,
`scope`, `prm_url`) plus the `Authenticator`.

### 4.2 Middleware `require_auth`
1. Extract `Authorization: Bearer <tok>` (own the string before `next.run`).
2. Dispatch on `Authenticator`:
   - `Jwt(a)` → `a.check_auth(tok).await` (Ok → proceed; Err → challenge).
   - `Token(s)` → `subtle` constant-time compare `tok` vs secret.
3. Missing/invalid → 401 challenge.

Challenge header by mode:
- `jwt`: `WWW-Authenticate: Bearer resource_metadata="<prm_url>"` (unchanged).
- `token`: `WWW-Authenticate: Bearer` (no resource_metadata — no OAuth AS).

### 4.3 Router assembly (`build_router`, per mode)
- `jwt`: public PRM route (`GET /.well-known/oauth-protected-resource`) +
  protected `/mcp` under `require_auth`.
- `token`: protected `/mcp` under `require_auth`; **no PRM route.**
- `none`: `/mcp` with **no** auth layer; **no PRM route**; emit a startup
  `tracing::warn!` that app auth is disabled.

`build_router` gains a regression test per mode (see §6).

## 5. Config changes (`src/config.rs`)

Generic names (all `AUTHELIA_*` removed):

| Env | Modes | Required? | Notes |
|---|---|---|---|
| `AUTH_MODE` | all | no (default `jwt`) | `jwt` \| `token` \| `none` |
| `BIND_ADDR` | all | no (`0.0.0.0:8080`) | |
| `RESOURCE_URI` | jwt | required in jwt | PRM `resource`; default for `aud` |
| `AUTH_JWKS_URI` | jwt | one-of | JWKS source |
| `AUTH_JWT_PUBLIC_KEY` | jwt | one-of | static PEM (inline or path) |
| `AUTH_JWT_ISSUER` | jwt | optional | enforce `iss` if set; PRM `authorization_servers` |
| `AUTH_JWT_AUDIENCE` | jwt | optional | enforce `aud` if set; defaults to `RESOURCE_URI` |
| `REQUIRED_SCOPE` | jwt | no (`caldav`) | scope membership (jwt only) |
| `MCP_TOKEN` | token | required in token | the shared bearer secret |
| `FASTMAIL_USERNAME` | all | **required** | |
| `FASTMAIL_APP_PASSWORD` | all | **required** | secret; redacted in Debug (already) |
| `CALDAV_BASE_URL` | all | no (fastmail default) | |

`Config` becomes mode-aware: auth fields modeled as `Option`/an enum, with
`from_lookup` branching on `AUTH_MODE` and validating only that mode's needs:
- `jwt`: `RESOURCE_URI` + exactly one of (`AUTH_JWKS_URI`, `AUTH_JWT_PUBLIC_KEY`)
  + Fastmail. `AUTH_JWT_ISSUER`/`AUTH_JWT_AUDIENCE`/`REQUIRED_SCOPE` optional.
- `token`: `MCP_TOKEN` (non-empty; warn if < 32 chars) + Fastmail.
- `none`: Fastmail only.
Unknown `AUTH_MODE` → config error listing valid values.

Suggested shape: a `AuthConfig` enum (`Jwt { source, issuer, audience, scope,
resource }` | `Token { secret }` | `None`) parsed once, so `main` matches on it
cleanly rather than juggling loose Options.

## 6. Testing

- **Config**: per-mode validation — jwt with neither/both key sources → error;
  jwt with jwks-only and pem-only → ok; token without `MCP_TOKEN` → error;
  none with only Fastmail → ok; unknown mode → error; `AUTH_JWT_AUDIENCE`
  defaulting to `RESOURCE_URI`.
- **token mode**: correct token → pass; wrong token → 401; comparison is
  constant-time (uses `subtle`, asserted structurally/by review — not timing).
- **jwt static-pem mode**: reuse a throwaway RSA keypair (already in
  `src/auth/testdata/`); mint a token in-test; assert valid passes, expired
  fails, wrong-key/signature fails, and — with `AUTH_JWT_AUDIENCE` set — wrong
  aud fails while unset-aud skips the check.
- **router gating per mode** (extend the existing `build_router` test): jwt →
  `/mcp` 401 + PRM public 200; token → `/mcp` 401, PRM route absent (404);
  none → `/mcp` reaches the handler without auth, PRM absent.
- Existing CalDAV/iCal/tool tests unaffected.

Testability: the `Authenticator` is injectable into `build_router` exactly as
today; jwt mode is tested via a static PEM (no network) — no live JWKS needed.

## 7. Token minting (docs)

For `jwt` static-pubkey mode, document an offline mint so producing the token
isn't fiddly. README §Auth gains:
- Generate a keypair (`openssl genrsa` / `openssl rsa -pubout`), deploy only the
  public key as `AUTH_JWT_PUBLIC_KEY`.
- Mint a long-lived JWT with the private key (a documented `step crypto jwt sign`
  or equivalent one-liner; claims: `iss`/`aud` if you enforce them, a far-future
  `exp`), paste it into the client via
  `claude mcp add --transport http caldav <url> --header "Authorization: Bearer <jwt>"`.
- Rotation = new keypair + redeploy public key + re-mint.

## 8. README updates

- Remove all Authelia references; describe generic OIDC/JWT issuer.
- New "Auth modes" section documenting `jwt` (JWKS or static PEM) / `token` /
  `none`, the env matrix (§5), the minting flow (§7), and the honest tradeoffs
  (token has no expiry/rotation; none trusts the edge and must stay private).
- Note the breaking env rename (`AUTHELIA_* → AUTH_*`) for anyone on the old
  config.

## 9. Out of scope / deferred

- Dockerfile + Scaleway Terraform + deploy docs (separate PR).
- `X-Auth-Token` handling in-app (that's the Scaleway edge's concern; app uses
  `Authorization: Bearer`).
- HMAC/`from_secret` JWTs, multiple issuers, JWT `kid` denylist/revocation,
  JWKS negative-caching (still deferred from the base build).
