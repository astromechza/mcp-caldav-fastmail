# Pluggable Auth Modes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make inbound auth pluggable via `AUTH_MODE` = `jwt` | `token` | `none`, with generic (non-Authelia) config, so the same binary runs behind an OIDC issuer, with an offline-minted static-key token, with a simple shared bearer, or behind an authenticating edge.

**Architecture:** A mode-aware `AuthConfig` parsed from env; an `Authenticator` enum (`Jwt` via the `jwt-authorizer` crate, `Token` via constant-time compare) consumed by the existing `require_auth` middleware; `build_router` branches per mode (PRM route only in `jwt`). `none` layers no auth.

**Tech Stack:** existing (axum 0.8, rmcp 0.9, reqwest 0.13, calcard) + `jwt-authorizer` (jwt) + `subtle` (token). Removes `jsonwebtoken`(direct) + `jwks` + `JwtValidator`/`JwksKeySource` **iff** the crate check in Task 0 passes.

**Reference spec:** `docs/superpowers/specs/2026-07-29-pluggable-auth-modes-design.md`.

**Branch:** `feat/auth-modes`, stacked on `feat/implementation` (PR #1 open).

**Volatile API:** `jwt-authorizer` 0.15.x — verify every call against `cargo doc`/registry source; Task 0 gates whether we adopt it at all.

---

## File Structure

```
Cargo.toml               + jwt-authorizer, + subtle; - jwks (if adopted)
src/config.rs            AuthConfig enum + mode-aware parsing (rewrite)
src/auth/authn.rs        NEW: Authenticator enum (Jwt | Token) + verify
src/auth/validator.rs    DELETE if jwt-authorizer adopted; else keep + add StaticKeySource
src/auth/metadata.rs     AuthState uses Authenticator; require_auth dispatches; build_router per-mode; challenge per-mode
src/auth/mod.rs          re-exports
src/main.rs              build Authenticator/AuthConfig, branch router per mode
README.md                generic auth section + minting doc (Task 5)
```

---

## Task 0: Crate verification + dependencies

**Files:** `Cargo.toml`

- [ ] **Step 1: Inspect `jwt-authorizer` 0.15.x real API from source**

Run: `cargo add jwt-authorizer --dry-run` to see the resolved version, then locate source: `find ~/.cargo/registry/src -maxdepth 2 -type d -name 'jwt-authorizer-*'` (add the dep first if not downloaded). Read its `src/` and docs. Determine and WRITE DOWN in your report:
- The builder methods: `JwtAuthorizer::from_jwks_url(&str)`, `from_rsa_pem(...)` / `from_rsa_pem_file(&str)` — does an INLINE PEM string constructor exist, or only file? (We need inline via `AUTH_JWT_PUBLIC_KEY` possibly holding PEM text OR a path — see Task 2.)
- How the authorizer is finalized: is it `.build().await -> Result<Authorizer<C>, _>`? Is `C` (claims) a generic needing a concrete `DeserializeOwned` type? Can `C = serde_json::Value`?
- **CRITICAL:** does the built `Authorizer` expose a programmatic check, e.g. `Authorizer::check_auth(&self, token: &str) -> Result<TokenData<C>, AuthError>` (async or sync?), usable WITHOUT the axum layer? Paste the exact signature.
- `Validation` builder: how to set `iss`/`aud` (`.iss(&[String])`, `.aud(&[String])`?) and how to OMIT them (don't call the setter). Confirm `exp` is validated by default.
- The error type returned on invalid token.

- [ ] **Step 2: Decision — adopt or fallback**

- **If `check_auth` (programmatic, non-layer) EXISTS:** adopt. Proceed with `jwt-authorizer`. Later tasks DELETE `jsonwebtoken`(direct dep)/`jwks`/`JwtValidator`/`JwksKeySource`.
- **If it does NOT exist (layer/extractor only):** FALLBACK. Do NOT add `jwt-authorizer`. Keep `jsonwebtoken` + `jwks`, and Task 2 instead adds a `StaticKeySource { key: DecodingKey }` to the existing `JwtValidator` and makes iss/aud optional there. Record this decision prominently — it changes Tasks 2/README.

Record the decision in your report; it governs the rest of the plan.

- [ ] **Step 3: Edit `Cargo.toml` deps**

If ADOPT:
```toml
jwt-authorizer = "0.15"
subtle = "2"
```
and remove `jwks` from `[dependencies]` (leave `jsonwebtoken` for now only if still referenced; Task 2 removes direct use — then drop it if `cargo build` shows it unused, but keep if `jwt-authorizer` doesn't re-export what tests need).
If FALLBACK: add only `subtle = "2"`; keep `jsonwebtoken` + `jwks`.

- [ ] **Step 4: Build**

Run: `cargo build`
Expected: compiles (existing code still uses `JwtValidator` until Task 2; that's fine). Record resolved `jwt-authorizer` + `subtle` versions.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add jwt-authorizer + subtle for pluggable auth"
```

Report: the ADOPT/FALLBACK decision, the exact `check_auth`/builder/`Validation` signatures found, resolved versions.

---

## Task 1: Config → mode-aware `AuthConfig`

**Files:** `src/config.rs` (rewrite), tests inline.

- [ ] **Step 1: Write the failing tests first**

Replace `src/config.rs` tests with:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn look(m: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<_, _> = m.iter().cloned().collect();
        move |k: &str| map.get(k).map(|s| s.to_string())
    }

    const FASTMAIL: [(&str, &str); 2] = [
        ("FASTMAIL_USERNAME", "me@fastmail.com"),
        ("FASTMAIL_APP_PASSWORD", "secret"),
    ];

    #[test]
    fn jwt_mode_with_jwks_ok() {
        let mut v = FASTMAIL.to_vec();
        v.extend([("RESOURCE_URI", "https://mcp.x"), ("AUTH_JWKS_URI", "https://i/jwks")]);
        let cfg = Config::from_lookup(look(v.leak())).unwrap();
        assert!(matches!(cfg.auth, AuthConfig::Jwt { .. }));
    }

    #[test]
    fn jwt_mode_with_pem_ok() {
        let mut v = FASTMAIL.to_vec();
        v.extend([("RESOURCE_URI", "https://mcp.x"), ("AUTH_JWT_PUBLIC_KEY", "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----")]);
        let cfg = Config::from_lookup(look(v.leak())).unwrap();
        assert!(matches!(cfg.auth, AuthConfig::Jwt { .. }));
    }

    #[test]
    fn jwt_mode_needs_exactly_one_key_source() {
        // neither
        let mut v = FASTMAIL.to_vec();
        v.extend([("RESOURCE_URI", "https://mcp.x")]);
        assert!(Config::from_lookup(look(v.leak())).is_err());
        // both
        let mut v2 = FASTMAIL.to_vec();
        v2.extend([("RESOURCE_URI", "https://mcp.x"), ("AUTH_JWKS_URI", "u"), ("AUTH_JWT_PUBLIC_KEY", "k")]);
        assert!(Config::from_lookup(look(v2.leak())).is_err());
    }

    #[test]
    fn token_mode_requires_secret() {
        let mut ok = FASTMAIL.to_vec();
        ok.extend([("AUTH_MODE", "token"), ("MCP_TOKEN", "abcdefghijklmnopqrstuvwxyz012345")]);
        assert!(matches!(Config::from_lookup(look(ok.leak())).unwrap().auth, AuthConfig::Token { .. }));

        let mut bad = FASTMAIL.to_vec();
        bad.extend([("AUTH_MODE", "token")]);
        assert!(Config::from_lookup(look(bad.leak())).is_err());
    }

    #[test]
    fn none_mode_needs_only_fastmail() {
        let mut v = FASTMAIL.to_vec();
        v.extend([("AUTH_MODE", "none")]);
        assert!(matches!(Config::from_lookup(look(v.leak())).unwrap().auth, AuthConfig::None));
    }

    #[test]
    fn unknown_mode_errors() {
        let mut v = FASTMAIL.to_vec();
        v.extend([("AUTH_MODE", "bogus")]);
        assert!(Config::from_lookup(look(v.leak())).is_err());
    }

    #[test]
    fn audience_defaults_to_resource_uri() {
        let mut v = FASTMAIL.to_vec();
        v.extend([("RESOURCE_URI", "https://mcp.x"), ("AUTH_JWKS_URI", "u")]);
        let cfg = Config::from_lookup(look(v.leak())).unwrap();
        if let AuthConfig::Jwt { audience, .. } = cfg.auth {
            assert_eq!(audience.as_deref(), Some("https://mcp.x"));
        } else { panic!("expected jwt") }
    }

    #[test]
    fn missing_fastmail_errors_all_modes() {
        assert!(Config::from_lookup(look(&[("AUTH_MODE", "none")])).is_err());
    }
}
```
(`.leak()` on the Vec is a test-only convenience to get `'static` slices; acceptable in tests.)

- [ ] **Step 2: Implement `Config` + `AuthConfig`**

Replace the top of `src/config.rs`:
```rust
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub enum JwtKeySource {
    Jwks(String),
    /// PEM public key — inline PEM text OR a filesystem path (resolved in main/auth).
    PublicKeyPem(String),
}

#[derive(Debug, Clone)]
pub enum AuthConfig {
    Jwt {
        resource: String,
        source: JwtKeySource,
        issuer: Option<String>,
        audience: Option<String>,
        required_scope: Option<String>,
    },
    Token { secret: String },
    None,
}

#[derive(Clone)]
pub struct Config {
    pub bind_addr: String,
    pub auth: AuthConfig,
    pub fastmail_username: String,
    pub fastmail_app_password: String,
    pub caldav_base_url: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("auth", &self.auth) // AuthConfig::Token secret: see note
            .field("fastmail_username", &self.fastmail_username)
            .field("fastmail_app_password", &"[redacted]")
            .field("caldav_base_url", &self.caldav_base_url)
            .finish()
    }
}

impl Config {
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let bind_addr = get("BIND_ADDR").unwrap_or_else(|| "0.0.0.0:8080".into());
        let fastmail_username = get("FASTMAIL_USERNAME")
            .ok_or_else(|| Error::Config("missing env FASTMAIL_USERNAME".into()))?;
        let fastmail_app_password = get("FASTMAIL_APP_PASSWORD")
            .ok_or_else(|| Error::Config("missing env FASTMAIL_APP_PASSWORD".into()))?;
        let caldav_base_url = get("CALDAV_BASE_URL")
            .unwrap_or_else(|| "https://caldav.fastmail.com/".into());

        let mode = get("AUTH_MODE").unwrap_or_else(|| "jwt".into());
        let auth = match mode.as_str() {
            "jwt" => {
                let resource = get("RESOURCE_URI")
                    .ok_or_else(|| Error::Config("jwt mode: missing RESOURCE_URI".into()))?;
                let jwks = get("AUTH_JWKS_URI");
                let pem = get("AUTH_JWT_PUBLIC_KEY");
                let source = match (jwks, pem) {
                    (Some(u), None) => JwtKeySource::Jwks(u),
                    (None, Some(k)) => JwtKeySource::PublicKeyPem(k),
                    (None, None) => return Err(Error::Config(
                        "jwt mode: set exactly one of AUTH_JWKS_URI or AUTH_JWT_PUBLIC_KEY".into())),
                    (Some(_), Some(_)) => return Err(Error::Config(
                        "jwt mode: set only ONE of AUTH_JWKS_URI or AUTH_JWT_PUBLIC_KEY".into())),
                };
                AuthConfig::Jwt {
                    audience: get("AUTH_JWT_AUDIENCE").or_else(|| Some(resource.clone())),
                    resource,
                    source,
                    issuer: get("AUTH_JWT_ISSUER"),
                    required_scope: get("REQUIRED_SCOPE"),
                }
            }
            "token" => {
                let secret = get("MCP_TOKEN")
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| Error::Config("token mode: missing MCP_TOKEN".into()))?;
                if secret.len() < 32 {
                    tracing::warn!("MCP_TOKEN is short (<32 chars); use a long random secret");
                }
                AuthConfig::Token { secret }
            }
            "none" => AuthConfig::None,
            other => return Err(Error::Config(format!(
                "unknown AUTH_MODE '{other}' (expected jwt|token|none)"))),
        };

        Ok(Config { bind_addr, auth, fastmail_username, fastmail_app_password, caldav_base_url })
    }

    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }
}
```
Note: `AuthConfig` derives `Debug`; its `Token { secret }` would print the secret via `Config`'s `auth` field. To avoid leaking it, give `AuthConfig` a manual `Debug` too (redact `Token.secret`), OR in `Config::Debug` print a mode tag instead of the whole `auth`. Implement a manual `Debug for AuthConfig` that renders `Token { secret: "[redacted]" }`. Add a test `config_debug_redacts_token_secret`.

- [ ] **Step 3: Run tests**

Run: `cargo test config::`
Expected: all pass (incl. the redaction test you add).

- [ ] **Step 4: Commit**

```bash
git add src/config.rs
git commit -m "feat: mode-aware AuthConfig (jwt/token/none), generic env names"
```

---

## Task 2: `Authenticator` + auth verification

**Files:** `src/auth/authn.rs` (new), `src/auth/mod.rs`, and (ADOPT) delete `src/auth/validator.rs` / (FALLBACK) extend it. Tests inline.

**This task has two variants — follow the Task 0 decision.**

### VARIANT ADOPT (jwt-authorizer)

- [ ] **Step 1: Write `Authenticator` with failing tests**

Create `src/auth/authn.rs`:
```rust
use crate::config::{AuthConfig, JwtKeySource};
use crate::error::{Error, Result};
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// Runtime authenticator selected by AuthConfig. `None` mode builds no Authenticator.
#[derive(Clone)]
pub enum Authenticator {
    Jwt(Arc<JwtChecker>),
    Token(Arc<TokenChecker>),
}

pub struct TokenChecker { secret: Vec<u8> }
impl TokenChecker {
    pub fn new(secret: String) -> Self { Self { secret: secret.into_bytes() } }
    /// Constant-time comparison of the presented bearer against the secret.
    pub fn check(&self, presented: &str) -> bool {
        // Lengths may differ; ct_eq requires equal length. Compare a fixed-size
        // digest to avoid length leak? For simplicity: reject on length mismatch
        // (length is not secret-sensitive here) then ct-compare bytes.
        let p = presented.as_bytes();
        if p.len() != self.secret.len() { return false; }
        p.ct_eq(&self.secret).into()
    }
}

/// Wraps jwt-authorizer's built Authorizer. Claims kept as JSON for scope check.
pub struct JwtChecker {
    authorizer: jwt_authorizer::Authorizer<serde_json::Value>, // VERIFY generic + type path
    required_scope: Option<String>,
}
impl JwtChecker {
    /// Verify a token; Ok(()) if valid (+ scope if required).
    pub async fn check(&self, token: &str) -> Result<()> {
        // VERIFY: exact method name/signature from Task 0 (check_auth async?).
        let data = self.authorizer.check_auth(token).await
            .map_err(|e| Error::Auth(format!("jwt: {e:?}")))?;
        if let Some(scope) = &self.required_scope {
            let claims = &data.claims; // serde_json::Value
            let ok = claims.get("scope").and_then(|s| s.as_str())
                .map(|s| s.split_whitespace().any(|x| x == scope))
                .unwrap_or(false);
            if !ok { return Err(Error::Auth(format!("missing scope {scope}"))); }
        }
        Ok(())
    }
}

impl Authenticator {
    /// Build from AuthConfig. Returns None for AuthConfig::None.
    pub async fn from_config(auth: &AuthConfig) -> Result<Option<Authenticator>> {
        match auth {
            AuthConfig::None => Ok(None),
            AuthConfig::Token { secret } =>
                Ok(Some(Authenticator::Token(Arc::new(TokenChecker::new(secret.clone()))))),
            AuthConfig::Jwt { source, issuer, audience, required_scope, .. } => {
                use jwt_authorizer::{JwtAuthorizer, Validation};
                // VERIFY all of this against Task 0 findings.
                let mut val = Validation::new();
                if let Some(i) = issuer { val = val.iss(&[i.clone()]); }
                if let Some(a) = audience { val = val.aud(&[a.clone()]); }
                let builder = match source {
                    JwtKeySource::Jwks(uri) => JwtAuthorizer::<serde_json::Value>::from_jwks_url(uri),
                    JwtKeySource::PublicKeyPem(pem_or_path) => {
                        // Support inline PEM OR path: if it looks like PEM, write to
                        // a temp? Prefer an inline constructor if it exists
                        // (from_rsa_pem(bytes)). If only from_rsa_pem_file exists,
                        // and the value is inline PEM, load via from_rsa_pem on bytes.
                        // Decide in Task 0; implement whichever the crate supports.
                        JwtAuthorizer::<serde_json::Value>::from_rsa_pem_file(pem_or_path) // ADJUST
                    }
                };
                let authorizer = builder.validation(val).build().await
                    .map_err(|e| Error::Auth(format!("build authorizer: {e:?}")))?;
                Ok(Some(Authenticator::Jwt(Arc::new(JwtChecker { authorizer, required_scope: required_scope.clone() }))))
            }
        }
    }

    /// Verify a presented bearer token string.
    pub async fn verify(&self, token: &str) -> bool {
        match self {
            Authenticator::Token(t) => t.check(token),
            Authenticator::Jwt(j) => j.check(token).await.is_ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_checker_exact_match() {
        let t = TokenChecker::new("correct-horse-battery-staple-000000".into());
        assert!(t.check("correct-horse-battery-staple-000000"));
        assert!(!t.check("wrong"));
        assert!(!t.check("correct-horse-battery-staple-000001"));
    }

    #[tokio::test]
    async fn from_config_none_is_none() {
        assert!(Authenticator::from_config(&AuthConfig::None).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn token_authenticator_verifies() {
        let a = Authenticator::from_config(&AuthConfig::Token { secret: "s3cr3t-token-32-chars-min-abcdef".into() })
            .await.unwrap().unwrap();
        assert!(a.verify("s3cr3t-token-32-chars-min-abcdef").await);
        assert!(!a.verify("nope").await);
    }

    // JWT static-PEM test: mint a token with the throwaway private key in
    // src/auth/testdata/test_priv.pem, build a JwtChecker from test_pub.pem,
    // assert valid passes, expired fails, wrong-key fails, and (aud set) wrong-aud fails.
    // Implement using jwt-authorizer's from_rsa_pem(_file) + a jsonwebtoken::encode
    // in the test (jsonwebtoken is a fine dev-only dep for signing test tokens;
    // add it under [dev-dependencies] if it was removed from [dependencies]).
    #[tokio::test]
    async fn jwt_static_pem_valid_and_invalid() {
        use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
        let priv_pem = include_str!("testdata/test_priv.pem");
        let mint = |aud: &str, exp: usize| {
            let mut h = Header::new(Algorithm::RS256);
            h.kid = Some("test".into());
            let claims = serde_json::json!({"sub":"u","iss":"https://issuer.x","aud":aud,"exp":exp,"scope":"caldav"});
            encode(&h, &claims, &EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap()).unwrap()
        };
        let cfg = AuthConfig::Jwt {
            resource: "https://mcp.x".into(),
            source: JwtKeySource::PublicKeyPem("src/auth/testdata/test_pub.pem".into()),
            issuer: Some("https://issuer.x".into()),
            audience: Some("https://mcp.x".into()),
            required_scope: Some("caldav".into()),
        };
        let a = Authenticator::from_config(&cfg).await.unwrap().unwrap();
        assert!(a.verify(&mint("https://mcp.x", 9_999_999_999)).await);   // valid
        assert!(!a.verify(&mint("https://mcp.x", 1)).await);              // expired
        assert!(!a.verify(&mint("https://other.x", 9_999_999_999)).await); // wrong aud
    }
}
```
Adjust every `jwt_authorizer::*` call to the REAL API from Task 0. The `from_rsa_pem_file` path assumes the PEM value is a file path; if we must also accept inline PEM, handle both (detect `-----BEGIN` prefix → inline via `from_rsa_pem(bytes)`; else treat as path). The test uses a file path pointing at the committed test pubkey.

- [ ] **Step 2: Delete the old validator (ADOPT only)**

Remove `src/auth/validator.rs`. Update `src/auth/mod.rs`:
```rust
pub mod authn;
pub mod metadata;
pub use authn::Authenticator;
pub use metadata::{AuthState, ProtectedResourceMetadata, build_router};
```
Remove `jsonwebtoken`/`jwks` from `[dependencies]` if now unused (keep `jsonwebtoken` under `[dev-dependencies]` for the test signer). Run `cargo build` and fix fallout (main.rs still references old types until Task 4 — if it breaks the build now, that's expected; Task 4 fixes main. To keep each task building, you may temporarily stub main; but PREFER doing Task 2+3+4 so the crate builds by end of Task 4. If intermediate build breakage is unavoidable, note it and ensure `cargo build` is green by end of Task 4).

- [ ] **Step 3: Run the auth tests**

Run: `cargo test auth::authn`
Expected: token tests pass; jwt static-pem test passes (valid/expired/wrong-aud).

- [ ] **Step 4: Commit**

```bash
git add src/auth/ Cargo.toml Cargo.lock
git commit -m "feat: Authenticator (jwt-authorizer + constant-time token), drop hand-rolled validator"
```

### VARIANT FALLBACK (keep jsonwebtoken)
If Task 0 chose fallback: instead of the above, add `StaticKeySource { key: DecodingKey }` to `validator.rs` implementing `KeySource` (returns the PEM-loaded key for any kid), make `JwtValidator` treat issuer/audience as `Option` (only `set_issuer`/`set_audience` when present), and build the `Authenticator::Jwt` around `JwtValidator`. Keep the same `Authenticator`/`TokenChecker` and the same tests (they don't care which impl backs jwt). Commit with an analogous message.

---

## Task 3: Metadata, middleware dispatch, per-mode router

**Files:** `src/auth/metadata.rs`

- [ ] **Step 1: Update `AuthState` + `require_auth` + add `build_router`**

Edit `src/auth/metadata.rs`. `AuthState` now carries an `Authenticator` and only the PRM fields:
```rust
use crate::auth::authn::Authenticator;
use axum::{
    extract::{Request, State},
    http::{header::{AUTHORIZATION, WWW_AUTHENTICATE}, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};

#[derive(Clone)]
pub struct AuthState {
    pub authenticator: Authenticator,
    /// PRM fields (jwt mode only).
    pub prm_url: String,
    pub resource: String,
    pub issuer: Option<String>,
    pub scope: Option<String>,
    /// true in jwt mode (challenge points at PRM); false in token mode (plain Bearer).
    pub jwt_mode: bool,
}

pub async fn prm_handler(State(st): State<AuthState>) -> Json<ProtectedResourceMetadata> {
    Json(ProtectedResourceMetadata::new(
        st.resource.clone(),
        st.issuer.clone().unwrap_or_default(),
        st.scope.clone().unwrap_or_else(|| "caldav".into()),
    ))
}

pub async fn require_auth(State(st): State<AuthState>, req: Request, next: Next) -> Response {
    let token = req.headers().get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    match token {
        Some(t) if st.authenticator.verify(&t).await => next.run(req).await,
        _ => challenge(&st),
    }
}

fn challenge(st: &AuthState) -> Response {
    let header = if st.jwt_mode {
        www_authenticate(&st.prm_url)
    } else {
        "Bearer".to_string()
    };
    (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, header)]).into_response()
}
```

Add `build_router` that branches per mode. It takes the protected router (carrying the nested `/mcp` service) and an `Option<AuthState>` (None = `none` mode):
```rust
/// Compose the app router.
/// - `auth = Some(state)` with `jwt_mode=true`  → PRM public + /mcp gated.
/// - `auth = Some(state)` with `jwt_mode=false` → /mcp gated, no PRM.
/// - `auth = None` (none mode)                  → /mcp open, no PRM.
pub fn build_router(protected: Router<()>, auth: Option<AuthState>) -> Router {
    match auth {
        None => protected, // none mode: no layer, no PRM
        Some(state) => {
            let gated = protected.layer(from_fn_with_state(state.clone(), require_auth));
            if state.jwt_mode {
                Router::new()
                    .route("/.well-known/oauth-protected-resource", get(prm_handler))
                    .merge(gated)
                    .with_state(state)
            } else {
                gated.with_state(state)
            }
        }
    }
}
```
Note the state-type plumbing: the `/mcp` nested service is state-agnostic (`Router<()>` after `nest_service`), and `with_state(state)` finalizes to `Router<()>`≡`Router`. Adjust generics to what compiles in axum 0.8 (you may need `Router<AuthState>` intermediates as in the base build's existing `build_router`; reconcile with the compiler). Keep `ProtectedResourceMetadata`/`www_authenticate` and their 2 unit tests unchanged.

- [ ] **Step 2: Per-mode router tests**

Add:
```rust
#[cfg(test)]
mod build_router_tests {
    use super::*;
    use crate::auth::authn::Authenticator;
    use crate::config::AuthConfig;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    async fn state(jwt_mode: bool, auth: Authenticator) -> AuthState {
        AuthState { authenticator: auth, prm_url: "https://mcp.x/.well-known/oauth-protected-resource".into(),
            resource: "https://mcp.x".into(), issuer: Some("https://i".into()), scope: Some("caldav".into()), jwt_mode }
    }
    fn dummy() -> Router<()> { Router::new().route("/mcp", get(|| async { "ok" })) }

    #[tokio::test]
    async fn token_mode_gates_mcp_and_has_no_prm() {
        let a = Authenticator::from_config(&AuthConfig::Token { secret: "x".repeat(32) }).await.unwrap().unwrap();
        let app = build_router(dummy(), Some(state(false, a).await));
        let r = app.clone().oneshot(HttpRequest::get("/mcp").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let prm = app.oneshot(HttpRequest::get("/.well-known/oauth-protected-resource").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(prm.status(), StatusCode::NOT_FOUND); // no PRM in token mode
    }

    #[tokio::test]
    async fn none_mode_is_open() {
        let app = build_router(dummy(), None);
        let r = app.oneshot(HttpRequest::get("/mcp").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jwt_mode_gates_mcp_and_serves_prm() {
        // Use a token authenticator as a stand-in verifier (jwt_mode flag drives routing/challenge,
        // not the authenticator kind); we only assert routing + challenge shape here.
        let a = Authenticator::from_config(&AuthConfig::Token { secret: "x".repeat(32) }).await.unwrap().unwrap();
        let app = build_router(dummy(), Some(state(true, a).await));
        let r = app.clone().oneshot(HttpRequest::get("/mcp").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert!(r.headers().get(WWW_AUTHENTICATE).unwrap().to_str().unwrap().contains("resource_metadata"));
        let prm = app.oneshot(HttpRequest::get("/.well-known/oauth-protected-resource").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(prm.status(), StatusCode::OK);
    }
}
```

- [ ] **Step 3: Run**

Run: `cargo test auth::metadata`
Expected: PRM/www_authenticate unit tests + the 3 build_router mode tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/auth/metadata.rs
git commit -m "feat: per-mode router + auth dispatch + mode-specific challenge"
```

---

## Task 4: Wire `main.rs` per mode

**Files:** `src/main.rs`

- [ ] **Step 1: Rewrite main to build AuthConfig → Authenticator → router**

```rust
use std::sync::Arc;
use mcp_caldav_fastmail::auth::{Authenticator, AuthState, build_router};
use mcp_caldav_fastmail::caldav::FastmailCalDav;
use mcp_caldav_fastmail::config::{AuthConfig, Config};
use mcp_caldav_fastmail::mcp::CalendarServer;
use axum::Router;
use rmcp::transport::streamable_http_server::{session::local::LocalSessionManager, StreamableHttpService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let cfg = Config::from_env()?;

    let caldav = Arc::new(FastmailCalDav::new(&cfg.caldav_base_url, &cfg.fastmail_username, &cfg.fastmail_app_password)?);
    let caldav_for_mcp = caldav.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(CalendarServer::new(caldav_for_mcp.clone())),
        Arc::new(LocalSessionManager::default()),
        Default::default(),
    );
    let protected: Router<()> = Router::new().nest_service("/mcp", mcp_service);

    let authenticator = Authenticator::from_config(&cfg.auth).await?;
    let auth_state = match (&cfg.auth, authenticator) {
        (AuthConfig::None, _) => {
            tracing::warn!("AUTH_MODE=none: application auth is DISABLED. Ensure the platform edge gates access to /mcp.");
            None
        }
        (AuthConfig::Jwt { resource, issuer, required_scope, .. }, Some(a)) => Some(AuthState {
            authenticator: a,
            prm_url: format!("{}/.well-known/oauth-protected-resource", resource.trim_end_matches('/')),
            resource: resource.clone(),
            issuer: issuer.clone(),
            scope: required_scope.clone(),
            jwt_mode: true,
        }),
        (AuthConfig::Token { .. }, Some(a)) => Some(AuthState {
            authenticator: a,
            prm_url: String::new(),
            resource: String::new(),
            issuer: None,
            scope: None,
            jwt_mode: false,
        }),
        _ => unreachable!("authenticator presence matches auth mode"),
    };

    let app = build_router(protected, auth_state);
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("listening on {} (mode: {})", cfg.bind_addr, match &cfg.auth {
        AuthConfig::Jwt { .. } => "jwt", AuthConfig::Token { .. } => "token", AuthConfig::None => "none" });
    axum::serve(listener, app).await?;
    Ok(())
}
```
Reconcile `Router<()>` generics with `build_router`'s signature from Task 3 (must match).

- [ ] **Step 2: Build + clippy**

Run: `cargo build && cargo clippy --all-targets -- -D warnings`
Expected: clean. Fix any leftover references to deleted `JwtValidator`/`JwksKeySource`.

- [ ] **Step 3: Smoke all three modes**

```bash
# jwt (static pem)
RESOURCE_URI=https://mcp.local AUTH_JWT_PUBLIC_KEY=src/auth/testdata/test_pub.pem AUTH_JWT_ISSUER=https://issuer.x \
FASTMAIL_USERNAME=x FASTMAIL_APP_PASSWORD=y BIND_ADDR=127.0.0.1:8101 cargo run & P=$!; sleep 3
echo "jwt /mcp:"; curl -s -i http://127.0.0.1:8101/mcp | grep -iE "^HTTP|www-authenticate"
echo "jwt PRM:"; curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8101/.well-known/oauth-protected-resource
kill $P 2>/dev/null

# token
AUTH_MODE=token MCP_TOKEN=$(printf 'a%.0s' {1..40}) FASTMAIL_USERNAME=x FASTMAIL_APP_PASSWORD=y BIND_ADDR=127.0.0.1:8102 cargo run & P=$!; sleep 3
echo "token /mcp no auth:"; curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8102/mcp
echo "token PRM absent:"; curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8102/.well-known/oauth-protected-resource
kill $P 2>/dev/null

# none
AUTH_MODE=none FASTMAIL_USERNAME=x FASTMAIL_APP_PASSWORD=y BIND_ADDR=127.0.0.1:8103 cargo run & P=$!; sleep 3
echo "none /mcp (open, expect not 401):"; curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8103/mcp
kill $P 2>/dev/null
```
Expected: jwt `/mcp` → 401 + resource_metadata challenge, PRM → 200. token `/mcp` → 401, PRM → 404. none `/mcp` → not 401 (200/400/406 from rmcp, but NOT auth-rejected). Paste results.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat: wire per-mode auth into main"
```

---

## Task 5: README + final verification

**Files:** `README.md`

- [ ] **Step 1: Rewrite auth section**

Update `README.md`: remove ALL Authelia mentions; add an "Authentication modes" section documenting `jwt` (JWKS or static PEM), `token`, `none`; the env matrix from spec §5; the offline token-minting flow (keygen + sign + `--header`); and honest tradeoffs (token = no expiry/rotation; none = trusts edge, keep container private). Note the breaking `AUTHELIA_* → AUTH_*` rename. Verify tool list + env names against the code.

- [ ] **Step 2: Full verification**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```
All clean; paste `cargo test` count. Fix anything failing.

- [ ] **Step 3: Commit**

```bash
git add README.md src/
git commit -m "docs: auth modes + minting; final fmt/lint pass"
```

---

## Self-Review (against spec)

- §2 modes (jwt/token/none): Tasks 1–4. ✓
- §2.1 key source xor: Task 1 config validation. ✓
- §2.2 exp always / iss,aud optional: Task 2 (Validation conditional). ✓
- §3 crate + verification gate + fallback: Task 0 + Task 2 variants. ✓
- §4 Authenticator/middleware/router: Tasks 2–4. ✓
- §5 generic config matrix + Debug redaction: Task 1. ✓
- §6 tests (config, token, jwt-pem, router per mode): Tasks 1–3. ✓
- §7 minting doc: Task 5. ✓
- §8 README generic + rename note: Task 5. ✓
- §9 out of scope (Docker/TF): not in plan. ✓

**Type consistency:** `Authenticator`/`AuthState`/`build_router` signatures are defined in Tasks 2–3 and consumed identically in Task 4. `AuthConfig`/`JwtKeySource` defined in Task 1, used in Tasks 2/4.

**Known volatile spots (verify-from-source steps included):** `jwt-authorizer` builder/`check_auth`/`Validation` (Task 0 gates; Task 2 adjusts), axum 0.8 `build_router` state generics (Task 3), rmcp `StreamableHttpService::new` (unchanged from base, Task 4).
