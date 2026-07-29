//! RFC 9728 OAuth 2.0 Protected Resource Metadata, and the axum glue that
//! challenges unauthenticated requests with a `WWW-Authenticate` header
//! pointing clients at the metadata document.

use serde::Serialize;

/// RFC 9728 protected-resource-metadata document.
#[derive(Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    pub fn new(resource: String, issuer: Option<String>, scope: Option<String>) -> Self {
        Self {
            resource,
            authorization_servers: issuer.into_iter().collect(),
            scopes_supported: scope.into_iter().collect(),
            bearer_methods_supported: vec!["header".into()],
        }
    }
}

/// The WWW-Authenticate header value pointing clients at the PRM document.
pub fn www_authenticate(resource_metadata_url: &str) -> String {
    format!(r#"Bearer resource_metadata="{resource_metadata_url}""#)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prm_serializes_expected_fields() {
        let prm = ProtectedResourceMetadata::new(
            "https://mcp.example.com".into(),
            Some("https://auth.example.com".into()),
            Some("caldav".into()),
        );
        let json = serde_json::to_value(&prm).unwrap();
        assert_eq!(json["resource"], "https://mcp.example.com");
        assert_eq!(json["authorization_servers"][0], "https://auth.example.com");
        assert_eq!(json["bearer_methods_supported"][0], "header");
    }

    #[test]
    fn prm_omits_unset_issuer_and_scope() {
        let prm = ProtectedResourceMetadata::new("https://mcp.x".into(), None, None);
        let json = serde_json::to_value(&prm).unwrap();
        assert_eq!(json["authorization_servers"], serde_json::json!([]));
        assert_eq!(json["scopes_supported"], serde_json::json!([]));
    }

    #[test]
    fn challenge_header_points_at_metadata() {
        let h = www_authenticate("https://mcp.example.com/.well-known/oauth-protected-resource");
        assert!(h.starts_with("Bearer resource_metadata="));
    }

    #[test]
    fn parse_bearer_is_case_insensitive() {
        // RFC 6750: the auth scheme is case-insensitive.
        assert_eq!(parse_bearer("Bearer abc123"), Some("abc123"));
        assert_eq!(parse_bearer("bearer abc123"), Some("abc123"));
        assert_eq!(parse_bearer("BEARER abc123"), Some("abc123"));
        assert_eq!(parse_bearer("bEaReR   abc123  "), Some("abc123"));
        // Wrong scheme or empty token -> None.
        assert_eq!(parse_bearer("Basic abc123"), None);
        assert_eq!(parse_bearer("Bearer "), None);
        assert_eq!(parse_bearer("abc123"), None);
    }
}

use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    http::header::WWW_AUTHENTICATE,
    middleware::Next,
    response::{IntoResponse, Json, Response},
    routing::get,
};

/// Auth state shared by the PRM handler and the auth-gating middleware.
///
/// `prm_url`/`resource`/`issuer`/`scope` are only meaningful in JWT mode,
/// where clients are pointed at a discoverable PRM document. In token mode
/// there is no PRM document, so those fields are unused; `jwt_mode` selects
/// which `WWW-Authenticate` challenge shape `challenge()` emits.
#[derive(Clone)]
pub struct AuthState {
    pub authenticator: crate::auth::Authenticator,
    pub prm_url: String,
    pub resource: String,
    pub issuer: Option<String>,
    pub scope: Option<String>,
    pub jwt_mode: bool,
}

/// GET /.well-known/oauth-protected-resource
pub async fn prm_handler(State(st): State<AuthState>) -> Json<ProtectedResourceMetadata> {
    Json(ProtectedResourceMetadata::new(
        st.resource.clone(),
        st.issuer.clone(),
        st.scope.clone(),
    ))
}

/// Extract a bearer token from an `Authorization` header value. Per RFC 6750
/// the `Bearer` auth scheme is case-insensitive (`bearer`, `BEARER`, ... all
/// valid), so match it that way rather than a case-sensitive prefix.
fn parse_bearer(header: &str) -> Option<&str> {
    let (scheme, rest) = header.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| rest.trim())
        .filter(|t| !t.is_empty())
}

/// Middleware: require a valid bearer token, else 401 with challenge.
pub async fn require_auth(State(st): State<AuthState>, req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(parse_bearer)
        .map(|s| s.to_string());

    match token {
        Some(t) if st.authenticator.verify(&t).await => next.run(req).await,
        _ => challenge(&st),
    }
}

/// Build the `WWW-Authenticate` challenge for the current auth mode: in JWT
/// mode it points clients at the PRM document; in token mode there is no PRM
/// document to discover, so a bare `Bearer` challenge is returned instead.
fn challenge(st: &AuthState) -> Response {
    let header = if st.jwt_mode {
        www_authenticate(&st.prm_url)
    } else {
        "Bearer".to_string()
    };
    (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, header)]).into_response()
}

/// GET /healthz - unauthenticated liveness probe for the container/orchestrator.
/// Served in every auth mode; never gated by `require_auth`.
pub async fn healthz() -> &'static str {
    "ok"
}

/// Compose the app router for the selected auth mode.
/// - `/healthz` is always public, in every mode.
/// - `Some(state)` with `jwt_mode == true`: public PRM route + `/mcp` gated by `require_auth`.
/// - `Some(state)` with `jwt_mode == false` (token mode): `/mcp` gated, no PRM route.
/// - `None` (AUTH_MODE=none): `/mcp` served open, no PRM route, no gating.
///
/// `protected` is any state-agnostic Router (in main, it carries the nested
/// /mcp MCP service).
pub fn build_router(protected: Router<()>, auth: Option<AuthState>) -> Router {
    match auth {
        None => Router::new()
            .route("/healthz", get(healthz))
            .merge(protected),
        Some(state) => {
            // `route_layer` (not `layer`) so the middleware only wraps
            // matched routes; unmatched paths (e.g. the PRM path in token
            // mode, or /healthz) fall through to axum's default 404 instead
            // of being challenged for auth first.
            let gated = protected.route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_auth,
            ));
            if state.jwt_mode {
                // `gated` is `Router<()>` (the auth middleware carries its own
                // state directly, independent of the router's state type), so
                // reinterpret it as `Router<AuthState>` via `with_state(())`
                // before merging it into the public sub-router. `Router::new()`
                // here infers `S = AuthState` because of the PRM route below;
                // `/healthz` (a state-free handler) is happy with any `S`.
                Router::new()
                    .route("/healthz", get(healthz))
                    .route("/.well-known/oauth-protected-resource", get(prm_handler))
                    .merge(gated.with_state(()))
                    .with_state(state)
            } else {
                // No PRM route in token mode; `gated` is already `Router<()>`
                // (the middleware carries its own state), so the public
                // `/healthz` router stays `Router<()>` too and needs no
                // further `with_state` call.
                Router::new().route("/healthz", get(healthz)).merge(gated)
            }
        }
    }
}

/// Regression guard for the security-critical composition in `main.rs`: for
/// each auth mode, the `/mcp` route must be gated (or open, for `none` mode)
/// exactly as intended, and the PRM route must be present only in jwt mode.
#[cfg(test)]
mod build_router_tests {
    use super::*;
    use crate::auth::Authenticator;
    use crate::config::AuthConfig;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::routing::get;
    use tower::ServiceExt;

    async fn token_auth() -> Authenticator {
        Authenticator::from_config(&AuthConfig::Token {
            secret: "x".repeat(32),
        })
        .await
        .unwrap()
        .unwrap()
    }

    fn dummy() -> Router<()> {
        Router::new().route("/mcp", get(|| async { "ok" }))
    }

    async fn state(jwt_mode: bool) -> AuthState {
        AuthState {
            authenticator: token_auth().await,
            prm_url: "https://mcp.x/.well-known/oauth-protected-resource".into(),
            resource: "https://mcp.x".into(),
            issuer: Some("https://i".into()),
            scope: Some("caldav".into()),
            jwt_mode,
        }
    }

    #[tokio::test]
    async fn token_mode_gates_mcp_and_no_prm() {
        let app = build_router(dummy(), Some(state(false).await));

        let r = app
            .clone()
            .oneshot(HttpRequest::get("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            r.headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .unwrap(),
            "Bearer"
        );

        let prm = app
            .oneshot(
                HttpRequest::get("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(prm.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn none_mode_is_open() {
        let app = build_router(dummy(), None);
        let r = app
            .oneshot(HttpRequest::get("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jwt_mode_gates_mcp_and_serves_prm() {
        let app = build_router(dummy(), Some(state(true).await));

        let r = app
            .clone()
            .oneshot(HttpRequest::get("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert!(
            r.headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("resource_metadata")
        );

        let prm = app
            .oneshot(
                HttpRequest::get("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(prm.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn healthz_is_public_in_all_modes() {
        let apps = vec![
            build_router(dummy(), None),
            build_router(dummy(), Some(state(false).await)),
            build_router(dummy(), Some(state(true).await)),
        ];
        for app in apps {
            let r = app
                .oneshot(HttpRequest::get("/healthz").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::OK);
        }
    }

    /// Production nests the MCP service (`nest_service("/mcp", ...)`), which
    /// prefix-matches `/mcp` AND `/mcp/*`, unlike the exact-match `/mcp`
    /// route used by `dummy()` above. Prove that `route_layer` gates the
    /// whole nested subtree, not just the exact `/mcp` path.
    #[tokio::test]
    async fn nested_mcp_subpaths_are_gated() {
        // nest (prefix match, like nest_service in production) exposes /mcp AND /mcp/*
        let protected: Router<()> = Router::new().nest(
            "/mcp",
            Router::new().route("/session", get(|| async { "ok" })),
        );
        let app = build_router(protected, Some(state(false).await)); // token mode
        // Unauthenticated request to a SUBPATH must be rejected, not fall through.
        let r = app
            .oneshot(
                HttpRequest::get("/mcp/session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "route_layer must gate nested /mcp subpaths"
        );
    }
}
