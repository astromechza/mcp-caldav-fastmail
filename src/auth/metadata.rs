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
    pub fn new(resource: String, issuer: String, scope: String) -> Self {
        Self {
            resource,
            authorization_servers: vec![issuer],
            scopes_supported: vec![scope],
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
            "https://auth.example.com".into(),
            "caldav".into(),
        );
        let json = serde_json::to_value(&prm).unwrap();
        assert_eq!(json["resource"], "https://mcp.example.com");
        assert_eq!(json["authorization_servers"][0], "https://auth.example.com");
        assert_eq!(json["bearer_methods_supported"][0], "header");
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

use crate::auth::validator::JwtValidator;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    http::header::WWW_AUTHENTICATE,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthState {
    pub validator: Arc<JwtValidator>,
    pub prm_url: String,
    pub resource: String,
    pub issuer: String,
    pub scope: String,
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
        Some(t) => match st.validator.validate(&t).await {
            Ok(_claims) => next.run(req).await,
            Err(_) => challenge(&st),
        },
        None => challenge(&st),
    }
}

fn challenge(st: &AuthState) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, www_authenticate(&st.prm_url))],
    )
        .into_response()
}

/// Compose the public PRM route with an auth-gated protected router.
/// `protected` is any Router (in main, it carries the nested /mcp MCP service);
/// require_auth is layered over it, and the public PRM route is merged in unguarded.
pub fn build_router(auth_state: AuthState, protected: axum::Router<AuthState>) -> axum::Router {
    use axum::routing::get;
    let protected = protected.layer(axum::middleware::from_fn_with_state(
        auth_state.clone(),
        require_auth,
    ));
    let public =
        axum::Router::new().route("/.well-known/oauth-protected-resource", get(prm_handler));
    public.merge(protected).with_state(auth_state)
}

#[cfg(test)]
mod middleware_tests {
    use super::*;
    use crate::auth::validator::KeySource;
    use crate::error::Result;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use jsonwebtoken::DecodingKey;
    use tower::ServiceExt;

    /// A KeySource that is never actually queried in these tests, since we
    /// never send a well-formed bearer token through the middleware.
    struct UnusedKeySource;
    #[async_trait::async_trait]
    impl KeySource for UnusedKeySource {
        async fn key(&self, _kid: &str) -> Result<DecodingKey> {
            unreachable!("no token is sent in this test, so no key lookup should occur")
        }
    }

    fn test_state() -> AuthState {
        AuthState {
            validator: Arc::new(JwtValidator::new(
                Arc::new(UnusedKeySource),
                "https://auth.example.com".into(),
                "https://mcp.example.com".into(),
                "caldav".into(),
            )),
            prm_url: "https://mcp.example.com/.well-known/oauth-protected-resource".into(),
            resource: "https://mcp.example.com".into(),
            issuer: "https://auth.example.com".into(),
            scope: "caldav".into(),
        }
    }

    #[tokio::test]
    async fn missing_token_yields_401_with_challenge() {
        let state = test_state();
        let app = Router::new()
            .route("/protected", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_auth,
            ));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/protected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get(WWW_AUTHENTICATE).is_some());
    }
}

/// Regression guard for the security-critical composition in `main.rs`: the
/// protected router (which in production nests the /mcp service) must be
/// gated by `require_auth`, while the public PRM route must remain reachable
/// without a token.
#[cfg(test)]
mod build_router_tests {
    use super::*;
    use crate::auth::validator::{JwtValidator, KeySource};
    use crate::error::Result;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use jsonwebtoken::DecodingKey;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// A KeySource that is never actually queried in these tests, since we
    /// never send a well-formed bearer token through the middleware.
    struct UnusedKeySource;
    #[async_trait::async_trait]
    impl KeySource for UnusedKeySource {
        async fn key(&self, _kid: &str) -> Result<DecodingKey> {
            unreachable!("no token is sent in this test, so no key lookup should occur")
        }
    }

    fn test_state() -> AuthState {
        AuthState {
            validator: Arc::new(JwtValidator::new(
                Arc::new(UnusedKeySource),
                "https://auth.example.com".into(),
                "https://mcp.example.com".into(),
                "caldav".into(),
            )),
            prm_url: "https://mcp.example.com/.well-known/oauth-protected-resource".into(),
            resource: "https://mcp.example.com".into(),
            issuer: "https://auth.example.com".into(),
            scope: "caldav".into(),
        }
    }

    #[tokio::test]
    async fn mcp_route_is_gated_while_prm_route_stays_public() {
        let protected = Router::new().route("/mcp", get(|| async { "ok" }));
        let app = build_router(test_state(), protected);

        let mcp_resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mcp_resp.status(), StatusCode::UNAUTHORIZED);
        assert!(mcp_resp.headers().get(WWW_AUTHENTICATE).is_some());

        let prm_resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(prm_resp.status(), StatusCode::OK);
    }
}
