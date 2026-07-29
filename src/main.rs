use std::sync::Arc;

use mcp_caldav_fastmail::auth::metadata::{prm_handler, require_auth};
use mcp_caldav_fastmail::auth::{AuthState, JwksKeySource, JwtValidator};
use mcp_caldav_fastmail::caldav::FastmailCalDav;
use mcp_caldav_fastmail::config::Config;
use mcp_caldav_fastmail::mcp::CalendarServer;

use axum::{Router, middleware, routing::get};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, tower::StreamableHttpService,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env()?;

    let caldav = Arc::new(FastmailCalDav::new(
        &cfg.caldav_base_url,
        &cfg.fastmail_username,
        &cfg.fastmail_app_password,
    )?);

    let keys = Arc::new(JwksKeySource::new(cfg.authelia_jwks_uri.clone()));
    let validator = Arc::new(JwtValidator::new(
        keys,
        cfg.authelia_issuer.clone(),
        cfg.resource_uri.clone(),
        cfg.required_scope.clone(),
    ));
    let prm_url = format!(
        "{}/.well-known/oauth-protected-resource",
        cfg.resource_uri.trim_end_matches('/')
    );
    let auth_state = AuthState {
        validator,
        prm_url,
        resource: cfg.resource_uri.clone(),
        issuer: cfg.authelia_issuer.clone(),
        scope: cfg.required_scope.clone(),
    };

    let caldav_for_mcp = caldav.clone();
    let mcp_service: StreamableHttpService<CalendarServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(CalendarServer::new(caldav_for_mcp.clone())),
            Arc::new(LocalSessionManager::default()),
            Default::default(),
        );

    // /.well-known/* MUST be public (no auth middleware); /mcp is protected by
    // require_auth. Do NOT layer require_auth over the PRM route.
    let protected =
        Router::new()
            .nest_service("/mcp", mcp_service)
            .layer(middleware::from_fn_with_state(
                auth_state.clone(),
                require_auth,
            ));
    let public = Router::new().route("/.well-known/oauth-protected-resource", get(prm_handler));
    let app = public.merge(protected).with_state(auth_state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("listening on {}", cfg.bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}
