use std::sync::Arc;

use mcp_caldav_fastmail::auth::{Authenticator, AuthState, build_router};
use mcp_caldav_fastmail::caldav::FastmailCalDav;
use mcp_caldav_fastmail::config::{AuthConfig, Config};
use mcp_caldav_fastmail::mcp::CalendarServer;

use axum::Router;
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
    let caldav_for_mcp = caldav.clone();
    let mcp_service: StreamableHttpService<CalendarServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(CalendarServer::new(caldav_for_mcp.clone())),
            Arc::new(LocalSessionManager::default()),
            Default::default(),
        );
    let protected: Router<()> = Router::new().nest_service("/mcp", mcp_service);

    let mode_label = match &cfg.auth {
        AuthConfig::Jwt { .. } => "jwt",
        AuthConfig::Token { .. } => "token",
        AuthConfig::None => "none",
    };

    let authenticator = Authenticator::from_config(&cfg.auth).await?;
    let auth_state = match (&cfg.auth, authenticator) {
        (AuthConfig::None, _) => {
            tracing::warn!(
                "AUTH_MODE=none: application auth is DISABLED. Ensure the platform edge \
                 (e.g. a private container gateway) gates access to /mcp."
            );
            None
        }
        (
            AuthConfig::Jwt {
                resource,
                issuer,
                required_scope,
                ..
            },
            Some(a),
        ) => Some(AuthState {
            authenticator: a,
            prm_url: format!(
                "{}/.well-known/oauth-protected-resource",
                resource.trim_end_matches('/')
            ),
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
    tracing::info!(
        "listening on {} (auth mode: {})",
        cfg.bind_addr,
        mode_label
    );
    axum::serve(listener, app).await?;
    Ok(())
}
