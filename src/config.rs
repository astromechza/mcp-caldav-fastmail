use crate::error::{Error, Result};

#[derive(Clone)]
pub struct Config {
    pub bind_addr: String,
    pub resource_uri: String,
    pub authelia_issuer: String,
    pub authelia_jwks_uri: String,
    pub required_scope: String,
    pub fastmail_username: String,
    pub fastmail_app_password: String,
    pub caldav_base_url: String,
}

/// Manual `Debug` impl so `fastmail_app_password` never appears in logs: `{cfg:?}`
/// redacts it instead of printing the plaintext Fastmail app password.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("resource_uri", &self.resource_uri)
            .field("authelia_issuer", &self.authelia_issuer)
            .field("authelia_jwks_uri", &self.authelia_jwks_uri)
            .field("required_scope", &self.required_scope)
            .field("fastmail_username", &self.fastmail_username)
            .field("fastmail_app_password", &"[redacted]")
            .field("caldav_base_url", &self.caldav_base_url)
            .finish()
    }
}

impl Config {
    /// Load config from environment. Uses a lookup closure for testability.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let req = |k: &str| get(k).ok_or_else(|| Error::Config(format!("missing env {k}")));
        Ok(Config {
            bind_addr: get("BIND_ADDR").unwrap_or_else(|| "0.0.0.0:8080".into()),
            resource_uri: req("RESOURCE_URI")?,
            authelia_issuer: req("AUTHELIA_ISSUER")?,
            authelia_jwks_uri: req("AUTHELIA_JWKS_URI")?,
            required_scope: get("REQUIRED_SCOPE").unwrap_or_else(|| "caldav".into()),
            fastmail_username: req("FASTMAIL_USERNAME")?,
            fastmail_app_password: req("FASTMAIL_APP_PASSWORD")?,
            caldav_base_url: get("CALDAV_BASE_URL")
                .unwrap_or_else(|| "https://caldav.fastmail.com/".into()),
        })
    }

    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(m: HashMap<&'static str, &'static str>) -> impl Fn(&str) -> Option<String> {
        move |k: &str| m.get(k).map(|s| s.to_string())
    }

    #[test]
    fn defaults_applied_when_optional_absent() {
        let m = HashMap::from([
            ("RESOURCE_URI", "https://mcp.example.com"),
            ("AUTHELIA_ISSUER", "https://auth.example.com"),
            ("AUTHELIA_JWKS_URI", "https://auth.example.com/jwks.json"),
            ("FASTMAIL_USERNAME", "me@fastmail.com"),
            ("FASTMAIL_APP_PASSWORD", "secret"),
        ]);
        let cfg = Config::from_lookup(lookup(m)).unwrap();
        assert_eq!(cfg.bind_addr, "0.0.0.0:8080");
        assert_eq!(cfg.caldav_base_url, "https://caldav.fastmail.com/");
        assert_eq!(cfg.required_scope, "caldav");
    }

    #[test]
    fn missing_required_errors() {
        let cfg = Config::from_lookup(lookup(HashMap::new()));
        assert!(cfg.is_err());
    }

    #[test]
    fn debug_redacts_app_password() {
        let m = HashMap::from([
            ("RESOURCE_URI", "https://mcp.example.com"),
            ("AUTHELIA_ISSUER", "https://auth.example.com"),
            ("AUTHELIA_JWKS_URI", "https://auth.example.com/jwks.json"),
            ("FASTMAIL_USERNAME", "me@fastmail.com"),
            ("FASTMAIL_APP_PASSWORD", "supersecret"),
        ]);
        let cfg = Config::from_lookup(lookup(m)).unwrap();
        let debug_str = format!("{cfg:?}");
        assert!(debug_str.contains("[redacted]"));
        assert!(!debug_str.contains("supersecret"));
    }
}
