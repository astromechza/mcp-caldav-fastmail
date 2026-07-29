use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub enum JwtKeySource {
    Jwks(String),
    /// PEM public key — inline PEM text OR a filesystem path (resolved later in the auth layer).
    PublicKeyPem(String),
}

#[derive(Clone)]
pub enum AuthConfig {
    Jwt {
        resource: String,
        source: JwtKeySource,
        issuer: Option<String>,
        audience: Option<String>,
        required_scope: Option<String>,
    },
    Token {
        secret: String,
    },
    None,
}

// Manual Debug so a Token secret is never printed.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthConfig::Jwt {
                resource,
                source,
                issuer,
                audience,
                required_scope,
            } => f
                .debug_struct("Jwt")
                .field("resource", resource)
                .field("source", source)
                .field("issuer", issuer)
                .field("audience", audience)
                .field("required_scope", required_scope)
                .finish(),
            AuthConfig::Token { .. } => f
                .debug_struct("Token")
                .field("secret", &"[redacted]")
                .finish(),
            AuthConfig::None => f.write_str("None"),
        }
    }
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
            .field("auth", &self.auth)
            .field("fastmail_username", &self.fastmail_username)
            .field("fastmail_app_password", &"[redacted]")
            .field("caldav_base_url", &self.caldav_base_url)
            .finish()
    }
}

impl Config {
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        // Treat an empty-string env var as unset. Deployment tooling (docker-compose,
        // k8s env-from-secret, etc.) commonly produces "" rather than omitting the
        // variable entirely, and "" is never a meaningful value for any of the keys
        // below. REQUIRED_SCOPE is the deliberate exception: its empty string is a
        // real, distinct value (explicit scope-check opt-out), so it bypasses this
        // helper and reads via `get` directly.
        let getne = |k: &str| get(k).filter(|s| !s.trim().is_empty());

        let bind_addr = getne("BIND_ADDR").unwrap_or_else(|| "0.0.0.0:8080".into());
        let fastmail_username = getne("FASTMAIL_USERNAME")
            .ok_or_else(|| Error::Config("missing env FASTMAIL_USERNAME".into()))?;
        let fastmail_app_password = getne("FASTMAIL_APP_PASSWORD")
            .ok_or_else(|| Error::Config("missing env FASTMAIL_APP_PASSWORD".into()))?;
        let caldav_base_url =
            getne("CALDAV_BASE_URL").unwrap_or_else(|| "https://caldav.fastmail.com/".into());

        let mode = get("AUTH_MODE").unwrap_or_else(|| "jwt".into());
        let auth = match mode.as_str() {
            "jwt" => {
                let resource = getne("RESOURCE_URI")
                    .ok_or_else(|| Error::Config("jwt mode: missing RESOURCE_URI".into()))?;
                let jwks = getne("AUTH_JWKS_URI");
                let pem = getne("AUTH_JWT_PUBLIC_KEY");
                let source = match (jwks, pem) {
                    (Some(u), None) => JwtKeySource::Jwks(u),
                    (None, Some(k)) => JwtKeySource::PublicKeyPem(k),
                    (None, None) => {
                        return Err(Error::Config(
                            "jwt mode: set exactly one of AUTH_JWKS_URI or AUTH_JWT_PUBLIC_KEY"
                                .into(),
                        ));
                    }
                    (Some(_), Some(_)) => {
                        return Err(Error::Config(
                            "jwt mode: set only ONE of AUTH_JWKS_URI or AUTH_JWT_PUBLIC_KEY".into(),
                        ));
                    }
                };
                AuthConfig::Jwt {
                    audience: getne("AUTH_JWT_AUDIENCE").or_else(|| Some(resource.clone())),
                    resource,
                    source,
                    issuer: getne("AUTH_JWT_ISSUER"),
                    required_scope: match get("REQUIRED_SCOPE") {
                        Some(s) if s.is_empty() => None, // explicit opt-out (REQUIRED_SCOPE="")
                        Some(s) => Some(s),              // custom scope
                        None => Some("caldav".into()),   // secure default (matches base behavior)
                    },
                }
            }
            "token" => {
                let secret = getne("MCP_TOKEN")
                    .ok_or_else(|| Error::Config("token mode: missing MCP_TOKEN".into()))?;
                if secret.len() < 32 {
                    tracing::warn!("MCP_TOKEN is short (<32 chars); use a long random secret");
                }
                AuthConfig::Token { secret }
            }
            "none" => AuthConfig::None,
            other => {
                return Err(Error::Config(format!(
                    "unknown AUTH_MODE '{other}' (expected jwt|token|none)"
                )));
            }
        };

        Ok(Config {
            bind_addr,
            auth,
            fastmail_username,
            fastmail_app_password,
            caldav_base_url,
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

    fn look(pairs: Vec<(&str, &str)>) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    fn fastmail() -> Vec<(&'static str, &'static str)> {
        vec![
            ("FASTMAIL_USERNAME", "me@fastmail.com"),
            ("FASTMAIL_APP_PASSWORD", "supersecret"),
        ]
    }

    #[test]
    fn jwt_mode_with_jwks_ok() {
        let mut v = fastmail();
        v.push(("RESOURCE_URI", "https://mcp.x"));
        v.push(("AUTH_JWKS_URI", "https://i/jwks"));
        let cfg = Config::from_lookup(look(v)).unwrap();
        assert!(matches!(cfg.auth, AuthConfig::Jwt { .. }));
    }

    #[test]
    fn jwt_mode_with_pem_ok() {
        let mut v = fastmail();
        v.push(("RESOURCE_URI", "https://mcp.x"));
        v.push((
            "AUTH_JWT_PUBLIC_KEY",
            "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----",
        ));
        let cfg = Config::from_lookup(look(v)).unwrap();
        assert!(matches!(
            cfg.auth,
            AuthConfig::Jwt {
                source: JwtKeySource::PublicKeyPem(_),
                ..
            }
        ));
    }

    #[test]
    fn jwt_mode_needs_exactly_one_key_source() {
        let mut none = fastmail();
        none.push(("RESOURCE_URI", "https://mcp.x"));
        assert!(Config::from_lookup(look(none)).is_err());

        let mut both = fastmail();
        both.push(("RESOURCE_URI", "https://mcp.x"));
        both.push(("AUTH_JWKS_URI", "u"));
        both.push(("AUTH_JWT_PUBLIC_KEY", "k"));
        assert!(Config::from_lookup(look(both)).is_err());
    }

    #[test]
    fn jwt_mode_missing_resource_errors() {
        let mut v = fastmail();
        v.push(("AUTH_JWKS_URI", "u"));
        assert!(Config::from_lookup(look(v)).is_err());
    }

    #[test]
    fn token_mode_requires_secret() {
        let mut ok = fastmail();
        ok.push(("AUTH_MODE", "token"));
        ok.push(("MCP_TOKEN", "abcdefghijklmnopqrstuvwxyz012345"));
        assert!(matches!(
            Config::from_lookup(look(ok)).unwrap().auth,
            AuthConfig::Token { .. }
        ));

        let mut bad = fastmail();
        bad.push(("AUTH_MODE", "token"));
        assert!(Config::from_lookup(look(bad)).is_err());
    }

    #[test]
    fn none_mode_needs_only_fastmail() {
        let mut v = fastmail();
        v.push(("AUTH_MODE", "none"));
        assert!(matches!(
            Config::from_lookup(look(v)).unwrap().auth,
            AuthConfig::None
        ));
    }

    #[test]
    fn unknown_mode_errors() {
        let mut v = fastmail();
        v.push(("AUTH_MODE", "bogus"));
        assert!(Config::from_lookup(look(v)).is_err());
    }

    #[test]
    fn audience_defaults_to_resource_uri() {
        let mut v = fastmail();
        v.push(("RESOURCE_URI", "https://mcp.x"));
        v.push(("AUTH_JWKS_URI", "u"));
        let cfg = Config::from_lookup(look(v)).unwrap();
        match cfg.auth {
            AuthConfig::Jwt { audience, .. } => {
                assert_eq!(audience.as_deref(), Some("https://mcp.x"))
            }
            _ => panic!("expected jwt"),
        }
    }

    #[test]
    fn required_scope_defaults_and_optout() {
        // No REQUIRED_SCOPE set -> secure default "caldav".
        let mut v = fastmail();
        v.push(("RESOURCE_URI", "https://mcp.x"));
        v.push(("AUTH_JWKS_URI", "u"));
        let cfg = Config::from_lookup(look(v)).unwrap();
        match cfg.auth {
            AuthConfig::Jwt { required_scope, .. } => {
                assert_eq!(required_scope.as_deref(), Some("caldav"));
            }
            _ => panic!("expected jwt"),
        }

        // REQUIRED_SCOPE="" -> explicit opt-out, no scope check.
        let mut v = fastmail();
        v.push(("RESOURCE_URI", "https://mcp.x"));
        v.push(("AUTH_JWKS_URI", "u"));
        v.push(("REQUIRED_SCOPE", ""));
        let cfg = Config::from_lookup(look(v)).unwrap();
        match cfg.auth {
            AuthConfig::Jwt { required_scope, .. } => assert_eq!(required_scope, None),
            _ => panic!("expected jwt"),
        }

        // REQUIRED_SCOPE=events -> custom scope honored.
        let mut v = fastmail();
        v.push(("RESOURCE_URI", "https://mcp.x"));
        v.push(("AUTH_JWKS_URI", "u"));
        v.push(("REQUIRED_SCOPE", "events"));
        let cfg = Config::from_lookup(look(v)).unwrap();
        match cfg.auth {
            AuthConfig::Jwt { required_scope, .. } => {
                assert_eq!(required_scope.as_deref(), Some("events"));
            }
            _ => panic!("expected jwt"),
        }
    }

    #[test]
    fn empty_key_source_treated_as_unset() {
        let mut v = fastmail();
        v.push(("RESOURCE_URI", "https://mcp.x"));
        v.push(("AUTH_JWKS_URI", ""));
        assert!(Config::from_lookup(look(v)).is_err());
    }

    #[test]
    fn empty_issuer_is_none() {
        let mut v = fastmail();
        v.push(("RESOURCE_URI", "https://mcp.x"));
        v.push(("AUTH_JWKS_URI", "https://i/jwks"));
        v.push(("AUTH_JWT_ISSUER", ""));
        let cfg = Config::from_lookup(look(v)).unwrap();
        match cfg.auth {
            AuthConfig::Jwt { issuer, .. } => assert_eq!(issuer, None),
            _ => panic!("expected jwt"),
        }
    }

    #[test]
    fn missing_fastmail_errors() {
        assert!(Config::from_lookup(look(vec![("AUTH_MODE", "none")])).is_err());
    }

    #[test]
    fn debug_redacts_secrets() {
        let mut v = fastmail();
        v.push(("AUTH_MODE", "token"));
        v.push(("MCP_TOKEN", "this-is-a-very-secret-token-value-1234"));
        let cfg = Config::from_lookup(look(v)).unwrap();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("[redacted]"));
        assert!(!dbg.contains("supersecret")); // fastmail pw
        assert!(!dbg.contains("this-is-a-very-secret-token-value")); // token
    }
}
