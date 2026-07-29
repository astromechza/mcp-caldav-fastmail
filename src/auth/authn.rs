//! Unified `Authenticator` selected at startup from `AuthConfig`, dispatching
//! to either JWT validation (via the existing rustls-only `JwtValidator`) or a
//! constant-time shared-secret check (token mode). `AuthConfig::None` builds
//! no `Authenticator` at all.

use crate::auth::validator::{JwksKeySource, JwtValidator, StaticKeySource};
use crate::config::{AuthConfig, JwtKeySource};
use crate::error::Result;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// Constant-time shared-secret bearer check (token mode).
pub struct TokenChecker {
    secret: Vec<u8>,
}

impl TokenChecker {
    pub fn new(secret: String) -> Self {
        Self {
            secret: secret.into_bytes(),
        }
    }

    pub fn check(&self, presented: &str) -> bool {
        let p = presented.as_bytes();
        // Length is not secret here; bail early if it differs (ct_eq needs equal len).
        if p.len() != self.secret.len() {
            return false;
        }
        p.ct_eq(&self.secret).into()
    }
}

/// Runtime authenticator selected by AuthConfig. `None` mode builds no Authenticator.
#[derive(Clone)]
pub enum Authenticator {
    Jwt(Arc<JwtValidator>),
    Token(Arc<TokenChecker>),
}

impl Authenticator {
    /// Build from AuthConfig. Returns Ok(None) for AuthConfig::None.
    pub async fn from_config(auth: &AuthConfig) -> Result<Option<Authenticator>> {
        match auth {
            AuthConfig::None => Ok(None),
            AuthConfig::Token { secret } => Ok(Some(Authenticator::Token(Arc::new(
                TokenChecker::new(secret.clone()),
            )))),
            AuthConfig::Jwt {
                source,
                issuer,
                audience,
                required_scope,
                ..
            } => {
                let keys: Arc<dyn crate::auth::validator::KeySource> = match source {
                    JwtKeySource::Jwks(uri) => Arc::new(JwksKeySource::new(uri.clone())),
                    JwtKeySource::PublicKeyPem(p) => Arc::new(StaticKeySource::from_pem_or_path(p)?),
                };
                let validator = JwtValidator::new(
                    keys,
                    issuer.clone(),
                    audience.clone(),
                    required_scope.clone(),
                );
                Ok(Some(Authenticator::Jwt(Arc::new(validator))))
            }
        }
    }

    /// Verify a presented bearer token string. true = authorized.
    pub async fn verify(&self, token: &str) -> bool {
        match self {
            Authenticator::Token(t) => t.check(token),
            Authenticator::Jwt(v) => v.validate(token).await.is_ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, JwtKeySource};

    #[test]
    fn token_checker_constant_time_semantics() {
        let t = TokenChecker::new("correct-horse-battery-staple-000000".into());
        assert!(t.check("correct-horse-battery-staple-000000"));
        assert!(!t.check("correct-horse-battery-staple-000001"));
        assert!(!t.check("short"));
        assert!(!t.check(""));
    }

    #[tokio::test]
    async fn none_builds_no_authenticator() {
        assert!(
            Authenticator::from_config(&AuthConfig::None)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn token_authenticator_verifies() {
        let a = Authenticator::from_config(&AuthConfig::Token {
            secret: "s3cr3t-token-32-chars-minimum-ab".into(),
        })
        .await
        .unwrap()
        .unwrap();
        assert!(a.verify("s3cr3t-token-32-chars-minimum-ab").await);
        assert!(!a.verify("nope").await);
    }

    #[tokio::test]
    async fn jwt_static_pem_valid_expired_wrongaud() {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        let priv_pem = include_str!("testdata/test_priv.pem");
        let mint = |aud: &str, exp: usize| {
            let mut h = Header::new(Algorithm::RS256);
            h.kid = Some("test".into());
            let claims = serde_json::json!({"sub":"u","iss":"https://issuer.x","aud":aud,"exp":exp,"scope":"caldav"});
            encode(
                &h,
                &claims,
                &EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap(),
            )
            .unwrap()
        };
        let cfg = AuthConfig::Jwt {
            resource: "https://mcp.x".into(),
            source: JwtKeySource::PublicKeyPem("src/auth/testdata/test_pub.pem".into()),
            issuer: Some("https://issuer.x".into()),
            audience: Some("https://mcp.x".into()),
            required_scope: Some("caldav".into()),
        };
        let a = Authenticator::from_config(&cfg).await.unwrap().unwrap();
        assert!(
            a.verify(&mint("https://mcp.x", 9_999_999_999)).await,
            "valid token should pass"
        );
        assert!(
            !a.verify(&mint("https://mcp.x", 1)).await,
            "expired must fail"
        );
        assert!(
            !a.verify(&mint("https://other.x", 9_999_999_999)).await,
            "wrong aud must fail"
        );
    }

    #[tokio::test]
    async fn jwt_static_pem_optional_aud_skipped() {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        let priv_pem = include_str!("testdata/test_priv.pem");
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("test".into());
        // No aud claim at all in the token; validator has audience=None -> not checked.
        let claims = serde_json::json!({"sub":"u","iss":"https://issuer.x","exp":9_999_999_999u64});
        let token = encode(
            &h,
            &claims,
            &EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap(),
        )
        .unwrap();
        let cfg = AuthConfig::Jwt {
            resource: "https://mcp.x".into(),
            source: JwtKeySource::PublicKeyPem("src/auth/testdata/test_pub.pem".into()),
            issuer: None,
            audience: None,
            required_scope: None,
        };
        let a = Authenticator::from_config(&cfg).await.unwrap().unwrap();
        assert!(
            a.verify(&token).await,
            "signature+exp only (no iss/aud/scope) should pass"
        );
    }
}
