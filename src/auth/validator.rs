//! OAuth 2.1 Resource Server JWT validation for inbound Authelia-issued tokens.
//!
//! Validates signature (via JWKS), issuer, audience, expiry, and a required scope.

use crate::error::{Error, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: Aud,
    pub exp: usize,
    #[serde(default)]
    pub scope: String,
}

/// aud may be a string or array depending on issuer; accept both.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Aud {
    One(String),
    Many(Vec<String>),
}

impl Aud {
    pub fn contains(&self, v: &str) -> bool {
        match self {
            Aud::One(s) => s == v,
            Aud::Many(xs) => xs.iter().any(|s| s == v),
        }
    }
}

/// Fetches JWKS keys keyed by `kid`. Injectable so the validator is testable without a live Authelia.
#[async_trait::async_trait]
pub trait KeySource: Send + Sync {
    async fn key(&self, kid: &str) -> Result<DecodingKey>;
}

pub struct JwtValidator {
    keys: Arc<dyn KeySource>,
    issuer: String,
    audience: String,
    required_scope: String,
}

impl JwtValidator {
    pub fn new(
        keys: Arc<dyn KeySource>,
        issuer: String,
        audience: String,
        required_scope: String,
    ) -> Self {
        Self {
            keys,
            issuer,
            audience,
            required_scope,
        }
    }

    /// Validate a bearer token; return claims on success.
    pub async fn validate(&self, token: &str) -> Result<Claims> {
        let header = decode_header(token).map_err(|e| Error::Auth(e.to_string()))?;
        let kid = header.kid.ok_or_else(|| Error::Auth("no kid".into()))?;
        let key = self.keys.key(&kid).await?;

        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&[&self.issuer]);
        v.set_audience(&[&self.audience]);
        let data = decode::<Claims>(token, &key, &v).map_err(|e| Error::Auth(e.to_string()))?;

        if !data
            .claims
            .scope
            .split_whitespace()
            .any(|s| s == self.required_scope)
        {
            return Err(Error::Auth(format!(
                "missing scope {}",
                self.required_scope
            )));
        }
        Ok(data.claims)
    }
}

/// Production key source: fetch + cache JWKS from Authelia.
pub struct JwksKeySource {
    jwks_uri: String,
    cache: RwLock<HashMap<String, DecodingKey>>,
    http: reqwest::Client,
}

impl JwksKeySource {
    pub fn new(jwks_uri: String) -> Self {
        Self {
            jwks_uri,
            cache: RwLock::new(HashMap::new()),
            http: reqwest::Client::new(),
        }
    }

    async fn refresh(&self) -> Result<()> {
        let jwks = jwks::Jwks::from_jwks_url_with_client(&self.http, self.jwks_uri.clone())
            .await
            .map_err(|e| Error::Auth(format!("jwks fetch: {e}")))?;

        let mut cache = self.cache.write().await;
        cache.clear();
        for (kid, jwk) in jwks.keys {
            cache.insert(kid, jwk.decoding_key);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl KeySource for JwksKeySource {
    async fn key(&self, kid: &str) -> Result<DecodingKey> {
        if let Some(k) = self.cache.read().await.get(kid) {
            return Ok(k.clone());
        }
        self.refresh().await?;
        self.cache
            .read()
            .await
            .get(kid)
            .cloned()
            .ok_or_else(|| Error::Auth(format!("unknown kid {kid}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};

    const PRIV: &str = include_str!("testdata/test_priv.pem");
    const PUB: &str = include_str!("testdata/test_pub.pem");

    struct StaticKey(DecodingKey);
    #[async_trait::async_trait]
    impl KeySource for StaticKey {
        async fn key(&self, _kid: &str) -> Result<DecodingKey> {
            Ok(self.0.clone())
        }
    }

    fn make_token(aud: &str, scope: &str, exp: usize) -> String {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("test".into());
        let claims = serde_json::json!({
            "sub": "user", "iss": "https://auth.example.com",
            "aud": aud, "exp": exp, "scope": scope
        });
        encode(
            &h,
            &claims,
            &EncodingKey::from_rsa_pem(PRIV.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn validator() -> JwtValidator {
        let key = DecodingKey::from_rsa_pem(PUB.as_bytes()).unwrap();
        JwtValidator::new(
            Arc::new(StaticKey(key)),
            "https://auth.example.com".into(),
            "https://mcp.example.com".into(),
            "caldav".into(),
        )
    }

    #[tokio::test]
    async fn valid_token_passes() {
        let t = make_token("https://mcp.example.com", "caldav openid", 9_999_999_999);
        assert!(validator().validate(&t).await.is_ok());
    }

    #[tokio::test]
    async fn wrong_audience_fails() {
        let t = make_token("https://other.example.com", "caldav", 9_999_999_999);
        assert!(validator().validate(&t).await.is_err());
    }

    #[tokio::test]
    async fn missing_scope_fails() {
        let t = make_token("https://mcp.example.com", "openid", 9_999_999_999);
        assert!(validator().validate(&t).await.is_err());
    }

    #[tokio::test]
    async fn expired_fails() {
        let t = make_token("https://mcp.example.com", "caldav", 1);
        assert!(validator().validate(&t).await.is_err());
    }

    #[tokio::test]
    async fn no_kid_header_fails() {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = None;
        let claims = serde_json::json!({
            "sub": "user", "iss": "https://auth.example.com",
            "aud": "https://mcp.example.com", "exp": 9_999_999_999u64, "scope": "caldav"
        });
        let t = encode(
            &h,
            &claims,
            &EncodingKey::from_rsa_pem(PRIV.as_bytes()).unwrap(),
        )
        .unwrap();
        let err = validator().validate(&t).await.unwrap_err();
        match err {
            Error::Auth(msg) => assert!(msg.contains("no kid")),
            _ => panic!("expected Error::Auth, got {err:?}"),
        }
    }
}
