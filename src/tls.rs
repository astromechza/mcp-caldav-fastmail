//! Compiled-in TLS root-of-trust for outbound HTTPS clients.
//!
//! The point is to not depend on a filesystem trust store, so outbound TLS
//! works in minimal container images regardless of what CA files they ship
//! (the runtime image is distroless today, but this also holds for `scratch`
//! or any image without a populated `/etc/ssl/certs`).
//!
//! `reqwest` 0.13's `rustls` feature verifies server certificates with
//! [`rustls-platform-verifier`], which -- on Linux -- loads trust roots from
//! the filesystem at *runtime* via `rustls-native-certs` (respecting
//! `SSL_CERT_FILE`/`SSL_CERT_DIR`, otherwise falling back to well-known paths
//! like `/etc/ssl/certs/ca-certificates.crt`). If no roots can be loaded from
//! disk, `rustls-platform-verifier` returns an error and the client fails to
//! build. Unlike `reqwest` 0.12, there is no `rustls-tls-webpki-roots` Cargo
//! feature in 0.13 that would compile Mozilla's roots into the binary --
//! that feature was removed when reqwest switched its `rustls` backend over
//! to the platform verifier.
//!
//! So we compile Mozilla's root CA list into the binary via `webpki-root-certs`
//! and pin every `reqwest::Client` we build to *only* those roots with
//! [`reqwest::ClientBuilder::tls_certs_only`], which bypasses
//! `rustls-platform-verifier` (and therefore any filesystem access) entirely.

use crate::error::{Error, Result};

/// Mozilla's root CA set, compiled into the binary, ready to hand to
/// [`reqwest::ClientBuilder::tls_certs_only`].
///
/// Every outbound `reqwest::Client` built by this crate should pass this to
/// `tls_certs_only` so that certificate verification never touches the
/// filesystem trust store.
pub fn webpki_roots() -> Result<Vec<reqwest::Certificate>> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|der| {
            reqwest::Certificate::from_der(der.as_ref())
                .map_err(|e| Error::Config(format!("failed to parse compiled-in root CA: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webpki_roots_parse_and_are_nonempty() {
        let roots = webpki_roots().expect("compiled-in roots should always parse");
        assert!(
            !roots.is_empty(),
            "expected at least one compiled-in Mozilla root CA"
        );
    }

    #[test]
    fn webpki_roots_build_a_working_tls_certs_only_client() {
        let roots = webpki_roots().expect("compiled-in roots should always parse");
        reqwest::Client::builder()
            .tls_certs_only(roots)
            .build()
            .expect("client should build with compiled-in-only roots");
    }
}
