# syntax=docker/dockerfile:1
#
# Multi-stage musl -> scratch build for mcp-caldav-fastmail.
#
# NOTE: this Dockerfile has NOT been built locally (Docker is not available in
# the environment that authored it). It was written and reasoned about by:
#   - reading reqwest/webpki-root-certs/rustls-platform-verifier/calcard/
#     chrono-tz source in ~/.cargo/registry to resolve the two `scratch`
#     "gotchas" below (TLS trust roots, tz database) without being able to
#     runtime-test them, and
#   - a native `cargo build --release` plus a best-effort
#     `cargo build --release --target x86_64-unknown-linux-musl` (the latter
#     failed locally for lack of an `x86_64-linux-musl-gcc` cross-linker,
#     which is expected on a plain macOS dev machine and is NOT evidence the
#     musl build itself is broken).
# The actual `docker build` of this file -- and therefore final proof the
# image runs -- is validated by the GitHub `release` workflow (a later task),
# not locally. Treat this image as unverified until that workflow succeeds.
#
# ---------------------------------------------------------------------------
# Gotcha #1: outbound TLS trust roots on `scratch` (no cert store at all)
#
# reqwest 0.13's `rustls` feature no longer has a `rustls-tls-webpki-roots`
# Cargo feature (that existed in 0.12). It now verifies certificates via
# `rustls-platform-verifier`, which on Linux loads root certs from the
# filesystem at *runtime* (`rustls-native-certs`, honoring `SSL_CERT_FILE`/
# `SSL_CERT_DIR`, else falling back to paths like
# `/etc/ssl/certs/ca-certificates.crt`) -- and returns an error if none are
# found. On bare `scratch` that means TLS client construction would fail.
#
# Fix (in application code, not just Cargo features -- see `src/tls.rs`):
# both `reqwest::Client`s this crate builds (the CalDAV client in
# `src/caldav/client.rs`, and the JWKS-fetching client in
# `src/auth/validator.rs`) compile Mozilla's root CA list into the binary via
# the `webpki-root-certs` crate and pin themselves to *only* those roots via
# `ClientBuilder::tls_certs_only(...)`, bypassing rustls-platform-verifier's
# filesystem read entirely. Both of our reqwest clients are constructed by us
# (the `jwks` crate's own JWKS fetch is called with our client injected via
# `from_jwks_url_with_client`, so no separate uncontrolled reqwest client is
# in play) -- there is no known TLS gap for any of none/static-PEM/JWKS-URL
# JWT modes.
#
# Belt-and-suspenders: we still copy the builder's CA bundle into the image
# and set SSL_CERT_FILE below. It is not required by our own HTTP clients
# (which never consult the filesystem, per the above), but it's a harmless
# safety net for any future dependency that builds its own reqwest/rustls
# client without going through `crate::tls::webpki_roots()`.
#
# Rustls-only is preserved: `cargo tree | grep -iE 'openssl|native-tls'` is
# empty after these changes.
#
# ---------------------------------------------------------------------------
# Gotcha #2: calcard TZID/zone data on `scratch`
#
# calcard resolves TZIDs via `chrono-tz` (`chrono_tz::Tz`, e.g.
# `chrono_tz::Europe__London`). chrono-tz ships prebuilt static tables
# (`src/prebuilt` in the chrono-tz source) generated from the IANA tz
# database at chrono-tz's own build/publish time -- it never reads
# `/usr/share/zoneinfo` or any other file at build OR run time. No zoneinfo
# files need to be copied into the runtime stage.
# ---------------------------------------------------------------------------

FROM rust:1.94-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /app
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl
# Symbol stripping is handled by `[profile.release] strip = true` in Cargo.toml
# (no external binutils `strip` needed in the builder image).

FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/mcp-caldav-fastmail /mcp-caldav-fastmail
# Belt-and-suspenders only -- see Gotcha #1 above. Our own HTTP clients are
# pinned to compiled-in webpki roots via `tls_certs_only` and never read this.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
# No zoneinfo COPY: calcard's TZID resolution (via chrono-tz) is fully
# compiled-in -- see Gotcha #2 above.
EXPOSE 8080
ENTRYPOINT ["/mcp-caldav-fastmail"]
