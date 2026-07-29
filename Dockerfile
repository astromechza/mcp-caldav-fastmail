# syntax=docker/dockerfile:1
#
# Multi-stage glibc -> distroless build for mcp-caldav-fastmail.
#
# Why glibc+distroless and not static-musl+scratch (the original goal):
#   rustls (0.23, via reqwest and the jwks crate) uses the `aws-lc-rs` crypto
#   provider by default, whose `aws-lc-sys` build compiles BoringSSL C + asm.
#   That C/asm does NOT cross-compile under `musl-gcc` (fails with
#   `cc1: error: unrecognized command-line option '-m64'`), and because the
#   `jwks` crate pulls its own rustls, forcing the pure-Rust `ring` provider
#   across the whole tree isn't clean either. Building natively for glibc
#   sidesteps the cross-compile entirely; `gcr.io/distroless/cc-debian12`
#   gives a small runtime with glibc + libgcc (needed for the Rust unwinder) +
#   CA certificates + tzdata and no shell/package manager. (The smaller
#   `base-debian12` lacks `libgcc_s.so.1` and the binary fails to start on it;
#   `panic = "abort"` would avoid that but a per-request panic would then abort
#   the whole server, so we keep unwinding and use the `cc` image.)
#   Verified: `podman build` + run + /healthz + token-auth smoke.
#
# TLS roots: the binary also compiles in Mozilla roots via `webpki-root-certs`
# and pins both reqwest clients to them with `tls_certs_only` (see src/tls.rs),
# so trust does not depend on the image's filesystem regardless of base image.
# Timezone data for calcard TZID resolution is compiled in via chrono-tz.

# Pin the builder to bookworm so its glibc matches distroless/cc-debian12
# (also bookworm, glibc 2.36). The default `-slim` (Debian trixie, glibc 2.38+)
# produces a binary that fails on the older runtime with
# `libc.so.6: version 'GLIBC_2.38' not found`. `rust:1-slim-bookworm` tracks the
# latest Rust 1.x while staying on bookworm.
FROM rust:1-slim-bookworm AS builder
# aws-lc-sys (BoringSSL) needs a C toolchain + cmake to build.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake perl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release --locked
# --locked: build the exact Cargo.lock deps and fail fast if it drifts from
# Cargo.toml, so published images are reproducible.
# Symbol stripping via [profile.release] strip = true in Cargo.toml.

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/mcp-caldav-fastmail /mcp-caldav-fastmail
EXPOSE 8080
ENTRYPOINT ["/mcp-caldav-fastmail"]
