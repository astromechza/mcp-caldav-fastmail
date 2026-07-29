# Containerize + CI + GHCR — Design

**Date:** 2026-07-29
**Status:** Approved (pending spec review)
**Builds on:** `feat/auth-modes` (PR #2). Branch `feat/deploy` stacks on it.

## 1. Purpose

Ship the MCP server as a small container image, with GitHub Actions running
tests on every PR and publishing images to GHCR. Enables the Scaleway
scale-to-zero deploy (Terraform is a later chunk).

Decisions (locked): static-musl → scratch image; amd64 only; publish on push to
`main` (`latest` + `sha-<short>`) and on `v*` tags (semver); add a public
`/healthz` endpoint.

## 2. `/healthz` endpoint

A public, unauthenticated `GET /healthz` returning `200` with body `ok`, mounted
**outside** the auth layer in `build_router`, in **all** modes (jwt/token/none).
Rationale: every other route requires auth or returns 4xx, so orchestrators
(Scaleway, k8s, docker) have no clean liveness signal without this.

Implementation: add the route to the public side of `build_router` (merged
alongside — and in `none`/`token` modes, added to — the router, never behind
`require_auth`). One handler `async fn healthz() -> &'static str { "ok" }`.
Tests: `/healthz` → 200 without a token in each of the three modes (extend the
existing per-mode `build_router_tests`).

No Docker `HEALTHCHECK` instruction: scratch has no shell/curl to run one; the
platform probes `/healthz` over HTTP instead.

## 3. Dockerfile (multi-stage, musl → scratch)

**Builder stage** (`rust:1.94-slim` or the current toolchain image):
- `rustup target add x86_64-unknown-linux-musl`; install `musl-tools`.
- `cargo build --release --target x86_64-unknown-linux-musl`.
- Layer-cache deps (copy Cargo.toml/Cargo.lock, fetch, then copy src) — best
  effort; correctness first.

**Runtime stage** (`FROM scratch`):
- `COPY --from=builder` the static binary to `/mcp-caldav-fastmail`.
- `EXPOSE 8080`; `ENTRYPOINT ["/mcp-caldav-fastmail"]`.

**Two scratch gotchas that MUST be verified during implementation** (rustls, no
libc, empty filesystem):
1. **CA roots for outbound Fastmail TLS.** scratch ships no trust store.
   Determine what reqwest's `rustls` feature uses for roots in this build and
   make HTTPS to Fastmail actually work — either:
   - bundle roots at compile time (`webpki-roots`, via the appropriate reqwest
     feature), OR
   - `COPY --from=builder /etc/ssl/certs/ca-certificates.crt` into the image and
     set `SSL_CERT_FILE` / use `rustls-tls-native-roots`.
   Verify with a real run (a request that forces a TLS handshake to Fastmail, or
   at minimum confirm the client builds a verifier without panicking).
2. **Time-zone data for TZID resolution** (calcard). Confirm whether calcard's
   `Tz::from_str` uses compiled-in zone data (chrono-tz style — no files needed)
   or reads `/usr/share/zoneinfo`. If it needs files, `COPY` zoneinfo (or a
   minimal subset) into the image. Verify by running the existing TZID test path
   logic against the built binary, or reason from calcard's deps.

**Fallback:** if either gotcha can't be resolved cleanly on `scratch`, fall back
to `gcr.io/distroless/static-debian12` (bundles CA certs + tzdata, still tiny,
no shell). Document which was used and why.

`.dockerignore`: `target/`, `.git/`, `docs/`, `*.md` (except what the build
needs — nothing), local env files.

## 4. `.github/workflows/ci.yml` — test on PR + push

Triggers: `pull_request`, `push` to `main`. Job:
- checkout; install Rust (pin the toolchain, add `rustfmt`, `clippy`).
- cargo registry/target cache (e.g. `Swatinem/rust-cache`).
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`

No image build/publish here. This is the required status check.

## 5. `.github/workflows/release.yml` — publish image to GHCR

Triggers: `push` to `main`, and `push` tags `v*`.
`permissions: { contents: read, packages: write }`.
Steps:
- checkout
- `docker/login-action` → `ghcr.io` with `${{ github.actor }}` /
  `${{ secrets.GITHUB_TOKEN }}`
- `docker/metadata-action` for `ghcr.io/astromechza/mcp-caldav-fastmail`, tags:
  - on `main`: `latest`, `sha-<short>`
  - on tag `v1.2.3`: `1.2.3`, `1.2`, `latest`
- `docker/build-push-action`: `platforms: linux/amd64`, `push: true`, cache via
  GitHub Actions cache (`cache-from/to: type=gha`).

Package inherits repo visibility (public repo → public package). Note in README
that the first publish may need the package linked to the repo / made public in
GHCR settings once.

Optional (nice, not required): a lightweight "does the image run" smoke in the
release job — run the pushed image with dummy env in `none` mode and `curl`
`/healthz`. Keep it only if it doesn't complicate the job much.

## 6. README deploy section + verification

Add a **Deployment** section: how to build (`docker build`), run
(`docker run -p 8080:8080 -e ...`), pull from GHCR
(`docker pull ghcr.io/astromechza/mcp-caldav-fastmail:latest`), the `/healthz`
probe, and a short Scaleway pointer (private container + `X-Auth-Token` edge, or
`AUTH_MODE=none`; full Terraform is a later chunk).

Implementation verification (run locally):
- `docker build` succeeds; report final image size.
- `docker run` in `none` mode with dummy Fastmail env → `curl /healthz` = 200.
- one auth-mode smoke against the container (token mode: no-token → 401,
  right-token → not 401).

## 7. Out of scope / deferred

- Scaleway Terraform (`scaleway_container` private + IAM + secret env) — next
  chunk.
- Multi-arch (arm64) — amd64 only for now (Scaleway serverless is amd64).
- Signed images / SBOM / provenance attestation — could add later.
