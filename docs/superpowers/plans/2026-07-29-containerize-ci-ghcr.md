# Containerize + CI + GHCR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Public `/healthz`, a musl→scratch Docker image, GitHub CI (test on PR/main), and a release workflow publishing to GHCR.

**Architecture:** `/healthz` mounted outside auth in `build_router` (all modes). Multi-stage Dockerfile builds a static musl binary into `scratch`. Two GH workflows: `ci.yml` (fmt/clippy/test), `release.yml` (buildx → ghcr.io, tag via metadata-action).

**Tech Stack:** existing Rust crate + Docker/buildx + GitHub Actions (`Swatinem/rust-cache`, `docker/{login,metadata,build-push}-action`).

**Reference spec:** `docs/superpowers/specs/2026-07-29-containerize-ci-ghcr-design.md`.
**Branch:** `feat/deploy`, stacked on `feat/auth-modes`.

---

## Task D0: `/healthz` endpoint (all modes)

**Files:** `src/auth/metadata.rs`

- [ ] **Step 1: Add the handler + route in `build_router` for ALL modes.**
Add:
```rust
pub async fn healthz() -> &'static str { "ok" }
```
Rework `build_router` so a public `/healthz` route exists in every mode, never behind `require_auth`. Target shape (reconcile axum 0.8 state generics with the compiler — follow the existing working pattern):
```rust
pub fn build_router(protected: Router<()>, auth: Option<AuthState>) -> Router {
    use axum::routing::get;
    let public = Router::new().route("/healthz", get(healthz)); // Router<()>
    match auth {
        None => public.merge(protected), // none mode: health + open /mcp
        Some(state) => {
            let gated = protected
                .route_layer(axum::middleware::from_fn_with_state(state.clone(), require_auth));
            let public = if state.jwt_mode {
                public.route("/.well-known/oauth-protected-resource", get(prm_handler))
            } else {
                public
            };
            public.merge(gated).with_state(state)
        }
    }
}
```
Keep `route_layer` (gates `/mcp` + subpaths; leaves `/healthz` and unmatched paths untouched).

- [ ] **Step 2: Tests — `/healthz` is public in all three modes.**
Extend `build_router_tests`:
```rust
#[tokio::test]
async fn healthz_is_public_in_all_modes() {
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    for app in [
        build_router(dummy(), None),
        build_router(dummy(), Some(state(false).await)), // token
        build_router(dummy(), Some(state(true).await)),  // jwt
    ] {
        let r = app.oneshot(HttpRequest::get("/healthz").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }
}
```
(Reuse the existing `dummy()`/`state()` helpers. If `dummy()`/`state()` are private to the module, they're in scope.)

- [ ] **Step 3: Verify + commit.**
Run: `cargo test --lib auth::` (all pass incl. new), `cargo clippy --all-targets -- -D warnings` (clean), and confirm the existing per-mode gating tests still pass (healthz must NOT break `/mcp` gating).
```bash
git add src/auth/metadata.rs
git commit -m "feat: public /healthz endpoint (all auth modes)"
```

---

## Task D1: Dockerfile (musl → scratch)

**Files:** `Dockerfile`, `.dockerignore`

- [ ] **Step 1: `.dockerignore`**
```
target/
.git/
docs/
*.md
.github/
```

- [ ] **Step 2: Write the multi-stage Dockerfile.**
Starting point (ADAPT after verifying the two gotchas below):
```dockerfile
# ---- builder ----
FROM rust:1.94-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /app
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN strip target/x86_64-unknown-linux-musl/release/mcp-caldav-fastmail || true

# ---- runtime ----
FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/mcp-caldav-fastmail /mcp-caldav-fastmail
# CA roots for outbound Fastmail TLS (see gotcha #1):
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
EXPOSE 8080
ENTRYPOINT ["/mcp-caldav-fastmail"]
```

- [ ] **Step 3: VERIFY gotcha #1 — outbound TLS root certs on scratch.**
Determine how reqwest's `rustls` feature (this crate: `reqwest = { default-features = false, features = ["rustls"] }`) sources trust roots:
- Inspect `~/.cargo/registry/src/*/reqwest-0.13*/` features. If `rustls` maps to the platform/native verifier, the `SSL_CERT_FILE` + copied `ca-certificates.crt` approach works. If it needs `webpki-roots`, EITHER add the reqwest feature that bundles webpki-roots (compile-in, drop the CA COPY) OR keep the CA-file approach with `rustls-tls-native-roots`.
- **Prove it:** after `docker build`, run the container in `none` mode with a dummy Fastmail account and attempt an operation that forces a TLS handshake to `caldav.fastmail.com` (it will fail auth with 401 from Fastmail, but a TLS/cert failure looks different — a cert error means roots are missing). At minimum, confirm the process starts and the reqwest client builds without panicking, and document the reasoning for why TLS will succeed. If uncertain, prefer the compile-in webpki-roots route (most robust on scratch).

- [ ] **Step 4: VERIFY gotcha #2 — TZID zone data on scratch.**
Check whether calcard's `Tz::from_str` resolution needs `/usr/share/zoneinfo` or uses compiled-in data:
- `find ~/.cargo/registry/src -maxdepth 2 -type d -name 'calcard-*'` and inspect its tz handling / deps (does it pull `chrono-tz` or read files?).
- If it needs files, add `COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo` (or a minimal subset) to the runtime stage. If compiled-in, no action.
- Document the finding.

- [ ] **Step 5: FALLBACK decision.**
If either gotcha can't be cleanly resolved on `scratch`, switch the runtime stage to `FROM gcr.io/distroless/static-debian12` (bundles CA certs + tzdata) and drop the manual COPYs. Record which base was used and why in the commit message + README.

- [ ] **Step 6: Build + smoke.**
```bash
docker build -t mcp-caldav-fastmail:local .
docker run -d --rm -p 8080:8080 -e AUTH_MODE=none -e FASTMAIL_USERNAME=x -e FASTMAIL_APP_PASSWORD=y --name mcptest mcp-caldav-fastmail:local
sleep 2
curl -s -o /dev/null -w "healthz: %{http_code}\n" http://127.0.0.1:8080/healthz   # expect 200
docker rm -f mcptest
docker images mcp-caldav-fastmail:local --format "size: {{.Size}}"
```
Expect `/healthz` → 200; record image size.

- [ ] **Step 7: Commit.**
```bash
git add Dockerfile .dockerignore
git commit -m "build: multi-stage musl->scratch Dockerfile (+ CA roots / tz as needed)"
```

---

## Task D2: CI workflow (test on PR + main)

**Files:** `.github/workflows/ci.yml`

- [ ] **Step 1: Write `ci.yml`.**
```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test
```
(Pin action major versions as shown. `dtolnay/rust-toolchain@stable` is fine; if the crate needs a specific version for `edition 2024`, use `@master` with `toolchain: 1.94.0` or a `rust-toolchain.toml`.)

- [ ] **Step 2: Validate YAML locally.**
Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo OK` (or any YAML linter available). Ensure it parses.

- [ ] **Step 3: Commit.**
```bash
git add .github/workflows/ci.yml
git commit -m "ci: fmt/clippy/test on PR and main"
```

---

## Task D3: Release workflow (publish to GHCR)

**Files:** `.github/workflows/release.yml`

- [ ] **Step 1: Write `release.yml`.**
```yaml
name: release
on:
  push:
    branches: [main]
    tags: ['v*']
permissions:
  contents: read
  packages: write
jobs:
  image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/astromechza/mcp-caldav-fastmail
          tags: |
            type=raw,value=latest,enable=${{ github.ref == 'refs/heads/main' }}
            type=sha,prefix=sha-,enable=${{ github.ref == 'refs/heads/main' }}
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
      - uses: docker/build-push-action@v6
        with:
          context: .
          platforms: linux/amd64
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

- [ ] **Step 2: Validate YAML parses** (same as D2 Step 2 for this file).

- [ ] **Step 3: Commit.**
```bash
git add .github/workflows/release.yml
git commit -m "ci: publish image to GHCR on main + version tags"
```

---

## Task D4: README deploy section + final verification

**Files:** `README.md`

- [ ] **Step 1: Add a Deployment section.**
Document: `docker build -t mcp-caldav-fastmail .`; `docker run -p 8080:8080 -e AUTH_MODE=... -e FASTMAIL_USERNAME=... -e FASTMAIL_APP_PASSWORD=... mcp-caldav-fastmail`; pull `docker pull ghcr.io/astromechza/mcp-caldav-fastmail:latest`; the `/healthz` liveness probe; a note that the first GHCR publish may need the package made public / linked to the repo once in GHCR settings; and a short Scaleway pointer (private container + `X-Auth-Token` edge or `AUTH_MODE=none`; Terraform is a later chunk). State which runtime base image was used (scratch or distroless) and why.

- [ ] **Step 2: Full verification.**
```bash
cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
docker build -t mcp-caldav-fastmail:local .
docker run -d --rm -p 8080:8080 -e AUTH_MODE=token -e MCP_TOKEN=$(python3 -c "print('a'*40)") -e FASTMAIL_USERNAME=x -e FASTMAIL_APP_PASSWORD=y --name mcptest mcp-caldav-fastmail:local
sleep 2
curl -s -o /dev/null -w "healthz: %{http_code}\n" http://127.0.0.1:8080/healthz
curl -s -o /dev/null -w "mcp noauth: %{http_code}\n" http://127.0.0.1:8080/mcp
curl -s -o /dev/null -w "mcp authed: %{http_code}\n" -H "Authorization: Bearer $(python3 -c "print('a'*40)")" http://127.0.0.1:8080/mcp
docker rm -f mcptest
```
Expect: healthz 200, mcp noauth 401, mcp authed not-401. All cargo checks green.

- [ ] **Step 3: Commit.**
```bash
git add README.md
git commit -m "docs: deployment (Docker + GHCR) section"
```

---

## Self-Review (against spec)

- §2 `/healthz` all modes: D0. ✓
- §3 Dockerfile musl→scratch + CA/tz gotchas + fallback: D1. ✓
- §4 ci.yml fmt/clippy/test: D2. ✓
- §5 release.yml GHCR main+tags, amd64, metadata tags: D3. ✓
- §6 README + verification: D4. ✓
- §7 deferred (Scaleway TF, arm64): not in plan. ✓

**Volatile/verify spots:** reqwest rustls trust-root source on scratch (D1 S3), calcard tz data on scratch (D1 S4), axum 0.8 state generics in the reworked `build_router` (D0 S1), GH Action major versions (D2/D3).
