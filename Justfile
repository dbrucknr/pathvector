# pathvector task runner — install just with `cargo install just`
# Usage: just <recipe>   |   just --list

# cargo-fuzz hardcodes Command::new("cargo") — it never reads the CARGO env
# var. The only reliable fix is to put the nightly bin dir first in PATH so
# that "cargo" resolves to nightly before Homebrew's stable binary.
#
# `rustup which` is the platform-independent way to locate the real nightly
# binary regardless of what `cargo` points to in PATH. Backtick variables are
# lazy — evaluated only when a recipe that uses them is invoked, so running
# `just test` never requires nightly to be installed.
nightly-bin    := `rustup which --toolchain nightly cargo | xargs dirname`
cargo-fuzz-bin := `which cargo-fuzz`

# Show available recipes
default:
    @just --list

# ── Local interop (GoBGP + pathvectord, no Docker) ────────────────────────────

# Start GoBGP for local interop testing (non-privileged ports, no sudo).
# Reads gobgp.toml from the workspace root.
gobgp-up:
    gobgpd -f gobgp.toml

# Start pathvectord against the local interop config (config.toml).
dev:
    cargo run -p pathvectord -- config.toml

# Open the live TUI dashboard pointed at the local dev daemon.
dashboard:
    cargo run -p pathvector -- --address http://127.0.0.1:50052 dashboard

# Run any pathvector CLI command against the local dev daemon.
# Usage: just pv route list   |   just pv peer list   |   just pv watch routes
pv *args:
    cargo run -q -p pathvector -- --address http://127.0.0.1:50052 {{args}}

# Run the simulated BGP exchange (gobgp-up + dev must already be running).
exchange:
    ./scripts/exchange.sh

# ── Standard suite ────────────────────────────────────────────────────────────

# Run every check that CI runs, in the same order.  Green here = green on push.
# Note: e2e is not included here — run `just e2e` separately (requires Docker).
ci: test lint fmt-check doc msrv

# Run the full test suite (excludes pathvector-e2e, which requires Docker images)
test:
    cargo test --workspace --exclude pathvector-e2e

# Test against the minimum supported Rust version (mirrors the msrv CI job)
msrv:
    rustup run 1.88 cargo test --workspace --exclude pathvector-e2e

# Configure git to use the committed hooks in .githooks/.
# Run once after cloning: just install-hooks
install-hooks:
    git config core.hooksPath .githooks
    @echo "Hooks installed. The pre-push hook will run 'just e2e' before each push."
    @echo "Skip with: git push --no-verify"

# Clippy across all targets (warnings promoted to errors, matching CI)
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Run clippy inside a Linux/amd64 container — matches CI exactly and catches
# #[cfg(target_os = "linux")] warnings invisible on macOS. Requires Docker.
# Use before pushing if you touched any Linux-gated code.
# First run is slow (image pull + full compile); subsequent runs reuse the cache.
lint-linux:
    docker run --rm \
        --platform linux/amd64 \
        -v "{{justfile_directory()}}:/workspace" \
        -w /workspace \
        -e CARGO_HOME=/workspace/.cargo-linux-cache \
        rust:latest \
        sh -c "apt-get update -qq && apt-get install -y -qq protobuf-compiler > /dev/null \
            && rustup component add clippy \
            && cargo clippy --workspace --all-targets -- -D warnings"

# Verify rustfmt formatting (does not modify files)
fmt-check:
    cargo fmt --check

# Build documentation and fail on any warning
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# ── End-to-end ────────────────────────────────────────────────────────────────

# GoBGP version embedded in the gobgpd Docker image.
gobgp-version := "4.6.0"

# Build the gobgpd test image.
# GoBGP only ships Linux binaries, so both images are always Linux containers.
# On Apple Silicon, Docker Desktop runs a native linux/arm64 VM — no QEMU.
_build-gobgpd-image:
    #!/usr/bin/env bash
    set -euo pipefail
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    echo "Building pathvector-gobgpd-test:latest (linux/${ARCH})..."
    docker build \
        --build-arg TARGETARCH="${ARCH}" \
        --build-arg GOBGP_VERSION={{gobgp-version}} \
        -f e2e/Dockerfile \
        -t pathvector-gobgpd-test:latest \
        .

# Build the pathvectord test image (multi-stage Rust build inside Docker).
_build-pathvectord-image:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building pathvector-e2e:latest..."
    docker build \
        -f e2e/Dockerfile.pathvectord \
        -t pathvector-e2e:latest \
        .

# Build both test images (idempotent — Docker layer cache keeps rebuilds fast).
e2e-images: _build-gobgpd-image _build-pathvectord-image

# Run end-to-end tests.
# Both gobgpd and pathvectord run as Docker containers on an isolated bridge
# network per test.  BGP is container-to-container — the macOS Docker Desktop
# TCP proxy never touches it.  Only pathvectord's gRPC port is mapped to the
# host (for PathvectorClient), and HTTP/2 is unaffected by the proxy.
e2e: e2e-images
    cargo test -p pathvector-e2e -- --test-threads=1 --nocapture

# Start the compose dev environment (manual inspection / debugging).
e2e-up:
    #!/usr/bin/env bash
    set -euo pipefail
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
        docker compose -f e2e/docker-compose.yml up --build -d

# Stop and remove the compose dev environment.
e2e-down:
    docker compose -f e2e/docker-compose.yml down

# Stream logs from the compose dev environment.
e2e-logs:
    docker compose -f e2e/docker-compose.yml logs -f

# ── Fuzz ──────────────────────────────────────────────────────────────────────

# Compile all fuzz targets (no fuzzing — fast compile check)
fuzz-build:
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} build

# Smoke-run every target for 60 s each — used by CI
fuzz-smoke: fuzz-build
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} run session_framing fuzz/corpus/session_framing -- -max_total_time=60
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} run session_message fuzz/corpus/session_message -- -max_total_time=60

# Extended fuzzing of the framing decode path — runs until Ctrl-C, grows corpus
fuzz-framing corpus="fuzz/corpus/session_framing":
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} run session_framing {{corpus}}

# Extended fuzzing of the message decode path — runs until Ctrl-C, grows corpus
fuzz-message corpus="fuzz/corpus/session_message":
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} run session_message {{corpus}}
