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
    RUST_LOG=pathvectord=debug,pathvector_session=debug cargo run -p pathvectord -- config.toml

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
ci: check-test-bins test lint lint-linux fmt-check doc msrv

# Guards against a `[[bin]]` (including auto-discovered src/bin/*.rs targets)
# that Cargo will treat as testable (the `test` field defaults to `true`) but
# isn't a real test harness. Without an explicit `test = false`, `cargo test`/
# `cargo nextest run` invoke the compiled binary with `--list --format terse`
# during discovery; if the binary's real `main` doesn't understand that flag
# and does real work unconditionally (spawns a server, connects somewhere,
# runs a workload), the whole test run hangs indefinitely with no error
# output. This bit `pathvector-stress`'s `stress` binary and
# `pathvector-e2e`'s `mock_rtr_server`/`mock_bgp_peer` (see CHANGELOG.md
# 2026-07-04) before `test = false` was added to each. Runs in seconds —
# purely `cargo metadata` + a grep, no compilation.
#
# Lives in scripts/ rather than inline so CI can call it directly with plain
# bash — invoking it via `just` would eagerly evaluate every top-level
# backtick-assigned Justfile variable, including nightly-bin/cargo-fuzz-bin
# (used only by the fuzz recipes), which fail on a runner that hasn't
# installed cargo-fuzz/nightly.
check-test-bins:
    ./scripts/check-test-bins.sh

# nextest runs each test in its own process for much better parallelism than
# the built-in harness, but it does not support doctests, so those still run
# as a second, separate step. Requires cargo-nextest — see CONTRIBUTING.md.
# Run the full test suite (excludes pathvector-e2e, which requires Docker images)
test:
    cargo nextest run --workspace --exclude pathvector-e2e
    cargo test --workspace --exclude pathvector-e2e --doc

# Uses a separate target dir (target/msrv) so this never shares build
# artifacts with `just test`'s stable-toolchain target/debug — cargo's
# fingerprints include the exact rustc version, so alternating toolchains
# against one shared target dir forces a full workspace rebuild (all ~150+
# dependencies) on every switch. Costs extra disk space; the first run into
# target/msrv is still a full cold build, but every run after that is
# incremental, matching `just test`'s speed instead of always paying ~19 min.
# Test against the minimum supported Rust version (mirrors the msrv CI job)
msrv:
    CARGO_TARGET_DIR=target/msrv rustup run 1.88 cargo nextest run --workspace --exclude pathvector-e2e
    CARGO_TARGET_DIR=target/msrv rustup run 1.88 cargo test --workspace --exclude pathvector-e2e --doc

# Configure git to use the committed hooks in .githooks/.
# Run once after cloning: just install-hooks
install-hooks:
    git config core.hooksPath .githooks
    @echo "Hooks installed. The pre-push hook will run 'just e2e' before each push."
    @echo "Skip with: git push --no-verify"

# Clippy across all targets (warnings promoted to errors, matching CI)
# pathvector-e2e is excluded here (matching test/msrv) since it pulls in
# testcontainers, a heavy compile-time dependency, for no benefit -- e2e code
# still gets linted, just as part of `just e2e` below where the Docker/compile
# cost is already being paid.
lint:
    cargo clippy --workspace --exclude pathvector-e2e --all-targets -- -D warnings -A clippy::similar_names

# Run clippy inside a Linux container — catches #[cfg(target_os = "linux")]
# warnings invisible on macOS. Requires Docker.
#
# Two named volumes are kept across runs:
#   pathvector-linux-cargo  — crate registry (downloaded once, stays on Linux FS)
#   pathvector-linux-target — compiled artifacts (incremental builds, Linux FS)
#
# Source is mounted read-only; CARGO_TARGET_DIR redirects build output to the
# named volume, keeping Docker Desktop's slow macOS-FS I/O out of the hot path.
#
# First run: ~5–10 min (image pull + compile all deps).
# Subsequent runs: ~30 s (incremental, cache warm).
lint-linux:
    docker run --rm \
        --platform linux/amd64 \
        -v "{{justfile_directory()}}:/workspace:ro" \
        -v pathvector-linux-cargo:/usr/local/cargo/registry \
        -v pathvector-linux-target:/target \
        -w /workspace \
        -e CARGO_TARGET_DIR=/target \
        rust:1.88-slim \
        sh -c "apt-get update -qq && apt-get install -y -qq protobuf-compiler make >/dev/null \
            && rustup component add clippy 2>/dev/null \
            && cargo clippy --workspace --exclude pathvector-e2e --all-targets -- -D warnings \
                -A clippy::similar_names"

# Verify rustfmt formatting (does not modify files)
fmt-check:
    cargo fmt --check

# Build documentation and fail on any warning
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# Build the mdBook user guide (output in book/)
docs-build:
    mdbook build

# Serve the mdBook guide with live reload at http://localhost:3000
docs-serve:
    mdbook serve --open

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
        -f pathvector-e2e/Dockerfile \
        -t pathvector-gobgpd-test:latest \
        .

# Build the pathvectord test image (multi-stage Rust build inside Docker).
# Shares its builder stage with the three mock-* images below (all four
# binaries are compiled in one `cargo build` — see Dockerfile.pathvectord's
# header comment), so build this one first for the others to reuse its cache.
_build-pathvectord-image:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building pathvector-e2e:latest..."
    docker build \
        --target pathvectord \
        -f pathvector-e2e/Dockerfile.pathvectord \
        -t pathvector-e2e:latest \
        .

# Build the BIRD 2 test image (Alpine + bird2 package).
_build-bird-image:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building pathvector-bird-test:latest..."
    docker build \
        -f pathvector-e2e/Dockerfile.bird \
        -t pathvector-bird-test:latest \
        pathvector-e2e/

_build-frr-image:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building pathvector-frr-test:latest..."
    docker build \
        -f pathvector-e2e/Dockerfile.frr \
        -t pathvector-frr-test:latest \
        pathvector-e2e/

# Build the mock RTR server test image — shares Dockerfile.pathvectord's
# builder stage, so this reuses the compile from _build-pathvectord-image
# almost for free instead of recompiling the workspace.
_build-mock-rtr-image:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building pathvector-mock-rtr-test:latest..."
    docker build \
        --target mock-rtr \
        -f pathvector-e2e/Dockerfile.pathvectord \
        -t pathvector-mock-rtr-test:latest \
        .

# Build the mock BGP peer test image — shares Dockerfile.pathvectord's
# builder stage (see _build-mock-rtr-image).
_build-mock-bgp-peer-image:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building pathvector-mock-bgp-peer-test:latest..."
    docker build \
        --target mock-bgp-peer \
        -f pathvector-e2e/Dockerfile.pathvectord \
        -t pathvector-mock-bgp-peer-test:latest \
        .

# Build the mock BGP dialer test image — shares Dockerfile.pathvectord's
# builder stage (see _build-mock-rtr-image).
_build-mock-bgp-dialer-image:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building pathvector-mock-bgp-dialer-test:latest..."
    docker build \
        --target mock-bgp-dialer \
        -f pathvector-e2e/Dockerfile.pathvectord \
        -t pathvector-mock-bgp-dialer-test:latest \
        .

# Build the mock BGP fault-peer test image — shares Dockerfile.pathvectord's
# builder stage (see _build-mock-rtr-image).
_build-mock-bgp-fault-peer-image:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building pathvector-mock-bgp-fault-peer-test:latest..."
    docker build \
        --target mock-bgp-fault-peer \
        -f pathvector-e2e/Dockerfile.pathvectord \
        -t pathvector-mock-bgp-fault-peer-test:latest \
        .

# Build the mock BGP collision-peer test image — shares Dockerfile.pathvectord's
# builder stage (see _build-mock-rtr-image).
_build-mock-bgp-collision-peer-image:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building pathvector-mock-bgp-collision-peer-test:latest..."
    docker build \
        --target mock-bgp-collision-peer \
        -f pathvector-e2e/Dockerfile.pathvectord \
        -t pathvector-mock-bgp-collision-peer-test:latest \
        .

# Build all test images (idempotent — Docker layer cache keeps rebuilds fast).
e2e-images: _build-gobgpd-image _build-pathvectord-image _build-bird-image _build-frr-image _build-mock-rtr-image _build-mock-bgp-peer-image _build-mock-bgp-dialer-image _build-mock-bgp-fault-peer-image _build-mock-bgp-collision-peer-image

# Run end-to-end tests.
# Both gobgpd and pathvectord run as Docker containers on an isolated bridge
# network per test.  BGP is container-to-container — the macOS Docker Desktop
# TCP proxy never touches it.  Only pathvectord's gRPC port is mapped to the
# host (for PathvectorClient), and HTTP/2 is unaffected by the proxy.
#
# Each test allocates its own bridge network name and host ports
# (alloc_grpc_port/alloc_metrics_port), so tests are safe to run concurrently —
# CI already does (`--test-threads=4`). --test-threads=8 here assumes a
# reasonably powerful local machine; lower it if Docker Desktop's resource
# limits make runs flaky. Requires cargo-nextest — see CONTRIBUTING.md.
# Run end-to-end tests against Docker containers (requires Docker + cargo-nextest)
e2e: e2e-images
    cargo clippy -p pathvector-e2e --all-targets -- -D warnings
    cargo nextest run -p pathvector-e2e --test-threads 8

# Start the compose dev environment (manual inspection / debugging).
e2e-up:
    #!/usr/bin/env bash
    set -euo pipefail
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
        docker compose -f pathvector-e2e/docker-compose.yml up --build -d

# Stop and remove the compose dev environment.
e2e-down:
    docker compose -f pathvector-e2e/docker-compose.yml down

# Stream logs from the compose dev environment.
e2e-logs:
    docker compose -f pathvector-e2e/docker-compose.yml logs -f

# ── Stress ────────────────────────────────────────────────────────────────────

# Run the full-table stress harness (Stage 1 — no Docker required).
# Builds pathvectord and the stress binary in debug mode, then runs all phases:
#   - pathvectord: originate 10k / 100k / 500k routes, measure time + RSS
#   - withdrawal: withdraw all 500k, check RSS reclamation
#   - churn: 5× announce/withdraw cycles of 10k routes, check for RSS growth
#   - GoBGP 1:1 comparison: same phases against gobgpd via AddPathStream
#
# Prerequisites: protoc on PATH (brew install protobuf).
# GoBGP comparison also requires: gobgpd 4.x on PATH or in $GOPATH/bin.
# See pathvector-stress/README.md for full documentation.
stress:
    cargo build -p pathvectord -p pathvector-stress
    cargo run -p pathvector-stress --bin stress

# Same as `stress` but with release builds — use this for numbers worth recording.
stress-release:
    cargo build --release -p pathvectord -p pathvector-stress
    ./target/release/stress

# ── MRT replay ───────────────────────────────────────────────────────────────

# Replay an MRT TABLE_DUMP_V2 file against a running pathvectord (Stage 2 benchmark).
#
# Requires an MRT file (RouteViews or RIPE RIS RIB dump).  Download one with:
#   curl -O https://data.ris.ripe.net/rrc00/latest-bview.gz
#
# Starts pathvectord on port 1179 (non-privileged) and the MRT replayer, then
# prints convergence time, throughput, and final RIB prefix count.
#
# Usage:
#   just mrt ./latest-bview.gz
mrt mrt_file='':
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{mrt_file}}" ]; then
        echo "Usage: just mrt ./latest-bview.gz"
        exit 1
    fi
    cargo build --release -p pathvectord -p pathvector-mrt
    # Kill any leftover pathvectord holding port 1179 or 51200 from a previous run.
    pkill -x pathvectord 2>/dev/null || true
    sleep 0.3
    echo "Starting pathvectord on port 1179..."
    ./target/release/pathvectord pathvector-e2e/fixtures/mrt-pathvectord.toml &
    PVDPID=$!
    trap "kill $PVDPID 2>/dev/null || true" EXIT
    sleep 1
    ./target/release/pathvector-mrt --mrt "{{mrt_file}}" --peer 127.0.0.1:1179

# ── Fuzz ──────────────────────────────────────────────────────────────────────

# Compile all fuzz targets (no fuzzing — fast compile check)
fuzz-build:
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} build --fuzz-dir pathvector-fuzz

# Smoke-run every target for 60 s each — used by CI.
# Corpus dirs aren't committed (see .gitignore) — cargo-fuzz errors if the
# target directory doesn't exist, so create it on a fresh clone / cache miss.
fuzz-smoke: fuzz-build
    mkdir -p pathvector-fuzz/corpus/session_framing pathvector-fuzz/corpus/session_message pathvector-fuzz/corpus/rtr_pdu
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} run --fuzz-dir pathvector-fuzz session_framing pathvector-fuzz/corpus/session_framing -- -max_total_time=60
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} run --fuzz-dir pathvector-fuzz session_message pathvector-fuzz/corpus/session_message -- -max_total_time=60
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} run --fuzz-dir pathvector-fuzz rtr_pdu pathvector-fuzz/corpus/rtr_pdu -- -max_total_time=60

# Extended fuzzing of the framing decode path — runs until Ctrl-C, grows corpus
fuzz-framing corpus="pathvector-fuzz/corpus/session_framing":
    mkdir -p {{corpus}}
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} run --fuzz-dir pathvector-fuzz session_framing {{corpus}}

# Extended fuzzing of the message decode path — runs until Ctrl-C, grows corpus
fuzz-message corpus="pathvector-fuzz/corpus/session_message":
    mkdir -p {{corpus}}
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} run --fuzz-dir pathvector-fuzz session_message {{corpus}}

# Extended fuzzing of the RTR PDU decode path — runs until Ctrl-C, grows corpus
fuzz-rtr-pdu corpus="pathvector-fuzz/corpus/rtr_pdu":
    mkdir -p {{corpus}}
    PATH="{{nightly-bin}}:$PATH" {{cargo-fuzz-bin}} run --fuzz-dir pathvector-fuzz rtr_pdu {{corpus}}
