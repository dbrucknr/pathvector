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

# ── Standard suite ────────────────────────────────────────────────────────────

# Run every check that CI runs, in the same order.  Green here = green on push.
ci: test lint fmt-check doc msrv

# Run the full test suite
test:
    cargo test

# Test against the minimum supported Rust version (mirrors the msrv CI job)
msrv:
    rustup run 1.88 cargo test

# Clippy across all targets (warnings promoted to errors, matching CI)
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Verify rustfmt formatting (does not modify files)
fmt-check:
    cargo fmt --check

# Build documentation and fail on any warning
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# Check MSRV (mirrors the CI msrv job — requires `rustup toolchain install 1.88`)
msrv:
    rustup run 1.88 cargo test

# Run all CI checks locally: test · lint · fmt · doc · msrv
ci: test lint fmt-check doc msrv

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
