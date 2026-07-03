# Contributing to pathvector

---

## Which crate do I edit?

| I want to add… | Edit these crates |
|---|---|
| A new path attribute (AS4_PATH, BGPsec, etc.) | `pathvector-types` → `pathvector-session` (codec) → `pathvector-rib` (RIB storage) → `pathvectord` (UPDATE handling) |
| A new gRPC RPC | `proto/pathvector/v1/management.proto` → `pathvectord/src/grpc.rs` → `pathvector-client/src/client_trait.rs` → `pathvector/src/` (CLI command) |
| A new policy condition or action | `pathvector-policy/src/` → update `pathvectord` if the daemon needs to apply it |
| A new BGP message type or capability | `pathvector-session/src/codec/` |
| A new Linux kernel integration (FIB, syscall) | `pathvector-sys/src/` → `pathvectord/src/daemon.rs` |
| A new CLI subcommand | `pathvector/src/` (uses `DaemonClient` trait; add mock test in same file) |
| A new daemon config field | `pathvectord/src/config.rs` → `pathvectord/README.md` (document it) |

---

This document covers the local development workflow, CI requirements, and known
pain points. Read it before your first pull request.

---

## Prerequisites

| Tool | Install | Notes |
|---|---|---|
| Rust (stable) | `rustup toolchain install stable` | Workspace MSRV is 1.88 |
| Rust 1.88 | `rustup toolchain install 1.88` | Required for `just msrv` |
| protoc | `brew install protobuf` | Required to compile gRPC proto files |
| just | `cargo install just` | Task runner; all recipes in `Justfile` |
| cargo-nextest | `cargo install cargo-nextest --locked` | Required for `just test`, `just msrv`, `just e2e` — see below |
| Docker | [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Required for `just e2e` and `just lint-linux` |

---

## Local workflow

```sh
just ci          # Run everything CI runs (except e2e): tests, lint, fmt, docs, MSRV
just e2e         # Run the Docker-based end-to-end suite (requires Docker)
just lint-linux  # Run clippy inside a Linux/amd64 container (see below)
```

### What `just ci` runs

```
cargo nextest run --workspace --exclude pathvector-e2e
cargo test --workspace --exclude pathvector-e2e --doc
cargo clippy --workspace --exclude pathvector-e2e --all-targets -- -D warnings
cargo fmt --check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
CARGO_TARGET_DIR=target/msrv rustup run 1.88 cargo nextest run --workspace --exclude pathvector-e2e
CARGO_TARGET_DIR=target/msrv rustup run 1.88 cargo test --workspace --exclude pathvector-e2e --doc
```

This catches the vast majority of issues before pushing. Run it before every
commit.

**`just msrv` uses a separate `target/msrv` directory**, not the same
`target/debug` that `just test` uses. Cargo's build fingerprints include the
exact rustc version, so alternating between the stable toolchain and 1.88
against one shared target directory forces a full workspace rebuild (all
~150+ dependencies) on every single switch — measured at ~19 minutes locally.
A separate target dir per toolchain avoids that entirely: the first `just
msrv` run is still a full cold build, but every run after that is
incremental and takes single-digit seconds, matching `just test`. This costs
extra disk space (`target/msrv` is a full second copy of the dependency
build artifacts) but is worth it if you run `just msrv` more than once.

---

## Why cargo-nextest

`just test`, `just msrv`, and `just e2e` run tests through
[cargo-nextest](https://nexte.st/) instead of the built-in `cargo test`
harness. nextest runs each test in its own process, which schedules across
CPU cores far more aggressively than `cargo test`'s in-binary thread pool —
on this workspace's ~1,100 unit/integration tests it's the difference between
several minutes and a few seconds of actual test-execution time. CI uses it
too (`.github/workflows/ci.yml`), so a slow local `cargo test` habit will look
noticeably slower than CI.

**Install once:** `cargo install cargo-nextest --locked`. Without it, `just
test`/`just msrv`/`just e2e` fail immediately with "no such subcommand:
`nextest`".

**Doctests still run separately.** nextest does not execute doctests at all
(no flag enables it — this is a known, permanent nextest limitation, not a
config gap). Every recipe that used to run `cargo test` (which implicitly
included doctests) now runs `cargo nextest run` followed by a second
`cargo test --workspace ... --doc` step. Doctests are kept because they're
real, compiled, runnable examples in doc comments — the fast-but-incomplete
option would be dropping them, and we're not doing that.

**`just e2e` runs at `--test-threads 8` locally**, higher than CI's `4`,
because each e2e test already allocates its own isolated Docker bridge
network and host ports (see `pathvector-e2e/src/lib.rs`), so concurrent runs
are safe by construction — the number is a hardware-appropriate guess, not a
correctness requirement. Lower it if Docker Desktop's resource limits make
local e2e runs flaky.

---

## The macOS / Linux clippy split

**The most common source of CI failures when developing on macOS.**

The workspace enables `clippy::all` and `clippy::pedantic` as errors. Any code
inside a `#[cfg(target_os = "linux")]` block is **never compiled on macOS**, so
clippy never sees it locally. On `ubuntu-latest` in GitHub Actions, that code
compiles and any lint violations become CI failures.

### When this bites you

Any time you touch:
- `pathvector-sys/src/tcp.rs` — the `apply_linux` function and its Linux-only tests
- `pathvectord/src/daemon.rs` — the BGP listener MD5 key installation block
- Any new `#[cfg(target_os = "linux")]` code you add

### How to catch it before pushing

```sh
just lint-linux
```

This runs `cargo clippy --workspace --exclude pathvector-e2e --all-targets -- -D warnings` inside a
`rust:latest` Docker container pinned to `linux/amd64` — the same environment
as CI. `pathvector-e2e` is excluded here for the same reason it's excluded
from `just test`/`just msrv`: it pulls in `testcontainers`, a heavy
compile-time dependency, for no benefit in this recipe. It's still linted —
`just e2e` runs `cargo clippy -p pathvector-e2e` before the test suite,
where the Docker/compile cost is already being paid.

**First run is slow.** On an M2 Mac, the initial compile takes 15–30 minutes:
- Docker pulls the `linux/amd64` image (once)
- Every crate compiles from scratch under Rosetta 2 x86 emulation (once)

Subsequent runs are fast because `.cargo-linux-cache/` at the workspace root
persists the compiled dependency cache between container invocations. Only crates
you actually changed are recompiled.

**Rule of thumb:** run `just lint-linux` whenever you touch Linux-gated code.
For all other changes, `just ci` is sufficient.

### Common Linux-only lint violations

These are the ones that have bitten us. All are in pedantic and invisible on macOS:

| Lint | Trigger | Fix |
|---|---|---|
| `doc_markdown` | Function name in doc comment without backticks | `` `apply_tcp_md5sig` `` not `apply_tcp_md5sig` |
| `struct_field_names` | All fields share a common prefix (e.g. `tcpm_`) | `#[allow(clippy::struct_field_names)]` with a comment explaining why (kernel ABI) |
| `cast_possible_truncation` | `i32 as u16`, `usize as u8`, `usize as u32` in FFI | `#[allow(...)]` with a comment proving the value fits, or `try_from().expect()` |
| `unnested_or_patterns` | `Some(A) \| Some(B)` in `matches!` | `Some(A \| B)` |
| `items_after_statements` | `use` or `struct` defined after a `let` in a function body | Move items to the top of the block |

---

## End-to-end tests

The e2e suite runs `pathvectord` and GoBGP as Docker containers. See
[TESTING.md](TESTING.md) for full details.

```sh
just e2e          # Build both images and run all 41 e2e tests
just e2e-images   # Build images only (skips tests)
```

**After changing `pathvectord` source, always rebuild the image before running
e2e tests.** `just e2e` does this automatically. Running `cargo test -p
pathvector-e2e` directly against a stale image is the most common source of
confusing e2e failures — the old binary silently ignores new TOML fields added
with `#[serde(default)]`.

---

## Test layers

See [TESTING.md](TESTING.md) for the full testing philosophy and coverage map.
Quick reference:

| Command | What it runs |
|---|---|
| `cargo test` | Unit + doc + prop tests across all crates |
| `just fuzz-smoke` | 60 s fuzz smoke run (requires nightly) |
| `just e2e` | Full Docker e2e suite |
| `just lint-linux` | Linux clippy (catches macOS blind spots) |

---

## Commit style

- Present-tense imperative subject line: `fix: collapse nested if in grpc test`
- Prefix: `fix:`, `feat:`, `chore:`, `docs:`, `test:`, `refactor:`
- Body explains *why*, not *what* — the diff already shows what changed
- Reference the RFC when fixing a protocol bug: `fix: enforce RFC 8212 default-reject on eBGP`

---

## Adding Linux-gated code

If you add a new `#[cfg(target_os = "linux")]` block:

1. Write it, run `just ci` to confirm it compiles on macOS.
2. Run `just lint-linux` before pushing to confirm clippy is clean on Linux.
3. Add a `#[cfg(not(target_os = "linux"))]` stub or `let _ = ...` for any
   variables that would otherwise be unused on non-Linux platforms.
4. Add a comment explaining what the Linux path does and why the non-Linux
   path is a no-op (or why the feature is Linux-only).
