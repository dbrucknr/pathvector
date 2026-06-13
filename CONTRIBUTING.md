# Contributing to pathvector

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
cargo test --workspace --exclude pathvector-e2e
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
rustup run 1.88 cargo test --workspace --exclude pathvector-e2e
```

This catches the vast majority of issues before pushing. Run it before every
commit.

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

This runs `cargo clippy --workspace --all-targets -- -D warnings` inside a
`rust:latest` Docker container pinned to `linux/amd64` — the same environment
as CI.

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
