# Getting Started

This chapter walks through building pathvector from source, running it alongside
GoBGP for local interoperability testing, and exercising the management CLI.

## Prerequisites

- Rust stable (≥ 1.88) — install via [rustup](https://rustup.rs)
- `protoc` — `brew install protobuf` on macOS, `apt install protobuf-compiler` on Linux
- GoBGP 4.6.0 — `go install github.com/osrg/gobgp/v4/cmd/gobgpd@v4.6.0`
- Docker — required for the end-to-end test suite

## Build

```sh
git clone https://github.com/dbrucknr/pathvector
cd pathvector
cargo build --release
```

Binaries are at `target/release/pathvectord` and `target/release/pathvector`.

## Quick start

```sh
# Install just (task runner)
cargo install just

# Run all unit + doc + property tests
cargo test --workspace --exclude pathvector-e2e

# Run the end-to-end suite against GoBGP in Docker
just e2e
```

## Local interoperability guide

The full guide for running pathvectord and GoBGP side-by-side, injecting
routes, observing the RIB, and testing policy changes is in the next chapter.

{{#include ../../LOCAL_INTEROP.md}}
