# Introduction

pathvector is a BGP-4 implementation written in Rust, built to the highest
standards of safety, correctness, and test discipline. The goal is a production-grade
BGP speaker that is a credible alternative to [GoBGP](https://github.com/osrg/gobgp)
for single-AS and eBGP peering deployments.

## What pathvector is

- A **BGP-4 daemon** (`pathvectord`) that manages one TCP session per configured
  peer, evaluates import and export policies, maintains a three-table RIB
  (Adj-RIB-In, Loc-RIB, Adj-RIB-Out), and exposes a gRPC management API
- A **CLI** (`pathvector`) for querying operational state and changing policy at runtime
- A **workspace of focused crates**, each with a clear RFC ownership story and
  close to 100% test coverage

## What makes it different

**Safety by construction.** `unsafe` code is confined to a single crate
(`pathvector-sys`) and a single function (`apply_tcp_md5sig`). Every other crate
in the workspace enforces `#![forbid(unsafe_code)]`. A code reviewer can audit
the entire unsafe surface by reading 60 lines.

**RFC 8212 by default.** eBGP routes are rejected unless an explicit import policy
accepts them. This is the correct secure default; many implementations require it
to be configured manually.

**Test discipline at every layer.** Unit tests, property-based tests (proptest),
fuzz targets (cargo-fuzz), snapshot tests (insta), end-to-end tests against a
real GoBGP peer (testcontainers), and dependency inversion for the CLI — every
public behaviour is verified at the appropriate layer. See [Testing](testing.md).

## Current status

pathvector is under active development. The core BGP-4 session lifecycle,
three-table RIB, import/export policy engine, route origination, and outbound
UPDATE propagation are fully implemented and validated against GoBGP in a
Docker-based end-to-end suite.

Key gaps relative to a production router:

- **No FIB integration** — routes are selected and stored in Loc-RIB but not
  installed into the kernel's forwarding table. FIB integration (Netlink) is the
  next major milestone.
- **No Graceful Restart** — sessions tear down cleanly but do not preserve routes
  across a daemon restart.
- **No Route Reflector** — iBGP deployments require full-mesh or an external
  reflector.

See [Roadmap](roadmap.md) for the full picture.

## Workspace layout

| Crate | Role |
|---|---|
| `pathvector-types` | BGP primitive types: `Asn`, `AsPath`, `Community`, `Nlri`, `Route`, ... |
| `pathvector-policy` | Policy engine: conditions, actions, term evaluation |
| `pathvector-rib` | RIB tables, best-path decision process (RFC 4271 §9.1) |
| `pathvector-session` | Wire codec, BGP FSM, TCP transport |
| `pathvector-sys` | Unsafe enclave: `apply_tcp_md5sig` (Linux setsockopt) |
| `pathvector-client` | gRPC client library for the management API |
| `pathvector-bmp` | BGP Monitoring Protocol receiver (not yet started) |
| `pathvectord` | Daemon binary — wires everything together |
| `pathvector` | CLI binary |
