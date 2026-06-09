# Integration Testing

End-to-end tests that bring up a real BGP session between `pathvectord` and
GoBGP, then assert on routing state through `pathvector-client`.  These tests
prove correctness at the protocol boundary rather than at the unit level.

---

## Why a separate suite

The regular `just ci` suite (`cargo test --workspace`) is fast, hermetic, and
runs without Docker.  It covers codec correctness, RIB invariants, policy
semantics, and the gRPC conversion layer.  What it cannot do is verify that
a real BGP session forms, that UPDATE messages actually move routes end-to-end,
or that session teardown clears the RIB correctly.

The e2e suite fills that gap.  It is intentionally kept out of `just ci` so
that the common developer loop stays fast and Docker-free.

---

## Architecture

```
  ┌─────────────────────────────────────────────────────────┐
  │  Test process (host)                                     │
  │                                                          │
  │  pathvector-e2e crate                                    │
  │    │                                                     │
  │    ├── PathvectorClient → gRPC → pathvectord             │
  │    │     (localhost:5120x, dynamically allocated)        │
  │    │                                                     │
  │    └── testcontainers-rs ──────────────────────────────┐ │
  │                                                        │ │
  └────────────────────────────────────────────────────────┼─┘
                                                           │
  ┌────────────────────────────────────────────────────────▼─┐
  │  pathvectord subprocess (host)                            │
  │    BGP port: localhost:<mapped>                           │
  │    gRPC port: localhost:5120x                             │
  └──────────────────────────────┬───────────────────────────┘
                                 │ BGP session (RFC 4271)
                                 ▼ localhost:<mapped>
  ┌────────────────────────────────────────────────────────────┐
  │  Docker: osrg/gobgp                                        │
  │    AS 65001  router-id 1.0.0.1                             │
  │    passive-mode = true (never initiates)                   │
  │    dynamic-neighbors: accepts any incoming AS 65002 conn   │
  │    hold-time = 9 s  keepalive = 3 s                        │
  └────────────────────────────────────────────────────────────┘
```

### Key design decisions

**GoBGP runs in Docker; `pathvectord` runs as a subprocess on the host.**

Running `pathvectord` as a real subprocess (not in-process mocked code) means
we test the actual binary that ships.  The path is resolved from the workspace
`target/debug/` directory, which `just e2e` builds before running tests.

**testcontainers-rs for GoBGP lifecycle.**

testcontainers starts GoBGP in Docker, maps port 179 to a random host port, and
cleans up the container on test teardown.  Random port mapping means tests never
clash even if the test runner is changed to allow parallelism.

**Dynamic neighbors — no hardcoded IPs.**

When `pathvectord` on the host connects to `localhost:<mapped>`, Docker NATs the
connection through its bridge; the source IP seen by GoBGP inside the container
is the Docker bridge gateway (typically `172.17.0.1` on Linux, variable on Mac).

To avoid platform-specific IP detection, GoBGP is configured with
`dynamic-neighbors prefix = "0.0.0.0/0"`.  This means GoBGP accepts any
incoming BGP connection presenting AS 65002, regardless of source IP.

**`pathvector-client` as the assertion layer.**

All assertions use the same `PathvectorClient` that operators and the CLI would
use.  This gives two-for-one confidence: the routing state is correct *and* the
management API reports it accurately.

**Poll, don't sleep.**

No test uses a fixed `sleep`.  `wait_for_established`, `wait_for_route`, and
`wait_for_route_withdrawn` poll every 200 ms with a hard deadline (typically
10–15 s).  When something breaks, the test fails fast with a clear message
rather than hanging or passing silently.

---

## Running the suite

**Prerequisite: Docker must be running.**

```sh
# Build the daemon binary, then run all e2e tests serially.
just e2e
```

Tests are serialised (`--test-threads=1`) because each test allocates ports
from a shared counter starting at `51200`.

To run a single test:

```sh
cargo build -p pathvectord
cargo test -p pathvector-e2e -- --test-threads=1 announced_route_appears_in_rib
```

---

## Scenario coverage

Each scenario maps to a specific RFC requirement.

| Test | File | RFC | What it proves |
|---|---|---|---|
| `session_reaches_established` | session.rs | RFC 4271 §8 | FSM reaches Established; OPEN + KEEPALIVE exchange succeeds |
| `peer_state_fields_correct_after_established` | session.rs | RFC 4271 §8 | AS numbers, peer type, hold-time populated correctly |
| `list_peers_includes_gobgp_peer` | session.rs | RFC 4271 §8 | Management API reflects live session state |
| `wait_for_established_respects_deadline` | session.rs | — | Test harness deadline fires correctly; not a BGP test |
| `announced_route_appears_in_rib` | routes.rs | RFC 4271 §9.2 | UPDATE received and installed in Loc-RIB |
| `withdrawn_route_removed_from_rib` | routes.rs | RFC 4271 §9.3 | WITHDRAW removes route from Loc-RIB |
| `multiple_routes_all_installed` | routes.rs | RFC 4271 §9.2 | Multiple prefixes handled correctly; `list_routes` returns all |
| `partial_withdrawal_leaves_others_intact` | routes.rs | RFC 4271 §9.3 | Withdraw of one prefix does not disturb others |
| `list_candidates_returns_peer_route` | routes.rs | RFC 4271 §9.1 | Candidate map populated; `list_candidates` API works |
| `unknown_prefix_returns_none` | routes.rs | RFC 4271 §9.1 | `get_best_route` returns `None` for absent prefix |

---

## CI integration

The e2e suite runs as a separate GitHub Actions job named `e2e`, triggered on
pushes to `main` and on manual dispatch.  It does **not** block PR CI — fast
feedback on every push comes from the standard `ci` job.

The `e2e` job:

1. Installs Rust (stable) and `protoc`.
2. Runs `cargo build -p pathvectord` to build the binary.
3. Pulls `osrg/gobgp:latest` (Docker is pre-installed on `ubuntu-latest`).
4. Runs `cargo test -p pathvector-e2e -- --test-threads=1`.

---

## Known limitations and future work

**GoBGP image pinning.**

The harness uses `osrg/gobgp:latest`.  For reproducible CI, pin to a specific
image digest once the image is known to be stable, e.g.:

```rust
const GOBGP_TAG: &str = "sha256:abc123...";
```

**Export path not yet asserted.**

These tests verify the import path (GoBGP → `pathvectord`).  The export path
(`pathvectord` → GoBGP) could be asserted by querying GoBGP's gRPC API or by
exec-ing `gobgp global rib` and parsing its output.  Export path testing is
deferred until the GoBGP gRPC client is available in the harness.

**Single-peer topology.**

The current harness has exactly one GoBGP peer.  A multi-peer harness (two
GoBGP instances) would let us test best-path selection, route reflection, and
policy differences per-peer.  That is a straightforward harness extension.

**Test parallelism.**

Tests are serialised today.  Each test could instead bind a unique port range,
allowing parallel execution.  The harness's atomic port counter already supports
this — remove `--test-threads=1` once the port allocation is validated.

**Hold timer race on slow CI.**

With `hold-time = 9` and a 15 s establishment deadline, there is a 6 s margin.
On pathologically slow CI runners this could cause flaky failures.  If that
happens, raise the deadline in `Harness::new` before touching the hold timer
(the RFC minimum is 3 s; lower values are not worth the risk).
