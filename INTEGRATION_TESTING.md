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

Both `pathvectord` and `gobgpd` run as Linux containers on a per-test Docker
bridge network.  BGP traffic is container-to-container — it never touches the
macOS Docker Desktop TCP proxy, which corrupts BGP handshakes when host→container
routing is involved.  Only `pathvectord`'s gRPC port is mapped to the host so
that `PathvectorClient` can reach it; HTTP/2 is unaffected by the proxy.

```
  ┌─────────────────────────────────────────────────────────────┐
  │  Test process (host)                                         │
  │                                                              │
  │  pathvector-e2e crate                                        │
  │    │                                                         │
  │    ├── PathvectorClient ─── gRPC (HTTP/2) ──────────────┐   │
  │    │     localhost:<dynamic host port>                   │   │
  │    │                                                     │   │
  │    └── testcontainers-rs ── docker exec (gobgp CLI) ─┐  │   │
  │                                                       │  │   │
  └───────────────────────────────────────────────────────┼──┼───┘
                                                          │  │
  ┌── Docker bridge network (per-test) ──────────────────▼──▼───┐
  │                                                              │
  │  gobgpd container                  pathvectord container     │
  │  172.20.x.10                       172.20.x.11               │
  │  AS 65001                          AS 65002                  │
  │  image: pathvector-gobgpd-test     image: pathvector-e2e     │
  │                                                              │
  │        ◄────── BGP session (port 179, container-to-container) ──►
  │                                                              │
  └──────────────────────────────────────────────────────────────┘
```

### Key design decisions

**Both daemons run in Docker.**

GoBGP only ships Linux binaries; there are no macOS prebuilts.  Running both
services in Docker means the suite works identically on macOS and Linux without
any native dependency installation.  The images are built once with `just e2e-images`
and cached by Docker's layer cache for subsequent runs.

**Container-to-container BGP.**

BGP (port 179) stays inside the Docker bridge network.  The macOS Docker Desktop
TCP proxy only intercepts host→container connections; container-to-container traffic
goes through the Linux kernel bridge directly.  This is what allows the handshake
to complete on macOS.

**Per-test Docker bridge network.**

Each `Harness::new()` call creates a fresh `docker network create` with a unique
name.  The network is removed on `Drop`.  This ensures complete isolation between
concurrent test runs and prevents stale ARP/routing state from one test affecting
another.

**`docker inspect` for container IPs.**

`pathvectord`'s `PeerConfig.address` is `Ipv4Addr` (not a hostname), so the
harness calls `docker inspect` after starting the `gobgpd` container to obtain
its actual bridge IP.  This IP is then written into a per-test `pathvectord.toml`
fixture file that is bind-mounted into the `pathvectord` container.

**`docker exec` for the gobgp CLI.**

The `gobgp` CLI binary is installed inside the `gobgpd` container.  The harness
uses `docker exec <container_id> gobgp global rib add ...` to inject routes.
This avoids needing to map GoBGP's gRPC port (50051) to the host.

**`pathvector-client` as the assertion layer.**

All assertions use the same `PathvectorClient` that operators and the CLI would
use.  This gives two-for-one confidence: the routing state is correct *and* the
management API reports it accurately.

**Poll, don't sleep.**

No test uses a fixed `sleep`.  `wait_for_established`, `wait_for_route`, and
`wait_for_route_withdrawn` poll every 200 ms with a hard deadline (typically
10 s).  When something breaks the test fails fast with a clear message rather
than hanging or passing silently.

---

## Running the suite

**Prerequisites: Docker must be running.**

```sh
# Build both Docker images, then run all e2e tests serially.
just e2e
```

This is equivalent to:

```sh
just e2e-images                          # build pathvector-gobgpd-test:latest
                                         #   and pathvector-e2e:latest
cargo test -p pathvector-e2e -- --test-threads=1 --nocapture
```

Tests are serialised (`--test-threads=1`) because each test allocates a
host gRPC port from a shared atomic counter starting at `51200`.

To run a single test:

```sh
just e2e-images
cargo test -p pathvector-e2e -- --test-threads=1 announced_route_appears_in_rib
```

To start the compose dev environment for manual inspection:

```sh
just e2e-up    # starts gobgpd + pathvectord in the background
just e2e-logs  # stream logs
just e2e-down  # stop and clean up
```

---

## Docker images

| Image | Built from | Purpose |
|---|---|---|
| `pathvector-gobgpd-test:latest` | `e2e/Dockerfile` | GoBGP 4.6.0 on Alpine; includes the `gobgp` CLI for `docker exec` route injection |
| `pathvector-e2e:latest` | `e2e/Dockerfile.pathvectord` | Multi-stage Rust build; `debian:bookworm-slim` runtime with `nc` for the HEALTHCHECK |

Both images are Linux/arm64 on Apple Silicon (native, no QEMU) and Linux/amd64
on x86 CI runners.  The GoBGP version is pinned in the `Justfile`:

```just
gobgp-version := "4.6.0"
```

---

## Scenario coverage

Each scenario maps to a specific RFC requirement.

| Test | File | RFC | What it proves |
|---|---|---|---|
| `session_reaches_established` | session.rs | RFC 4271 §8 | FSM reaches Established; OPEN + KEEPALIVE exchange succeeds end-to-end |
| `peer_state_fields_correct_after_established` | session.rs | RFC 4271 §8 | AS numbers, peer type, hold-time populated correctly |
| `list_peers_includes_gobgp_peer` | session.rs | RFC 4271 §8 | Management API reflects live session state |
| `wait_for_established_respects_deadline` | session.rs | — | Test harness deadline fires correctly; not a BGP test |
| `announced_route_appears_in_rib` | routes.rs | RFC 4271 §9.2 | UPDATE received and installed in Loc-RIB with correct attributes |
| `withdrawn_route_removed_from_rib` | routes.rs | RFC 4271 §9.3 | WITHDRAW removes route from Loc-RIB |
| `multiple_routes_all_installed` | routes.rs | RFC 4271 §9.2 | Multiple prefixes handled correctly; `list_routes` returns all |
| `partial_withdrawal_leaves_others_intact` | routes.rs | RFC 4271 §9.3 | Withdraw of one prefix does not disturb others |
| `list_candidates_returns_peer_route` | routes.rs | RFC 4271 §9.1 | Candidate map populated; `list_candidates` API works |
| `unknown_prefix_returns_none` | routes.rs | RFC 4271 §9.1 | `get_best_route` returns `None` for absent prefix |

---

## CI integration

The e2e suite is not yet wired into GitHub Actions (tracked in TODO.md).  It
runs locally via `just e2e`.  The intended CI structure when added:

- Separate `e2e` job on `ubuntu-latest` (Docker pre-installed)
- Runs after the standard `ci` job passes
- Steps: `just e2e-images` (with Docker layer cache), then `just e2e`
- Does not block PR feedback — the fast `ci` job covers that

---

## Known limitations and future work

**Inbound path only.**

Current tests verify the import path (GoBGP → `pathvectord`).  The export path
(`pathvectord` → GoBGP) is not yet asserted.  This would require querying GoBGP's
gRPC API or exec-ing `gobgp global rib` to verify routes it received from
`pathvectord`.  Tracked in TODO.md.

**Import-policy reject not yet tested.**

RFC 8212 default-reject behaviour for eBGP peers is unit-tested but not yet
verified end-to-end.  A test that configures no import policy and asserts a
GoBGP-announced prefix does not appear in the RIB would close this gap.

**Single-peer topology.**

The current harness has exactly one GoBGP peer.  A multi-peer harness would let
us test best-path selection and per-peer policy differences end-to-end.

**Test parallelism.**

Tests are serialised today.  Each test binds a unique host port from an atomic
counter, so parallel execution is possible in principle.  Remove
`--test-threads=1` once the Docker network naming is validated to be unique
enough under parallel `Harness::new()` calls.

**BIRD interoperability.**

GoBGP is permissive about RFC compliance; BIRD is strict.  A BIRD peer image
would provide stronger interoperability evidence.  Tracked in TODO.md.
