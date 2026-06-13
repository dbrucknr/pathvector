# Crate Overview

The workspace is organised as a strict dependency stack. Each crate has a single
responsibility and depends only on crates below it.

```
pathvector-types          ← primitive BGP types, zero external deps
    ↑
pathvector-policy         ← route evaluation engine
    ↑
pathvector-rib            ← RIB tables and best-path selection
    ↑
pathvector-session        ← wire codec, BGP FSM, TCP transport
    ↑
pathvectord               ← daemon binary; wires everything together
    ↑
pathvector                ← CLI binary

pathvector-sys            ← unsafe enclave (setsockopt only)
pathvector-client         ← gRPC client; no internal deps
pathvector-bmp            ← BMP receiver (not yet started)
```

## `pathvector-types`

The foundation. Defines every BGP primitive type used across the workspace:
`Asn`, `AsPath`, `Community`, `LargeCommunity`, `ExtendedCommunity`, `Nlri`,
`Origin`, `LocalPref`, `Med`, `NextHop`, `Route`, `PeerType`, and the AFI/SAFI
registry. Zero external runtime dependencies. All types are `#[derive(Clone,
Debug, PartialEq)]`; newtypes prevent accidental mixing of conceptually distinct
`u32` values.

RFC ownership: §5 path attribute types, RFC 1997, 4360, 8092, 7999, 4760 SAFI
constants, RFC 6793, 1930, 6996, 5065.

## `pathvector-policy`

The route evaluation engine. A `Policy<R>` is a list of `Term<C, A>` values;
evaluation is first-match-wins. Terms have a `Condition` (e.g. prefix list,
community match, local-pref comparison) and an `Action` (Accept, Reject, Next,
or a modifying action like `SetLocalPref` or `AddCommunity`). The engine is
generic over the route type via `EvaluateTerm`.

## `pathvector-rib`

Three RIB tables: `AdjRibIn<A>` (pre-policy, per-peer), `LocRib<A>` (post-policy
best paths), and `AdjRibOut<A>` (post-export-policy, per-peer). `select_best`
implements RFC 4271 §9.1 decision steps 2–7 and 10. `LocRib` uses `RouteMap<A>`
from the `routemap` crate for O(log n) longest-prefix-match queries.

## `pathvector-session`

Wire codec (`BgpCodec`), BGP FSM (`Fsm`), and TCP transport (`spawn`). The codec
handles framing (19-byte marker + length + type header) and all five message types
(OPEN, UPDATE, KEEPALIVE, NOTIFICATION, ROUTE-REFRESH). The FSM is a pure state
machine with no I/O; the transport layer drives it via `FsmInput` events and acts
on `FsmOutput` commands.

## `pathvector-sys`

The sole crate permitted to write `unsafe`. Contains one public function:
`apply_tcp_md5sig(fd, peer_ip, key)`. On Linux this calls `setsockopt(TCP_MD5SIG)`;
on all other platforms it is a no-op. See [Safety](safety.md).

## `pathvector-client`

A gRPC client library wrapping the management API. Has no dependency on any
internal crate — all domain types are defined independently in `src/types.rs`.
The `DaemonClient` trait is the seam used for dependency inversion in CLI tests.

## `pathvectord`

The daemon binary. Owns `DaemonState` (the central shared state behind a
`RwLock`), the main event loop, gRPC service implementations, and the BGP TCP
listener. Wires together all library crates and handles the Update-Send Process
(RFC 4271 §9.2): `handle_update` → `propagate_prefix` → `flush_updates`.

## `pathvector`

The CLI binary. Every subcommand is dispatched through `impl DaemonClient`,
making all command logic unit-testable via `MockDaemonClient` without a network
connection.
