# Architecture

A guide to how the pathvector crates compose at runtime. Intended for contributors
who want to understand how a BGP message travels from a peer's TCP socket into the
RIB, and how a route change travels back out to all established peers.

---

## Crate dependency graph

```
pathvector-types          (zero external deps — primitive types only)
    ↑
pathvector-policy         (route evaluation engine)
    ↑
pathvector-rib            (RIB tables and best-path selection)
    ↑
pathvector-session        (wire codec, BGP FSM, TCP transport)
    ↑
pathvectord               (daemon — wires everything together)

pathvector-client         (gRPC client library — no internal deps)
pathvector-bmp            (future BMP receiver — not yet started)
```

**`pathvector-client` has no dependencies on any internal crate.** All domain types
are defined independently in `src/types.rs`. This is intentional: the client is a
trust boundary — it communicates with the daemon over the network and must treat
daemon responses as untrusted input. Keeping it isolated also lets external consumers
depend on the client without pulling in the full BGP implementation.

---

## Inbound route path

How a BGP UPDATE from a remote peer reaches the Loc-RIB:

```
Peer TCP socket (port 179)
  │
  ▼
FramedBgpTransport                     pathvector-session/src/transport/mod.rs
  │  FramedRead<TcpStream, BgpCodec>
  │  → BgpCodec::decode()              pathvector-session/src/framing/
  │    strips 16-byte marker, validates length and type field
  │  → BgpMessage::decode()            pathvector-session/src/message/
  │    parses OPEN / UPDATE / KEEPALIVE / NOTIFICATION / ROUTE-REFRESH
  │
  ▼
Session<FramedBgpTransport>::run()     pathvector-session/src/transport/mod.rs
  │  Converts BgpMessage to FsmInput
  │
  ▼
Fsm::on_input(FsmInput)                pathvector-session/src/fsm/mod.rs
  │  Pure state machine — no I/O.
  │  Returns Vec<FsmOutput>; callers execute each output (send a message,
  │  start/stop a timer, emit a SessionEvent).
  │  On UPDATE in Established: FsmOutput::RouteUpdate(UpdateMessage)
  │
  ▼
SessionEvent::RouteUpdate(msg)         pathvector-session/src/transport/mod.rs
  │  Emitted by the per-peer session task
  │  via SessionHandle::next_event()
  │
  ▼
per-peer forwarding task (pathvectord) pathvectord/src/main.rs  run()
  │  tokio::spawn per configured peer
  │  event_tx.send((peer_addr, event))
  │
  ▼
event_rx.recv()  ←──────────────────── single mpsc channel; all peers multiplex in
  │
  ▼
DaemonState::on_route_update()         pathvectord/src/main.rs
  │
  ▼
handle_update(peer_id, msg, ...)
  ├─ for each withdrawn NLRI:
  │    AdjRibIn::withdraw(nlri)         pathvector-rib/src/adj_rib_in.rs
  │    LocRib::withdraw(peer, nlri)     pathvector-rib/src/loc_rib.rs
  │
  └─ for each announced NLRI:
       AdjRibIn::insert(raw_route)      pre-policy store for soft reconfig
       import_policy.evaluate(&mut r)  pathvector-policy/src/lib.rs
       if Accept:
         LocRib::insert(peer, route)   pathvector-rib/src/loc_rib.rs
           → best_path::select_best()  pathvector-rib/src/best_path.rs
             RFC 4271 §9.1 decision steps 2,4,5,6,7,10
```

---

## Outbound route path

How a best-path change reaches a peer's TCP socket:

```
LocRib::insert / withdraw              (best path may have changed)
  │
  ▼
DaemonState::on_route_update (cont.)
  │  for each affected NLRI, for each established peer:
  │
  ▼
propagate_prefix(nlri, loc_rib, adj_rib_out, export_policy, ...)
  │
  ├─ LocRib::best(nlri) → Some(route)
  │    prepare_outbound(route, peer_type, local_as, local_bgp_id)
  │      eBGP only: prepend local AS to AS_PATH
  │                 rewrite NEXT_HOP to local BGP identifier
  │                 strip LOCAL_PREF
  │
  ├─ export_policy.evaluate(&mut outbound_route) → Decision
  │
  ├─ if Accept:
  │    AdjRibOut::insert(route) → InsertOutcome  pathvector-rib/src/adj_rib_out.rs
  │      iBGP split-horizon enforced here:
  │        routes learned from iBGP not re-advertised to iBGP peers
  │      confederation segment stripping for eBGP peers applied here
  │    if route changed vs. previously advertised:
  │      update_tx.try_send(route_to_update(route))
  │
  └─ if Reject or no best:
       AdjRibOut::withdraw(nlri)
       if previously advertised:
         update_tx.try_send(withdraw_msg(nlri))

update_tx: mpsc::Sender<UpdateMessage>  ──────────────────────────────────────┐
                                                                               │
  ┌────────────────────────────────────────────────────────────────────────────┘
  ▼
Session::wait_for_input()              pathvector-session/src/transport/mod.rs
  │  select! loop: timers | peer messages | outbound UPDATE channel
  │  lowest-priority arm drains outbound channel without blocking timer handling
  │
  ▼
FramedBgpTransport::send(BgpMessage::Update(msg))
  │  BgpCodec::encode() → write to FramedWrite<TcpStream>
  │
  ▼
Peer TCP socket
```

---

## Session lifecycle events

Three `SessionEvent` variants drive all daemon state changes:

| Event | Trigger | DaemonState method |
|---|---|---|
| `Established(SessionInfo)` | FSM reaches Established after KEEPALIVE exchange | `on_established` — records peer type, resets `AdjRibOut`, performs full-table dump to new peer |
| `Terminated` | TCP close, NOTIFICATION received, hold timer expired | `on_terminated` — clears `AdjRibIn`, withdraws peer's routes from `LocRib`, propagates best-path changes to other established peers |
| `RouteUpdate(UpdateMessage)` | UPDATE received in Established state | `on_route_update` — calls `handle_update`, propagates affected NLRIs to all peers |

---

## Management plane

The gRPC server and the BGP event loop share state via `Arc<RwLock<DaemonState>>`:

```
gRPC request (HTTP/2 + protobuf)
  │
  ▼
tonic server                           pathvectord/src/grpc.rs
  │  PeerService  — list_peers(), get_peer()
  │  RibService   — get_best_route(), list_routes(), list_candidates()
  │
  │  Arc<RwLock<DaemonState>>::read().await
  │    Non-blocking read lock — never contends with the BGP event loop
  │    (write lock is held only while processing one SessionEvent)
  │
  ▼
Query DaemonState fields directly:
  peer_types, established_at, hold_times,    → PeerState proto
  peer_remote_as, adj_ribs_in (prefix counts)
  loc_rib.best(prefix)                       → Route proto
  loc_rib.best_routes()                      → ListRoutes proto
  loc_rib.candidates(prefix)                 → ListCandidates proto
  │
  ▼
Type conversion (domain → proto)       pathvectord/src/grpc.rs
  │
  ▼
gRPC response
```

The read/write lock split is deliberate: gRPC read queries never block BGP event
processing, and BGP event processing (write lock, held briefly per event) never
blocks waiting on slow gRPC clients.

---

## The `BgpTransport` trait seam

`Session<T: BgpTransport>` is generic over its I/O layer:

```
BgpTransport (trait)
  ├─ FramedBgpTransport   production: FramedRead + FramedWrite over TcpStream
  └─ MockTransport        test-only (#[cfg(test)]): in-memory Vec<BgpMessage>
```

`transport::spawn()` is non-generic and always produces `Session<FramedBgpTransport>`.
`transport::spawn_with<T: BgpTransport>()` (test-only) injects a pre-built transport,
bypassing real TCP. The first `InitiateTcpConnect` output from the FSM activates the
injected transport and queues `TcpConnected` — the FSM never knows it isn't talking
to a real socket.

This seam is what allows all FSM write-path tests (`test_send_failure_in_execute_*`,
`test_outbound_update_write_failure_*`) to run without binding any ports.

---

## `DaemonState` owns no I/O

`DaemonState` holds all BGP routing state — `LocRib`, per-peer `AdjRibIn` / `AdjRibOut`,
import/export policies, session metadata — but it does no I/O itself. Outbound messages
are queued onto per-peer `mpsc::Sender<UpdateMessage>` channels; the session tasks drain
them. This means every method on `DaemonState` is a plain synchronous function and is
fully unit-testable without spawning tasks or binding sockets:

```rust
// From the test suite — no async, no network:
let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
state.on_established(peer_a, PeerType::External, 65002, 90);
state.on_route_update(peer_a, update_message);
let msg = receivers.get_mut(&peer_b).unwrap().try_recv().unwrap();
assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
```

---

## Key design invariants

- **The FSM is pure.** `Fsm::on_input` takes an input and returns outputs; it never
  reads from or writes to a socket. All side effects (TCP connect, message send, timer
  start/stop) are encoded as `FsmOutput` variants and executed by the transport layer.

- **`pathvector-types` has no external dependencies.** It is the shared vocabulary for
  the entire workspace. Nothing in the codec, RIB, or policy engine depends on anything
  that isn't in this crate or the standard library.

- **iBGP split-horizon lives in `AdjRibOut`.** The invariant that routes learned from
  an iBGP peer are not re-advertised to other iBGP peers is enforced at insertion time
  in `AdjRibOut::insert`, not scattered across the propagation logic.

- **`propagate_prefix` is idempotent.** It reads the current best from `LocRib`,
  applies export policy, and sends an UPDATE or WITHDRAW only when the advertised state
  actually changes (by comparing against what is in `AdjRibOut`). It is safe to call
  for any NLRI at any time without producing spurious wire messages.

- **All `unsafe_code = "forbid"` workspace-wide.** Set at the workspace level in
  `Cargo.toml`; no crate can opt out.
