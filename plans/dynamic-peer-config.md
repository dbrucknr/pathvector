# Plan: Dynamic Peer Reconfiguration — ✅ Completed 2026-06-17

`AddPeer` and `RemovePeer` gRPC RPCs are implemented and tested. See CHANGELOG.md
(2026-06-17) for the full implementation summary.

Remaining follow-on: `UpdatePeer` RPC and config-file watch. Both are captured in
TODO.md under "Dynamic peer reconfiguration".

---

## Motivation (original)

pathvectord currently reads its configuration once at startup. Adding, removing, or
modifying a peer requires a full daemon restart — which drops all sessions, flushes
the Loc-RIB, and causes a reconvergence event visible to every connected peer. This
is the primary operational gap separating pathvector from a production-grade
replacement for GoBGP or BIRD.

## Approach: gRPC-driven live config

Extend `DaemonService` with peer management RPCs. This is simpler to implement
correctly than a config-file watcher because the RPC layer already owns the
`DaemonState` handle and the session spawn path.

A config-file watcher (`inotify`/`kqueue` that diffs and calls the new RPCs) can
be layered on top once the RPC layer exists.

## New gRPC RPCs

```protobuf
service DaemonService {
  // Existing RPCs ...

  rpc AddPeer(AddPeerRequest)    returns (AddPeerResponse);
  rpc RemovePeer(RemovePeerRequest) returns (RemovePeerResponse);
  rpc UpdatePeer(UpdatePeerRequest) returns (UpdatePeerResponse);
}

message AddPeerRequest {
  string address   = 1;
  uint32 remote_as = 2;
  // optional fields: local_as override, hold_timer, import/export policy name
}

message RemovePeerResponse {
  // empty — success is the absence of error
}
```

## Files to modify

| File | Change |
|---|---|
| `proto/pathvector.proto` | Add `AddPeer`, `RemovePeer`, `UpdatePeer` RPCs + messages |
| `pathvectord/src/grpc.rs` | Implement the three handlers |
| `pathvectord/src/daemon.rs` | `DaemonState::add_peer()`, `remove_peer()`, `update_peer()` — spawn/stop sessions at runtime |
| `pathvector-client/src/lib.rs` | Expose typed wrappers for the new RPCs |
| `pathvector/src/main.rs` | Add `peer add`, `peer remove` CLI subcommands |

## `DaemonState` changes

`add_peer()` — inserts a new `PeerConfig` into the peer table, spawns a session
task, registers the session handle. Equivalent to what `build_daemon` does at
startup for each peer, but called at runtime.

`remove_peer()` — sends `SessionCommand::Stop` to the session handle, waits for
the task to complete, calls `on_terminated` to flush the peer's routes from the
Loc-RIB, removes the peer from the peer table.

`update_peer()` — `remove_peer()` followed by `add_peer()`. Causes a session
reset to the affected peer only; all other peers are unaffected.

## Prerequisite

The session spawn path (`spawn_session` or equivalent) must be callable at
runtime, not just during `build_daemon`. If it currently captures startup state
by value this refactor is a prerequisite for the dynamic config work.

## Tests

- `test_add_peer_establishes_session` — call `AddPeer` via gRPC; assert peer
  appears in `ListPeers` with state `Connecting`
- `test_remove_peer_withdraws_routes` — add a peer, inject a route, remove the
  peer; assert the route is withdrawn from `ListRoutes`
- `test_update_peer_resets_only_target` — two peers; update one; assert the other
  remains `Established`

## Order of execution

1. Refactor session spawn path to be callable at runtime
2. Add `DaemonState::add_peer` / `remove_peer`
3. Add proto RPCs + `grpc.rs` handlers
4. Add `pathvector-client` wrappers
5. Add CLI `peer add` / `peer remove` subcommands
6. Write tests

## Related TODO entries

- TODO.md §pathvectord: "Dynamic peer reconfiguration (runtime config)"
- TODO.md §pathvectord: "Peer groups" (can share the same RPC layer)
