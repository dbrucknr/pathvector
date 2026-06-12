# Architecture Decision Records

Decisions that shaped the codebase — what was chosen, what was rejected, and why.
Each entry is written after the fact so the rationale doesn't rot in git commit messages.

---

## ADR-001 — Policy engine dispatch: `Vec<Box<dyn EvaluateTerm>>` vs generics

**Date:** 2026-05  
**Status:** Accepted

### Context

The policy engine (`pathvector-policy`) evaluates a sequence of Terms against a mutable
route. Terms consist of heterogeneous Conditions and Actions. The two dispatch options were:

- **Static (generics / enum dispatch):** `Term<C, A>` where `C` and `A` are concrete types;
  callers either use a closed enum or a monomorphized generic.
- **Dynamic (`dyn` trait objects):** `Vec<Box<dyn EvaluateTerm<R>>>` — allows arbitrary
  condition/action combinations without recompilation.

### Decision

Dynamic dispatch (`dyn EvaluateTerm`) was chosen.

### Rationale

BGP policy is **control-plane**, not data-plane. A policy is evaluated once per received
route (on UPDATE receipt) — not per forwarded packet. The vtable overhead of a single
indirect call is ~1–3 ns. At 1,000 routes/second (an aggressive BGP convergence event)
the entire policy engine overhead is under 1 µs. There is no measurable difference between
static and dynamic dispatch at this call rate.

Dynamic dispatch enables callers to compose conditions and actions at runtime without
knowing the concrete types at compile time, which is essential for a policy engine that
needs to be configurable (from config files, from gRPC) without recompilation.

### Consequences

- No vtable overhead concern in practice.
- Policy terms are heap-allocated (`Box`). At typical policy sizes (1–50 terms) this is
  one allocation per term at policy construction time — not per evaluation.
- A future enum-based closed set of built-in conditions/actions could eliminate the heap
  allocs entirely if benchmarks ever justify it. The `EvaluateTerm` trait boundary makes
  this a drop-in replacement.

---

## ADR-002 — RibSnapshot: `Arc::make_mut` copy-on-write for gRPC/event-loop isolation

**Date:** 2026-06-11  
**Status:** Accepted (with known follow-on, see ADR-002b)

### Context

`DaemonState` is protected by `Arc<RwLock<DaemonState>>`. The BGP event loop holds the
write lock to process incoming UPDATEs; gRPC management handlers hold the read lock while
iterating the RIB for `ListRoutes`, `GetBestRoute`, etc.

At internet scale (~950k IPv4 prefixes) a `ListRoutes` call iterates the full table in
several milliseconds. During that window the write lock cannot be acquired — every incoming
BGP UPDATE from every peer is queued. This creates hold-timer pressure: peers waiting for
their KEEPALIVEs to be processed may drop the session.

### Decision

Split the read-heavy state (`LocRib`, `originated_routes`, peer metadata, derived counts)
into a new `RibSnapshot` struct held behind `Arc<RibSnapshot>` inside `DaemonState`.

- **gRPC handlers:** call `state.read().await.snapshot()` → gets an `Arc` clone
  (O(1) atomic refcount increment), releases the outer `RwLock` immediately, then iterates
  the snapshot without holding any lock.
- **BGP event loop:** mutates via `Arc::make_mut(&mut self.rib)` — when refcount is 1
  (no concurrent gRPC readers) this is a zero-cost in-place mutation; when refcount > 1
  (a gRPC call is in-flight) it performs a deep clone of `RibSnapshot` before mutating.
- **Write-heavy fields** (`adj_ribs_in`, `adj_ribs_out`) stay directly on `DaemonState`
  since they are mutated on every UPDATE and benefit from no read-sharing.
- **Derived counts** (`prefixes_received`, `prefixes_advertised`) are synced into
  `RibSnapshot` via `sync_received` / `sync_advertised` after each mutation so gRPC can
  read them from the snapshot without accessing `adj_ribs_in/out`.

### Why `Arc::make_mut` over a plain `RwLock<RibSnapshot>`

A nested `RwLock<RibSnapshot>` would still block: the event loop would need a write lock
on the inner `RwLock` while gRPC holds a read lock, reproducing the original contention.
`Arc::make_mut` avoids any inner lock — the CoW only triggers when the outer refcount is
actually elevated, which happens only during the brief window of an active gRPC call.

### RFC correctness impact

**None.** All RFC 4271 protocol state machine logic (`on_established`, `on_route_update`,
`on_terminated`, best-path selection, export policy application) is unchanged. The
`RibSnapshot` split is purely a concurrency optimization for the management plane. The BGP
data path remains serial under the event loop write lock — this is correct per RFC 4271
§8.1 (FSM events are processed one at a time).

### Consequences

- Resolves performance items 4 and 5 from TODO.md.
- The CoW copy cost (deep clone of `RibSnapshot`) is O(N routes). This triggers only when
  a `ListRoutes` gRPC call is active simultaneously with a BGP UPDATE. At a 1 req/s
  management-plane rate and BGP update rates of ~10k routes/s during convergence, the
  probability of contention is low.
- `LocRib::Clone` required adding `Clone` to `RouteMap` in the `routemap` crate. Done
  via `#[derive(Clone)]` on `RouteMap<A, V>` and `TbNode<V>` (both are `Vec`-backed,
  derivation is correct).

### Known concern: CoW under long-lived gRPC streams

`Arc::make_mut` is the right primitive here — not `arc-swap`. `arc-swap` requires cloning
the full snapshot on *every* write (clone → mutate → swap pointer), so BGP UPDATE processing
would always be O(N routes). `Arc::make_mut` is O(1) in the common case and only pays the
clone cost when a snapshot Arc is actually held concurrently — strictly better for a
write-heavy event loop with rare management reads.

The remaining concern is a future long-lived streaming gRPC handler (e.g. `WatchRoutes`)
that retains a snapshot `Arc` across `await` points, turning every concurrent UPDATE into
a full RIB clone. The mitigation: streaming handlers must drop the snapshot before their
first yield point. Watch handlers already do this correctly — each event is carried by
the broadcast channel, not by a retained snapshot reference. New streaming RPCs must be
audited for this before merging.

---

## ADR-003 — `LOCAL_ORIGIN_PEER` sentinel for originated routes

**Date:** 2026-06-09  
**Status:** Accepted

### Context

Routes injected via the origination API (`OriginateRoute` gRPC) need a `PeerId` to
participate in `LocRib` best-path selection alongside peer-learned routes. Options:

- **Separate code path:** skip `LocRib` for originated routes; apply a priority rule.
- **Sentinel PeerId:** use a reserved address (`0.0.0.0`) as the peer identity for all
  locally originated routes. They compete in normal RFC 4271 best-path selection.

### Decision

Sentinel `PeerId` (`Ipv4Addr::new(0, 0, 0, 0)`, constant `LOCAL_ORIGIN_PEER`).

### Rationale

Keeping originated routes in the same `LocRib` best-path pipeline:
- Maintains one code path for RIB reads, export policy, UPDATE generation.
- Correctly handles the case where a peer-learned route and an originated route compete
  for the same prefix — RFC 4271 best-path rules apply, which is the correct behavior.
- Import policy is **not** applied to originated routes — they bypass `AdjRibIn` and go
  directly into `LocRib`. This matches GoBGP `TABLE_TYPE_GLOBAL` semantics: the caller
  asserts the route is correct as injected.

### Consequences

- `0.0.0.0` must never be a real peer address. This is enforced by `bgp_id` validation
  (RFC 4271 §6.2 requires a non-zero BGP Identifier) and by the fact that `0.0.0.0` is
  not a valid unicast router address.
- `peer_address = "0.0.0.0"` appears in `ListRoutes` output for originated routes,
  distinguishing them from peer-learned routes.

---

## ADR-004 — Static dispatch throughout the BGP data path

**Date:** 2026-06  
**Status:** Accepted

### Context

All hot-path functions in `pathvectord` (`propagate_prefix`, `handle_update`,
`flush_updates`, `prepare_outbound`) could have been written as trait methods with dynamic
dispatch or as generic functions monomorphized at compile time.

### Decision

Concrete monomorphic functions taking `Ipv4Addr`-specialized types. No generics, no trait
objects in the BGP event loop.

### Rationale

The implementation is dual-stack (IPv4 and IPv6). Generics were introduced when IPv6 support
was added — `LocRib<A>`, `AdjRibIn<A>`, `AdjRibOut<A>` are all generic over `IpAddress`.
The outbound pipeline has parallel `propagate_prefix` / `propagate_prefix_v6` functions in
`pathvectord/src/outbound.rs` rather than a single generic function, because the wire format
differs substantially (MP_REACH_NLRI vs traditional NLRI fields) and the additional
abstraction would obscure the protocol differences without simplifying the code.

The only `dyn` usage in the data-adjacent path is:
- `Pin<Box<dyn Stream<...>>>` in tonic streaming handlers — required by tonic's trait
  definition, unavoidable.
- `Vec<Box<dyn EvaluateTerm<R>>>` in the policy engine — see ADR-001.

### Consequences

- Zero vtable overhead in the BGP event loop.
- The concrete types made the required IPv6 changes obvious when they were added.
