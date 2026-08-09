# Concept: BlockingArbiter-shaped performance and storage

## Status

Concept and measurement plan. No implementation is implied by this document.

**Phase 0 and Phase 1 shipped 2026-08-08.** All benchmark claims below were
independently fact-checked against the code before implementation began, a
Plan sub-agent review caught one real design flaw before it shipped (Item
5's original design would have used derived `PartialEq`, which includes a
volatile `received_at` timestamp and would have made the fast path almost
never fire), and every behavior-changing item was real-teeth verified
(production logic temporarily broken, confirmed the corresponding test
failed for the exact right reason, then restored). See the per-item
"Shipped" notes below for exact numbers and `plans/performance-history.md`
for the consolidated benchmark log. Phases 2-6 remain concept-only.

## Motivation

BlockingArbiter is a separate reconciler that collects IP addresses from multiple
sources and controls a BGP speaker over gRPC. Its Rust implementation is expected to
use `pathvector-client` to originate and withdraw routes through `pathvectord`.

This is a narrower workload than a general internet-edge router:

- most routes are locally originated host routes (`/32` and possibly `/128`);
- many or all routes share the same next hop and community set;
- changes arrive as desired-state reconciliation batches;
- the number of BGP peers is small;
- fast, exact withdrawal matters more than longest-prefix lookup;
- listing current originated state may happen during controller startup or recovery.

The workload creates optimization opportunities that full-table benchmarks do not
fully expose. In particular, the repeated object is often the route attribute set,
not the IP prefix itself.

## Current baseline

Pathvector has already completed substantial RIB memory work:

- `Nlri<Ipv4Addr>` is an 8-byte, copyable key rather than a string;
- `LocRib` uses a flat `AHashMap<(Nlri, PeerId), Route>` candidate table;
- the per-prefix peer index stores up to four peers inline with `SmallVec`;
- the best-path table stores only the winning `PeerId`, not another `Route`;
- uncommon attributes are held behind `Option<Box<RareAttrs>>`;
- AS paths are `Arc` backed and routes decoded from one UPDATE can share them;
- locally originated empty AS paths share one process-wide allocation;
- outbound NLRIs with identical attributes are grouped into batched UPDATEs;
- jemalloc is used by the daemon and performance harnesses.

The synthetic origination history in [`performance-history.md`](performance-history.md)
shows that these changes brought Pathvector close to or below GoBGP's peak RSS while
remaining faster in that workload. The most recent recorded cumulative 900k-route
phase used 515.5 MB for Pathvector and 759.8 MB for GoBGP. These results are useful,
but they do not establish performance under concurrent gRPC reads, multiple peers,
real BlockingArbiter attributes, or sustained reconciliation churn.

The plan therefore starts with measurement rather than changing the prefix key.

### `routemap` placement matters

Pathvector uses the `routemap` crate in two materially different roles:

- `pathvector-rpki` uses `RouteMap` for prefix-coverage/LPM queries, which matches the
  treebitmap's lookup-oriented design;
- `LocRib::best` uses `RouteMap<A, PeerId>` as its best-peer index, but almost all of
  its runtime operations are exact-prefix `get`/`insert`/`remove` operations.

`RouteMap` intentionally trades insert speed for compact, cache-friendly LPM lookup.
Its stride-4 treebitmap walks up to 8 nodes for an IPv4 `/32` and 32 nodes for an IPv6
`/128`; inserting a missing child or value also maintains compact vectors with
`Vec::insert`. That is a good trade for read-heavy coverage and forwarding lookups,
but it may be the wrong trade for an update-heavy best-path index.

At the time this plan was written, `LocRib::longest_match` has tests but no production
call site elsewhere in the Pathvector workspace. The daemon's best-route, propagation,
and management paths use exact prefix lookups and iteration. This makes the placement
of `RouteMap` inside `LocRib` a higher-priority measurement target than changing
`RouteMap` itself.

## Goals

1. Define a reproducible BlockingArbiter-shaped workload.
2. Bound convergence latency, event-loop stalls, and memory at the supported scale.
3. Reduce repeated allocation for routes with identical attributes.
4. Avoid multiplying full route state by the number of BGP peers.
5. Remove pathological copy-on-write behavior during large management reads.
6. Reduce gRPC formatting, parsing, and peak-memory overhead for large batches.
7. Preserve exact route semantics: an optimization must never widen a host route.

## Non-goals

- Automatically aggregating blocked host routes into broader prefixes.
- Replacing exact-match maps with a trie without a measured containment workload.
- Optimizing for a full internet table before the intended deployment envelope is
  known.
- Weakening RFC behavior, policy evaluation, or Adj-RIB-Out consistency to gain
  throughput.
- Sharing mutable attributes between routes.

## Phase 0: Capture the production-shaped workload

**Partially shipped 2026-08-08** — scoped down to what Phase 1's
data-structure-level changes actually needed: `pathvector-rib/benches/
loc_rib_reconcile.rs` (scenarios 1 and 3 above, plus a shared-attribute
`/32`-heavy vs. mixed-prefix contrast) and `best_index.rs` (isolated
`RouteMap` vs. `AHashMap` comparison). Scenarios 6-9 (slow peer, concurrent
management reads, restart/resync, 24h soak) need the heavier gRPC/Docker
harness this document's own Phase 4/6 sections describe — deliberately
deferred until those phases are actually scoped, rather than built ahead
of a concrete need. See `plans/performance-history.md` for results.

Before changing storage, add a benchmark profile with parameters matching the planned
deployment:

| Parameter | Values to record |
|---|---|
| Address families | IPv4 only, or IPv4 and IPv6 |
| Route shape | `/32`, `/128`, or mixed prefixes |
| Steady-state route count | Expected, high-water mark, and hard limit |
| Reconcile batch | Typical and maximum additions, changes, and withdrawals |
| Sources | Count and overlap between source sets |
| Attributes | Exact next hop and standard/large/extended communities |
| Peers | Count, peer type, and negotiated message size |
| Churn | Changes per second and full-reconcile frequency |
| Management reads | Frequency of list/watch operations during churn |

The harness should exercise at least these scenarios:

1. empty to full desired set;
2. full set to empty;
3. repeated one-percent churn;
4. re-originating existing prefixes with unchanged attributes;
5. changing the shared attribute set for all prefixes;
6. one healthy and one deliberately slow outbound peer;
7. concurrent `ListOriginatedRoutes` calls during mutation;
8. daemon restart followed by controller resynchronization;
9. repeated announce/withdraw cycles for at least 24 hours in a soak job.

Record total reconciliation time, time to downstream RIB convergence, p50/p95/p99
gRPC latency, event-loop lock-hold time, peak/final RSS, allocation count if available,
outbound UPDATE count, session resets, and route-set divergence.

Do not use an RPC success response as the final convergence signal. Verify the exact
received route set at a real or instrumented BGP peer.

## Phase 1: Low-risk improvements

**Shipped 2026-08-08** — Items 1, 3, 4, and 5 implemented as designed below;
Item 2's benchmark justified implementing the swap too. See each item's own
"Shipped" note for numbers and `plans/performance-history.md` for the full
benchmark log.

### 1. Remove temporary allocation from single-candidate best-path selection

`LocRib::recompute_best` currently clones every candidate for one prefix into a fresh
temporary `AHashMap`. `select_best_with_oracle` then allocates a reachable-candidate
`Vec`, a neighboring-AS grouping `HashMap`, a `Vec` for each group, and a group-winner
`Vec`.

Those structures support correct MED comparison across several neighboring ASes, but
the dominant BlockingArbiter case is a locally originated prefix with exactly one
candidate. For that case, the result is known after checking next-hop reachability:

```rust
match peers.as_slice() {
    [peer] => {
        let route = &candidates[&(nlri, *peer)];
        if route.next_hop.as_ref().is_none_or(|nh| oracle.is_reachable(nh)) {
            best.insert(nlri.prefix(), *peer);
        } else {
            best.remove(nlri.prefix());
        }
    }
    _ => select_best_without_cloning(...),
}
```

The eventual API should avoid exposing map-specific requirements: best-path selection
can accept an iterator of `(PeerId, &Route)` or a borrowed candidate slice. The
multi-candidate path can then group borrowed references without cloning full routes,
and later work can reduce its temporary allocations independently.

Success criteria:

- zero route clones and zero temporary collections for one-candidate recomputation;
- materially improved local origination and withdrawal throughput;
- identical next-hop reachability behavior;
- RFC-clause-derived decision-process tests remain unchanged and pass;
- multi-candidate MED behavior remains deterministic and unchanged.

Although this is intended as a behavior-preserving fast path, implementation must
follow the RFC-reading and independent-test discipline in `AGENTS.md` because it
touches the best-path decision boundary.

**Shipped 2026-08-08** — implemented in `LocRib::recompute_best`
(`pathvector-rib/src/loc_rib.rs`) as a 3-way match on the `peer_index` slice
length rather than the sketched `match peers.as_slice()` form, reusing the
same `next_hop.as_ref().is_none_or(...)` expression `best_path.rs`'s Step 1
filter uses. Proven behaviorally identical to the general path via a new
differential proptest,
`prop_tests::prop_single_candidate_fast_path_matches_general_path`
(constructs a real `LocRib` and an equivalent one-entry `HashMap`, asserts
`select_best_with_oracle` agrees for every combination of NEXT_HOP
presence, reachability, LOCAL_PREF, and `stale`). Real-teeth verified:
inverting the fast path's reachability check made the proptest fail with a
concrete counterexample; reverted and reconfirmed. Combined with Item 5
below (both land on the same dominant single-candidate path), measured
~40-63% faster for single-candidate empty-to-full/idempotent-reorigination/
1%-churn workloads at n=100k — see `plans/performance-history.md`.

### 2. Benchmark and reconsider the Loc-RIB best index

Compare the current `RouteMap<A, PeerId>` best index with an
`AHashMap<Nlri<A>, PeerId>` under four workloads:

1. BGP-shaped mixed prefix lengths;
2. random IPv4 `/32` routes;
3. random IPv6 `/128` routes;
4. repeated updates and withdrawals of an established table.

Measure the index in isolation and through `LocRib::insert`/`withdraw`, because route
cloning and best-path recomputation may dominate the end-to-end result.

If the hash index wins materially for the intended workload, the simplest design is:

```rust
struct LocRib<A: IpAddress> {
    candidates: CandidateMap<A>,
    peer_index: PeerIndex<A>,
    best: AHashMap<Nlri<A>, PeerId>,
}
```

Keys in the hash index must be canonicalized with `masked()` on every insertion and
query so this preserves `RouteMap`'s existing treatment of host bits.

`LocRib::longest_match` can then probe exact prefixes from most-specific to least-
specific against the hash map. That changes a rare LPM read to at most 33 exact probes
for IPv4 or 129 for IPv6 while making every best-path mutation a single hash-table
operation. If a future forwarding workload needs frequent LPM, alternatives include an
optional secondary `RouteMap`, a periodically rebuilt read index, or a dedicated FIB
view. Maintaining both indexes synchronously should not be the default unless measured
LPM demand justifies paying both write costs.

This change would not imply a weakness in `routemap`; it would align each structure
with its intended workload. Continue using `RouteMap` where covering-prefix or frequent
LPM queries are intrinsic, including the RPKI table.

Success criteria:

- improved host-route insertion and withdrawal throughput through `LocRib`;
- no meaningful regression in exact best-route queries or full-table iteration;
- documented worst-case cost for the retained `LocRib::longest_match` API;
- no change to `pathvector-rpki`'s `RouteMap` usage;
- property tests compare hash-probe LPM results against `RouteMap` as an oracle.

**Shipped 2026-08-08** — benchmarked (`pathvector-rib/benches/best_index.rs`,
n=100k, `/32`-heavy and mixed-prefix shapes) before deciding: `AHashMap` won
every operation and shape measured — insert 37% (`/32`) / 19% (mixed)
faster, get 32% / 16% faster, remove 48% / 28% faster. This materially
justified the swap per the exit criteria above, so it was implemented in
the same commit: `LocRib::best` is now `AHashMap<Nlri<A>, PeerId>`, keys
canonicalized with `.masked()` on every insert/query exactly as specified.
`longest_match` is now a bounded exact-probe loop from `A::BITS` down to
`0` (confirmed via decode-path inspection that production NLRIs are
already masked at wire-decode time — `pathvector-session`'s
`decode_nlri_v4`/`_v6` — so this defense-in-depth masking is normally a
no-op, not load-bearing). `pathvector-rpki`'s own `RouteMap` usage is
untouched. Property-test oracle added:
`prop_tests::prop_longest_match_matches_routemap_oracle`, which — after an
initial version that only queried fully-random addresses passed even with
a deliberately broken probe range (a random query almost never lands
exactly on a stored prefix) — was strengthened to also query every
inserted prefix's own exact address, at which point the real-teeth check
(reverting the probe range to `0..A::BITS`, silently skipping the exact
`/32` case) correctly failed.

### 3. Reserve capacity for batch origination

`OriginateRoutes` knows the batch size, but the originated set and `LocRib` maps grow
incrementally. Add `with_capacity`/`reserve` operations to `LocRib` and reserve before
large batch insertion.

Candidate structures include:

- `RibSnapshot::originated_routes` and `originated_routes_v6`;
- `LocRib::candidates`;
- `LocRib::peer_index`;
- an `AHashMap` best index, if the preceding experiment supports that change;
- per-peer pending decision vectors.

Success criterion: fewer allocations and no throughput regression at small batches;
measure RSS and latency at 100k, 500k, and the deployment high-water mark.

**Shipped 2026-08-08** — `LocRib::with_capacity`/`reserve` added (also
reserves the `best` index now that it's an `AHashMap`, not just
`candidates`/`peer_index`), wired into `originate_routes`/`_v6`
(`pathvectord/src/daemon/origination.rs`) with the known batch length,
including `RibSnapshot::originated_routes`/`_v6`.

### 4. Use the internal fast hasher consistently

`LocRib`, `AdjRibIn`, and `AdjRibOut` use `AHashMap`, while the originated-route sets
currently use the standard `HashSet`. Evaluate `AHashSet` for originated route tracking.

This is expected to be a small CPU improvement, not a transformational memory change.

**Shipped 2026-08-08** — broader than originally scoped: swapped
`RibSnapshot::originated_routes`/`_v6`, `daemon/gr.rs`'s
`stale_nlri`/`stale_nlri_v6`/`prev_set`, and `daemon/peer.rs`'s
stale-now snapshot sets to `AHashSet`/`AHashMap` (all internal NLRI
bookkeeping, never attacker-controlled — same rationale `LocRib` already
uses). `mrai_last_sent` was left as std (not explicitly in scope; a
follow-up candidate if Phase 6 revisits MRAI storage).

### 5. Avoid work for identical re-origination

`LocRib::insert` conservatively reports an announcement when the current winning peer
updates because the old route has already been replaced. Preserve or compare a compact
attribute fingerprint so an identical idempotent origination can return `Unchanged`.

This matters when BlockingArbiter periodically reasserts its complete desired set.
Hash collisions must not suppress a real update: use the fingerprint to select a fast
path, then confirm equality where required.

**Shipped 2026-08-08** — a Plan sub-agent review caught a real design flaw
before implementation: using `Route`'s derived `PartialEq` (the original
"fingerprint" idea) would include `received_at`, a wall-clock construction
timestamp that differs on every independent `RouteBuilder::build()` call —
meaning the fast path would almost never fire for exactly the
re-origination pattern it targets. Implemented instead as
`Route::content_eq` (`pathvector-rib/src/route.rs`), a manual field
comparison excluding `received_at` but including `stale` (an RFC 4724
§4.2 fresh/stale transition is a real best-path-relevant change — verified
against `daemon/gr.rs`'s `mark_stale_and_repropagate`), using an exhaustive
field destructure (no `..`) so a future new `Route` field fails to compile
here until someone decides whether it belongs in content equality. Two new
unit tests pin both directions
(`test_insert_identical_content_by_winner_is_unchanged`,
`test_insert_stale_flip_by_winner_is_announced`). Real-teeth verified in
two independent, deliberately-isolated passes (disabling the gate alone,
then separately excluding `stale` from `content_eq` alone — an initial
combined attempt where both bugs were injected at once produced a
false-pass because the two bugs happened to cancel out on that specific
test, which is itself worth remembering for future real-teeth passes on
this file).

## Phase 2: Intern immutable route attributes

### Problem

BlockingArbiter-originated routes are likely to differ only by NLRI. Today each route
contains the full route shape and a route carrying communities owns a `RareAttrs` box
whose vectors are cloned as the route moves through RIB and outbound-policy paths.

### Proposed model

Split the prefix and per-route metadata from immutable path attributes:

```rust
struct Route<A: IpAddress> {
    nlri: Nlri<A>,
    attrs: Arc<RouteAttributes>,
    metadata: RouteMetadata,
}

struct RouteAttributes {
    origin: Origin,
    as_path: AsPath,
    next_hop: Option<NextHop>,
    local_pref: Option<LocalPref>,
    med: Option<Med>,
    rare: RareAttrs,
}
```

The exact field split should be determined by best-path and policy mutation needs.
Attributes that affect local selection but are never sent may belong in metadata.

An interner maps attribute content to a weakly held canonical `Arc<RouteAttributes>`.
Routes sharing an attribute set then pay one allocation for that set. Export policy
uses copy-on-write and interns the result when beneficial.

### Design constraints

- equality remains semantic, not pointer-only;
- the interner must not retain unused attribute sets forever;
- mutable policy evaluation must not modify attributes visible to another route;
- unknown transitive attributes and all community types remain lossless;
- per-peer next-hop and AS-path rewrites may create different outbound attribute sets;
- interning overhead must be bypassable when attribute diversity is high;
- tests must cover attributes that are equal but were constructed in different orders
  where ordering is or is not semantically significant.

### Success criteria

- material RSS reduction for 100k+ routes sharing BlockingArbiter attributes;
- fewer allocations during origination and full-table export;
- no regression for high-diversity MRT input;
- unchanged wire output and policy behavior in unit, property, and e2e tests.

## Phase 3: Compact Adj-RIB-Out state

### Problem

Every `AdjRibOut` currently stores a full `Route` for every advertised prefix. With
multiple peers, locally originated route state is multiplied by peer count even when
the peers receive identical attributes.

### Proposed model

Store the minimum state necessary to determine whether a peer needs an announcement or
withdrawal:

```rust
struct AdvertisedRoute {
    attrs: AttributeSetId,
    generation: u32,
}

type AdjRibOut<A> = AHashMap<Nlri<A>, AdvertisedRoute>;
```

`AttributeSetId` may identify interned post-export attributes. A generation is optional
and should only be retained if it simplifies session resets or table replacement.

The design must still support:

- exact detection of attribute changes;
- iBGP split-horizon and route-reflector behavior;
- confederation attribute transformations;
- peer-specific next-hop rewriting;
- complete full-table replay after session establishment;
- removal of all state when a peer is reset.

### Success criteria

Measure RSS as peers increase from 1 to 2, 4, 10, and 50. Per-peer memory growth should
approach the size of `NLRI + compact advertised state + map overhead`, rather than a full
route and independently allocated attributes.

## Phase 4: Remove the whole-RIB snapshot clone cliff

### Problem

`DaemonState` exposes an `Arc<RibSnapshot>` to gRPC readers and mutates it with
`Arc::make_mut`. This is O(1) while no reader holds a snapshot, but a concurrent reader
causes the next mutation to clone the full snapshot, including `LocRib` maps.

Large route-list RPCs are the dangerous case: they retain the snapshot while walking
and serializing the table. BlockingArbiter may issue exactly such a call during startup
reconciliation while route updates continue.

### Candidate approaches

Evaluate these in increasing order of architectural complexity:

1. Add pagination and bounded page sizes to list RPCs.
2. Under a short read lock, copy only compact route records needed for the response,
   then serialize after releasing the lock.
3. Add a reconciliation digest or server-side diff API so clients rarely list the
   complete table.
4. Maintain a dedicated management read model updated asynchronously from route events.
5. Shard immutable snapshots so a mutation copies only one prefix partition.

The first benchmark should hold a `RibSnapshot` during continuous updates and record
the mutation latency and RSS spike. Do not select a replacement architecture until
this failure mode is reproduced and quantified.

### Success criteria

- bounded mutation pause while a full management read is in progress;
- bounded transient memory overhead;
- a slow gRPC client cannot retain a full internal snapshot indefinitely;
- readers receive documented snapshot or pagination consistency semantics.

## Phase 5: Compact gRPC prefix representation

### Problem

The management API currently transmits prefixes and next hops as strings. A large
origination replay therefore formats, allocates, validates, and reparses values already
held numerically by the controller.

### Proposed compatible extension

Add a binary prefix form without immediately removing the existing string fields:

```protobuf
message IpPrefix {
  // Exactly 4 bytes for IPv4 or 16 bytes for IPv6, in network byte order.
  bytes address = 1;
  uint32 prefix_length = 2;
}
```

New request fields can prefer `IpPrefix`; old clients continue using CIDR strings.
Reject requests that provide both forms with conflicting values. Define duplicate and
conflict behavior explicitly and test it.

Also measure chunked or client-streaming origination against one large unary protobuf
message. Chunking should limit peak request memory while preserving validation and
failure semantics.

### Success criteria

- reduced serialized size and CPU for large host-route batches;
- no repeated CIDR string parsing on the new path;
- bounded peak memory at the maximum request size;
- backward compatibility for the current `pathvector-client` API.

## Phase 6: MRAI storage, only if profiling justifies it

Pathvector stores an `Instant` for each `(peer, prefix)` last-announcement time and a
set of suppressed prefixes. This can be a significant secondary index for large,
frequently changing originated sets.

Potential designs include compact monotonic timestamps, timestamp interning for a
batch, expiry buckets, or a timing wheel. This is not an early optimization: first
measure the table's memory and timer-scan cost under the real churn profile.

Any implementation change is RFC-governed. Before modifying behavior, fetch and read
the applicable RFC 4271 MRAI clauses and all amendments, derive expected behavior from
that text, and add independent clause-cited tests as required by `AGENTS.md`.

## Storage concepts for BlockingArbiter-RS

BlockingArbiter is a separate project, so these ideas are not direct Pathvector work.
They describe how its source reconciliation can avoid unnecessary set materialization
before sending changes to Pathvector.

### Normalize IPs at ingestion

Do not retain textual IP addresses as internal keys:

```rust
enum IpKey {
    V4(u32),
    V6(u128),
}
```

Use strings only at external boundaries. The standard `IpAddr` enum is also a sensible
starting point; a custom key should be adopted only if layout measurements show value.

### Track source ownership on each IP

When the configured source count is at most 64, a bit mask makes overlap cheap:

```rust
struct DesiredIp {
    source_mask: u64,
    attrs: AttributeSetId,
}
```

The transition from no bits to one bit triggers origination. The transition from one
bit to no bits triggers withdrawal. Other source changes do not touch BGP state.

For more sources, use a reference count when source identity is not required, or a
`SmallVec<[SourceId; 2]>` when it is.

### Reconcile source snapshots incrementally

Retain the previous set for each source and calculate:

```text
added   = new_source_set - old_source_set
removed = old_source_set - new_source_set
```

Update aggregate ownership only for those differences. The cost then follows source
churn rather than total desired-set size.

### Consider Roaring bitmaps only for suitable IPv4 data

`RoaringBitmap` can provide compact storage and fast set algebra for large IPv4 sets
with locality. It may be worse than a hash set for small or uniformly random sets, and
it does not naturally solve 128-bit IPv6 storage. Benchmark real source distributions
before adopting it.

### Use a radix trie only for prefix operations

A Patricia/radix trie is valuable for containment, longest-prefix match, or identifying
redundant covered prefixes. It is usually unnecessary for exact `/32` and `/128`
membership, where a hash set is simpler and faster.

### Never widen a route as a storage optimization

Multiple blocked hosts must not be converted to a covering prefix unless the product's
policy explicitly authorizes blocking every address in that covering prefix. Internal
compression must preserve the exact advertised set.

## Recommended execution order

1. Add the BlockingArbiter-shaped benchmark and supported-scale parameters.
2. Add the allocation-free single-candidate best-path fast path and measure it.
3. Benchmark `RouteMap` versus `AHashMap` as the Loc-RIB best index, especially for
   `/32`, `/128`, update, and withdrawal workloads.
4. Reproduce and measure concurrent management-read copy-on-write behavior.
5. Add capacity reservation and identical-route suppression.
6. Prototype complete attribute-set interning behind the existing `Route` API.
7. Measure and prototype compact Adj-RIB-Out state.
8. Add a backward-compatible binary prefix API and benchmark chunking/streaming.
9. Revisit MRAI storage only if it is material in profiles.
10. Evaluate specialized BlockingArbiter containers using real source distributions.

Each stage should be a separate change with before/after benchmark evidence. Retain a
stage only when it improves the targeted workload without materially regressing MRT,
multi-peer, policy-heavy, or small-table cases.

## Likely files involved

| Area | Files |
|---|---|
| Workload harness | `pathvector-stress/src/main.rs`, `pathvector-stress/README.md` |
| Best-index comparison | `pathvector-rib/src/loc_rib.rs`, `pathvector-rib/benches/loc_rib_insert.rs` |
| Route representation | `pathvector-rib/src/route.rs` |
| Loc-RIB capacity and equality | `pathvector-rib/src/loc_rib.rs` |
| Adj-RIB-Out compaction | `pathvector-rib/src/adj_rib_out.rs`, `pathvectord/src/outbound.rs` |
| Origination batching | `pathvectord/src/daemon/origination.rs`, `pathvectord/src/grpc.rs` |
| Snapshot/read model | `pathvectord/src/daemon/mod.rs`, `pathvectord/src/grpc.rs` |
| Prefix wire format | `proto/pathvector/v1/management.proto`, `pathvector-client` |
| Benchmarks | `pathvector-rib/benches`, `pathvector-stress` |

## Completion criteria

This initiative is complete for the BlockingArbiter deployment profile when:

- the supported route, peer, batch, and churn envelope is published;
- the production-shaped benchmark and soak workload are reproducible;
- peak RSS and convergence remain within their documented budgets;
- management reads do not create unbounded clone stalls or memory spikes;
- identical desired-state replays produce no unnecessary BGP advertisements;
- a slow peer does not cause healthy peers to miss negotiated hold timers;
- downstream peers converge to the exact desired prefix and attribute set;
- all changes retain protocol, property, and e2e test coverage.
