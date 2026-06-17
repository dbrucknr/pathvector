# Performance History

All benchmarks run on M2 Max (Apple Silicon). pathvectord is a release build.
GoBGP version: whatever is in `$PATH` at `/Users/dbrucknr/go/bin/gobgpd`.
Harness: `./target/release/stress` (synthetic gRPC load, single peer, no TCP session).

Numbers are peak RSS from the stress harness `500k` phase unless noted.
Run-to-run variance on GoBGP is ~15 MB; pathvectord ~5 MB.

---

## Baseline (pre-optimization)

Branch: `main` before `rib-memory-opt`

| Phase | pathvectord | GoBGP |
|---|---|---|
| 500k memory | ~1,400 MB | ~450 MB |
| 500k speed | — | — |

Notes: nested `HashMap<Nlri, HashMap<PeerId, Route>>` — inner map allocated per
prefix regardless of peer count. No best-path stored separately; full Route cloned
into best.

---

## Commit: flat CandidateMap + PeerIndex + best stores PeerId only

`git: rib-memory-opt` (first perf commit)

| Phase | pathvectord | GoBGP | pv/go |
|---|---|---|---|
| 10k memory | — | — | — |
| 100k memory | — | — | — |
| 500k memory | 604.8 MB | ~450 MB | 1.34× |
| 500k speed | — | — | — |

Changes:
- `CandidateMap<A> = HashMap<(Nlri<A>, PeerId), Route<A>>` (flat, no nested map)
- `PeerIndex<A> = HashMap<Nlri<A>, HashSet<PeerId>>` (secondary index for O(k) recompute)
- `best: RouteMap<A, PeerId>` stores only winning PeerId, not a full Route clone
- `originated_routes: HashSet<Nlri>` (was `HashMap<Nlri, Route>`)
- Fixed O(N²) hang in `recompute_best` (was scanning all candidates per insert)

---

## Commit: box rare route attributes + Arc<AsPath> interning

`git: 165ca49`

| Phase | pathvectord | GoBGP | pv/go |
|---|---|---|---|
| 10k memory | 13.7 MB | 52.3 MB | 0.26× |
| 100k memory | 74.8 MB | 122.8 MB | 0.61× |
| 500k memory | 481.8 MB | 479.1 MB | 1.006× |
| 500k speed | 0.76 s | 1.86 s | 0.41× |

Changes:
- `Route::rare: Option<Box<RareAttrs>>` — 7 infrequently-set fields (communities,
  cluster_list, aggregator, originator_id, atomic_aggregate) behind a box.
  `None` costs 8 bytes (null ptr) vs 96+ bytes of inline empty Vecs.
- `Route::as_path: Arc<AsPath>` — routes from the same UPDATE share one allocation.
  `Arc::make_mut` used in `prepare_outbound` for CoW AS_PATH prepend.
- `workspace_bin` profile-detection fix — stress harness now always uses matching build profile.

---

## Commit: AHash + SmallVec peer index + u32 timestamp

`git: (latest on rib-memory-opt)`

| Phase | pathvectord | GoBGP | pv/go |
|---|---|---|---|
| 10k memory | 12.4 MB | 51.8 MB | 0.24× |
| 100k memory | 71.3 MB | 131.5 MB | 0.54× |
| 500k memory | 484.1 MB | 443.3 MB | 1.09× |
| 500k speed | 0.76 s | 1.64 s | 0.46× |
| withdrawal (500k) | 0.68 s | — | — |

Changes:
- `AHashMap`/`AHashSet` replaces `std::collections::HashMap`/`HashSet` in `LocRib`
  — eliminates SipHash DoS overhead on internal (non-attacker-controlled) keys.
- `PeerIndex` inner collection: `HashSet<PeerId>` → `SmallVec<[PeerId; 4]>`
  — 4 peers stored inline, no heap allocation for the common case.
- `Route::received_at: u32` (was `Instant`, 16 bytes) — saves 12 bytes/route.
  Step 9 comparison semantics unchanged.

Notes: 500k memory is within GoBGP run-to-run variance (~15 MB). Memory gains
are clearest at 10k/100k where per-prefix overhead dominates over per-route size.

---

---

## Commit: AHashMap in AdjRibIn + AdjRibOut

`git: aba361f`

Changes:
- AHashMap replaces std HashMap in AdjRibIn and AdjRibOut.

Notes: AdjRib maps are per-session; benefit is hash op speed. Memory numbers
unchanged in stress test (originated routes bypass AdjRibIn).

---

## Commit: intern empty AsPath via shared static Arc

`git: (latest)`

| Phase | pathvectord | GoBGP | pv/go |
|---|---|---|---|
| 10k memory | 12.7 MB | 50.7 MB | 0.25× |
| 100k memory | 67.8 MB | 130.8 MB | 0.52× |
| 500k memory | **461.6 MB** | 455.5 MB | **1.01×** |
| 500k speed | 0.67 s | 1.51 s | 0.44× |
| withdrawal (500k) | 0.53 s | — | — |

Changes:
- `RouteBuilder::new` checks `as_path.is_empty()` and reuses a process-wide
  `static OnceLock<Arc<AsPath>>` instead of allocating a new Arc per route.
  `Arc::make_mut` in `prepare_outbound` still gives CoW semantics when prepend
  is needed for eBGP advertisement.

Root cause: 500k originated routes each called `Arc::new(AsPath::new())` → 500k
separate 40-byte heap allocations (16-byte ArcInner + 24-byte empty Vec header)
= ~20 MB. Sharing one Arc collapses this to a single allocation.

Result: −25 MB at 500k, now within noise of GoBGP (461.6 vs 455.5 MB).

---

## Route struct layout audit (80 bytes for Route<Ipv4Addr>)

```
 0- 7: nlri           8 bytes
 8   : origin         1 byte
 9-15: [padding]      7 bytes  ← Arc needs align 8
16-23: as_path Arc    8 bytes
24-40: Option<NextHop>17 bytes
41-47: [padding]      7 bytes  ← next field needs align 8
48-55: Option<LocalPref> 8 bytes
56-63: Option<Med>    8 bytes
64   : peer_type      1 byte
65-67: [padding]      3 bytes
68-71: received_at u32 4 bytes
72-79: rare Option<Box> 8 bytes
= 80 bytes total, 17 bytes padding
```

14 bytes of unavoidable padding due to 17-byte `Option<NextHop>` in an 8-byte aligned
struct. The compiler already applies repr(Rust) field reordering. Reducing further
requires changing `NextHop` to store only the address type matching the route's address
family (`Option<A>` instead of `Option<NextHop>`) — a type-system change to
pathvector-types, saves ~8 bytes/route at the cost of API complexity.

---

---

## Commit: extended stress phases (250k, 750k, 900k)

`git: (latest)`

| Phase | pathvectord | GoBGP | pv/go memory |
|---|---|---|---|
| 10k | 12.7 MB | 51.4 MB | **0.25×** |
| 100k | 67.8 MB | 127.8 MB | **0.53×** |
| 250k | 233.7 MB | 248.2 MB | **0.94×** |
| 500k | 461.5 MB | 443.9 MB | 1.04× |
| 750k | 495.2 MB | 626.8 MB | **0.79×** |
| 900k | 515.5 MB | 759.8 MB | **0.68×** |

Speed (all phases): pathvectord ~2× faster than GoBGP.

Note: phases are cumulative — each phase adds routes on top of the prior one.
Times for 750k/900k reflect the *incremental* batch, not a full cold start.
At 900k pathvectord uses 244 MB less than GoBGP; Go GC overhead compounds at scale.

Crossover point: ~500k routes where per-route cost overtakes Go runtime overhead.
Below 250k pathvectord uses less; above 500k pathvectord uses significantly less.

---

## Next candidates

| Candidate | Expected saving | Complexity |
|---|---|---|
| Pre-size LocRib maps with `with_capacity` (config hint) | Reduce resize allocations | Low |
| Route next_hop as `Option<A>` (family-typed) | 8 bytes/route, 4 MB at 500k | Requires type change in pathvector-types |
| AsPath interning across peers (intern table in daemon) | Depends on AS path diversity | Medium |
| `Option<LocalPref>` / `Option<Med>` → NonZero sentinel | 4 bytes/field saved, 2 MB each | Requires type change |
