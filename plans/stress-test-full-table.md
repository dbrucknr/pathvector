# Plan: Full-Table Stress Test

## Motivation

pathvector has not been tested beyond a handful of routes. Before any performance
comparison with GoBGP or BIRD is meaningful, we need to verify correctness and
stability under a realistic internet-scale load (~950k IPv4 prefixes). Performance
numbers measured against a buggy implementation are noise.

## Stages

### Stage 1 — Synthetic load via gRPC (no Docker, runnable today)

Drive `originate_route` at scale through `PathvectorClient` to shake out panics,
OOMs, and incorrect best-path results before touching real BGP wire traffic.

**Target sizes:** 10k → 100k → 500k prefixes  
**Metric:** does pathvectord stay up, memory stable, route count matches injected count?

Open questions to resolve here:
- **`list_routes` hits the 4 MB gRPC message limit at ~26k routes** (confirmed
  2026-06-17). The response body for 100k routes exceeds the default tonic limit.
  Needs either: (a) a `CountRoutes` RPC, (b) server-side pagination on
  `ListRoutes`, or (c) a `WatchRoutes` snapshot count. The stress harness works
  around this by trusting `originate_routes`' synchronous return value as the
  count; but `list_routes` is unusable at scale and must be fixed before the
  gRPC API can be called production-grade.
- Does `LocRib` rehash at scale cause latency spikes visible in hold-timer health?
- Are there any `unwrap()` / `expect()` panics hiding in low-frequency RIB paths?

**Files to create:**
- `stress/src/main.rs` — a small binary (or e2e test) that drives the gRPC API
  to originate N routes and verifies the count via `ListRoutes`

### Stage 2 — MRT replay via ExaBGP (real BGP wire traffic)

Once synthetic load passes, replay a real RouteViews MRT dump through ExaBGP
peering over TCP. This catches anything the gRPC path misses: real AS path
diversity, communities, AGGREGATOR attributes, and malformed-but-tolerated paths.

**MRT source:** RIPE RIS or RouteViews (publicly available, ~300 MB gzip)  
**Conversion:** `exabgp-mrt` converts the dump to ExaBGP `announce` format

**Docker composition:**
```
exabgp  ──BGP──►  pathvectord
```
Poll pathvectord gRPC until prefix count stabilises (no change for 5s).

**Metrics:**
- Time to convergence (session Established → RIB stable)
- Peak RSS (`docker stats`)
- Hold-timer health (did any KEEPALIVE slip?)
- Final prefix count matches MRT dump prefix count

**Known prerequisites before Stage 2 is reliable:**
- Full-table dump lock-hold (TODO: Performance concern #3) should be measured —
  `on_established` holds the write lock for the full initial dump; at 950k routes
  this is a multi-millisecond stall that could cause hold-timer expiry
- NLRI batching (Performance concern #2) not required for correctness but will
  affect convergence time numbers

### Stage 3 — Comparative benchmark (pathvector vs GoBGP vs BIRD)

Run the same Stage 2 scenario against GoBGP 4.x and BIRD 2.x on identical
hardware with equivalent config (one eBGP peer, accept-all import policy).

Present results in the three-size / Takeaway table format. Hardware: Apple M2 Max.

## Stage 1 baseline (2026-06-17, M2 Max, release binary)

| Phase | Routes | Time (s) | Peak RSS | Final RSS | ERRORs |
|---|---|---|---|---|---|
| 10k  | 10,000  | 0.04 | 30.3 MB  | 30.3 MB  | 0 |
| 100k | 100,000 | 0.28 | 236.7 MB | 236.7 MB | 0 |
| 500k | 500,000 | 1.24 | 1.3 GB   | 1.3 GB   | 0 |

Throughput: ~400k routes/sec via gRPC origination.  
Memory: ~2.6 KB/route — linear scaling, no obvious bloat.  
Extrapolated full table (~950k routes): ~2.5 GB RSS.

**Withdrawal reclamation (2026-06-17):** withdrawing all 500k routes reclaims
only 7% of RSS (93 MB of 1.3 GB). This is expected allocator page-retention
behavior (jemalloc / system allocator holds freed pages for reuse rather than
returning them to the OS). Confirmed not a leak: churn RSS is flat across 5
announce/withdraw cycles at 1.2 GB.

**Memory gap vs GoBGP**: GoBGP holds a full table in ~500–800 MB. The likely
causes are HashMap-backed RIB structures and full attribute clones per route
rather than interned/shared attributes. Worth profiling before the Stage 3
comparison.

## Success criteria

- Stage 1: zero panics, zero OOM, route count exact at 500k
- Stage 2: convergence completes, no hold-timer expiry, prefix count matches MRT
- Stage 3: pathvector convergence time and RSS within 2× of GoBGP (acceptable gap
  for a first implementation; identify root causes if larger)

## Stage 1b — GoBGP 1:1 comparison (2026-06-17, M2 Max, release binary)

Same harness, same batch size (500), same host.  GoBGP 4.5.0 vs pathvectord.
Route injection via each daemon's native gRPC API: `AddPathStream` (GoBGP) vs
`originate_routes` (pathvectord).

### Convergence time

| Phase | pathvectord | GoBGP 4.5.0 | Ratio (pv/go) |
|---|---|---|---|
| 10k  | 0.03 s | 0.05 s | 0.48× |
| 100k | 0.21 s | 0.38 s | 0.54× |
| 500k | 0.85 s | 1.62 s | 0.52× |

**Takeaway:** pathvectord converges roughly **2× faster** than GoBGP at all
three sizes.  This reflects the gRPC overhead difference between the two
implementations, not just BGP processing — the API encoding (strongly-typed
oneofs in GoBGP v4 vs. repeated messages in pathvector-client) may contribute.
Worth profiling to separate RIB insertion cost from transport overhead.

### Peak RSS

| Phase | pathvectord | GoBGP 4.5.0 |
|---|---|---|
| 10k  | 33.9 MB  | 50.7 MB  |
| 100k | 265.1 MB | 121.3 MB |
| 500k | 1.4 GB   | 451.8 MB |

**Takeaway:** GoBGP is dramatically more memory-efficient at scale (~3× at
500k routes).  pathvectord's ~2.6 KB/route vs GoBGP's ~0.9 KB/route.  The
likely causes: HashMap-backed `LocRib` with full attribute clones per route
rather than interned/shared attributes.  Attribute interning is the highest-
priority memory optimisation before a Stage 3 comparison.

## Known blockers

- Performance concern #3 (lock-hold during full-table dump) is likely to cause
  hold-timer expiry at 950k routes — fix or measure before Stage 2
- `list_routes` pagination at scale is untested — investigate before Stage 3
- ExaBGP MRT conversion tooling needs to be documented and committed to `bench/fixtures/`
  or downloaded by the harness at runtime

## Related TODO entries

- TODO.md §Performance: concerns #1–4 (event loop, NLRI batching, dump lock-hold, CoW)
- TODO.md §Performance: "System-level benchmarks against GoBGP and BIRD"
- TODO.md §Performance: "Backpressure / sustained churn tests"
