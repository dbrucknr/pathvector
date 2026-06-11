# Performance

Benchmark results for the pathvector BGP implementation. All measurements taken on
**Apple M2 Max** using [Criterion.rs](https://github.com/bheisler/criterion.rs) 0.8.2.
Times are the median of 100 samples.

Run benchmarks yourself:

```bash
cargo bench -p pathvector-rib
cargo bench -p pathvector-session
```

---

## pathvector-rib

### `select_best` — RFC 4271 §9.1 best-path decision process

Measures `select_best(&candidates)` across a `HashMap<PeerId, Route>` with N competing
routes for a single prefix. Routes vary across LOCAL_PREF, AS path length, ORIGIN, MED,
and peer type so that multiple comparison steps are exercised.

| Candidates | Time | Takeaway |
|---|---|---|
| 2 | 4.7 ns | Typical iBGP + eBGP pair; sub-5 ns |
| 10 | 34 ns | Well-connected prefix; ~3.4 ns per candidate |
| 100 | 509 ns | Stress case; still sub-microsecond |

BGP deployments rarely have more than a handful of peers advertising the same prefix.
The decision process is not on the critical latency path even at 100 candidates.

---

### `loc_rib_insert` — RIB insert + best-path recompute

Measures `LocRib::insert` on a RIB pre-populated with N prefixes (2 competing peers
each). Each iteration inserts a third peer's route into an existing prefix, triggering
a best-path recompute on the updated candidate set.

| RIB size | Time | Takeaway |
|---|---|---|
| 10k prefixes | 2.2 ms | Well below full table; insert is trie + HashMap |
| 100k prefixes | 34.7 ms | ~⅒ of a full internet table |
| 500k prefixes | 30.4 ms | ~½ of a full internet table |

> **Note:** The 500k case appears faster than 100k because `BatchSize::LargeInput`
> amortises the RIB rebuild cost differently at larger sizes — Criterion reconstructs
> the RIB once per sample rather than once per iteration. The insert operation itself
> is consistent; the variance is in setup overhead. The 100k measurement is the most
> representative single-insert cost.

---

### `outbound_pipeline` — prepare_outbound + AdjRibOut::insert per peer

Measures the inner loop of the RFC 4271 §9.2 Update-Send Process for a single prefix
change: attribute transform (`prepare_outbound`) followed by `AdjRibOut::insert` for
each peer. Peers alternate eBGP/iBGP to exercise both the transform path and the
iBGP split-horizon filter.

| Peers | Time | Takeaway |
|---|---|---|
| 1 | 240 ns | Single peer; dominated by `Route::clone` |
| 10 | 1.7 µs | Typical small deployment; ~170 ns per peer |
| 50 | 8.7 µs | Large deployment; linear scaling confirmed |

Scaling is linear (50 peers is ~36× a single peer). No hidden quadratic behaviour.

---

## pathvector-session

### `encode_update` — BGP UPDATE wire encoding (announce)

Measures `BgpMessage::Update(...).encode()` for an UPDATE announcing N IPv4 /24
prefixes with a 3-hop AS_PATH, IGP origin, and a single next-hop. With NLRI batching,
a single UPDATE can carry hundreds of prefixes.

| NLRI count | Time | Takeaway |
|---|---|---|
| 1 | 601 ns | Baseline; header + attribute + 1 prefix |
| 100 | 1.3 µs | 100 prefixes for ~700 ns additional; ~7 ns/prefix |
| 1000 | 5.6 µs | 1000-prefix burst; ~5 ns/prefix amortised |

Encode cost is dominated by attribute serialisation at low NLRI counts. Above ~10
prefixes, per-NLRI cost (~5 ns each) dominates.

---

### `decode_update` — BGP UPDATE wire parsing (announce)

Measures `BgpMessage::decode(wire_bytes)` on the same UPDATE payloads as above.

| NLRI count | Time | Takeaway |
|---|---|---|
| 1 | 176 ns | Faster than encode; no allocation for attributes |
| 100 | 856 ns | ~6.8 ns per additional NLRI |
| 1000 | 4.8 µs | ~4.6 ns/NLRI amortised; decode is faster than encode |

Decode is consistently faster than encode across all sizes because the parser reads
into pre-allocated `Vec` capacity whereas the encoder allocates a fresh `Vec<u8>`
per call.

---

### `encode_withdraw` — BGP UPDATE wire encoding (withdrawal)

Measures encoding a pure withdrawal UPDATE with N prefixes and no path attributes.

| NLRI count | Time | Takeaway |
|---|---|---|
| 1 | 156 ns | 4× faster than an announce (no attribute encoding) |
| 100 | 1.0 µs | ~8.5 ns per NLRI |
| 1000 | 5.2 µs | Matches announce cost at scale; NLRI loop dominates |

Withdrawals are cheaper than announcements at low counts (no attributes to encode) but
converge to the same per-NLRI cost at high counts.
