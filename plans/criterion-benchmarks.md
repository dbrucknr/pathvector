# Plan: Criterion Benchmark Suite

## Motivation

pathvector is a BGP control-plane implementation. Control-plane work is inherently
low-throughput compared to data-plane forwarding, but predictable latency still matters:
a slow decision process delays convergence, and a slow outbound pipeline delays
advertisement to peers. We want concrete numbers on M2 Max hardware to answer three
questions before the system-level stress test:

1. How fast is `select_best` as the candidate set grows?
2. How does `LocRib::insert` scale with RIB size?
3. How does the outbound pipeline scale with peer count?

All results reported with three sizes and a Takeaway column (established convention).

## Benchmark targets

| Crate | Benchmark | Sizes | What to measure |
|---|---|---|---|
| `pathvector-types` | `as_path_prepend` | 0 / 10 / 100 hops | Cost of prepend as path grows |
| `pathvector-types` | `community_match` | 1 / 10 / 100 communities | Set lookup cost |
| `pathvector-policy` | `policy_evaluate` | 1 / 10 / 50 terms | Term evaluation per route |
| `pathvector-rib` | `select_best` | 2 / 10 / 100 candidates | Decision process cost |
| `pathvector-rib` | `loc_rib_insert` | 1k / 10k / 100k routes | Insert + best-path recompute |
| `pathvector-rib` | `loc_rib_lpm` | 10k routes, random addrs | Longest-prefix-match cost |
| `pathvector-rib` | `outbound_pipeline` | 1 / 10 / 50 peers | `prepare_outbound` × N peers |
| `pathvector-session` | `codec_decode_update` | 1 / 100 / 1k NLRIs | Decode throughput |
| `pathvector-session` | `codec_encode_update` | 1 / 100 / 1k NLRIs | Encode throughput |
| `pathvector-session` | `codec_roundtrip` | all 5 message types | End-to-end encode→decode |

## Files to create / modify

| Action | Path |
|---|---|
| Edit | `Cargo.toml` (workspace) — add `criterion = { version = "0.8", features = ["html_reports"] }` to `[workspace.dependencies]` |
| Edit | `pathvector-types/Cargo.toml` — add `criterion` dev-dep + `[[bench]]` targets |
| Edit | `pathvector-policy/Cargo.toml` — add `criterion` dev-dep + `[[bench]]` target |
| Edit | `pathvector-rib/Cargo.toml` — add `criterion` dev-dep + `[[bench]]` targets |
| Edit | `pathvector-session/Cargo.toml` — add `criterion` dev-dep + `[[bench]]` targets |
| Create | `pathvector-types/benches/as_path_prepend.rs` |
| Create | `pathvector-types/benches/community_match.rs` |
| Create | `pathvector-policy/benches/policy_evaluate.rs` |
| Create | `pathvector-rib/benches/select_best.rs` |
| Create | `pathvector-rib/benches/loc_rib_insert.rs` |
| Create | `pathvector-rib/benches/outbound_pipeline.rs` |
| Create | `pathvector-session/benches/codec_decode_update.rs` |
| Create | `pathvector-session/benches/codec_encode_update.rs` |
| Create | `pathvector-session/benches/codec_roundtrip.rs` |
| Edit | `Justfile` — add `bench: cargo bench --workspace` recipe |

## `prepare_outbound` migration

`prepare_outbound` currently lives in `pathvectord/src/main.rs` as a private function.
The `outbound_pipeline` benchmark needs to call it from `pathvector-rib`. Move it to
`pathvector-rib/src/outbound.rs` as `pub fn prepare_outbound(...)` — it uses only
`pathvector-rib` and `pathvector-types` types, so no daemon deps are introduced.

Update `pathvectord` to import it as `use pathvector_rib::outbound::prepare_outbound`.
Add `pub mod outbound;` to `pathvector-rib/src/lib.rs`.

## Shared fixture pattern

Each bench file defines a local `make_route` helper (no shared module needed — three
similar lines is better than a premature abstraction):

```rust
fn make_route(nlri: Nlri<Ipv4Addr>, lp: u32, path_len: usize, pt: PeerType) -> Route<Ipv4Addr> {
    let asns = (0..path_len).map(|i| Asn::new(65000 + i as u32)).collect();
    RouteBuilder::new(nlri, Origin::Igp, AsPath::from_sequence(asns))
        .local_pref(LocalPref::new(lp))
        .peer_type(pt)
        .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)))
        .build()
}
```

## CI integration (follow-on)

Once a baseline is established, store criterion JSON output as a CI artifact and
fail the build if any benchmark regresses by more than 10%. The `critcmp` tool
compares criterion baselines and integrates cleanly into a GitHub Actions step.

## Order of execution

1. Add `criterion` to workspace `Cargo.toml`
2. Move `prepare_outbound` to `pathvector-rib/src/outbound.rs`
3. Write `pathvector-rib` benches first (highest value, most coverage)
4. Write `pathvector-session` codec benches
5. Write `pathvector-types` and `pathvector-policy` benches
6. `cargo bench` smoke run; fix compilation errors
7. Commit with baseline numbers in the commit message

## Expected order of magnitude (M2 Max)

| Benchmark | Expected range |
|---|---|
| `select_best/2` | 10–50 ns |
| `select_best/100` | 500 ns–2 µs |
| `loc_rib_insert/1k` | 1–5 µs |
| `loc_rib_insert/100k` | 5–20 µs |
| `outbound_pipeline/50` | 2–10 µs |
| `codec_decode_update/1k NLRIs` | 50–200 µs |

## Related TODO entries

- TODO.md §Performance: "Per-crate criterion benchmarks"
- TODO.md §Performance: concern #2 (no NLRI batching)
