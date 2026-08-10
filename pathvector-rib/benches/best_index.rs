//! `RouteMap` vs `AHashMap` as the `LocRib` best-path index (Item 2 of
//! `plans/blocking-arbiter-performance.md`).
//!
//! `LocRib::best` is currently a `RouteMap<A, PeerId>` — a treebitmap
//! optimized for longest-prefix-match. `LocRib::longest_match` (the only
//! consumer of that LPM capability) has zero production call sites; every
//! real caller does exact insert/get/remove. This benchmark measures whether
//! a plain `AHashMap<Nlri<A>, PeerId>` would be a better fit for that actual
//! usage pattern, under both a `/32`-heavy (`BlockingArbiter`) shape and a
//! mixed-prefix-length (general internet-edge) shape.
//!
//! This is a measurement, not a settled decision — see the "Item 2" section
//! of the plan doc for the exit criteria and current status (provisional:
//! `insert`/`remove` favor `AHashMap` at every size measured, but `get`
//! reverses at 500k for the `/32` shape specifically — see
//! `plans/performance-history.md` for the full sweep and the open follow-up
//! items before treating this as decided).
//!
//! NLRIs are pre-generated into a `Vec` *before* entering each benchmark's
//! timed region — an earlier version called the generator function (string
//! `format!` + `parse`) inside `b.iter`/`b.iter_custom`, which measured
//! NLRI construction cost alongside the map operation it was supposed to
//! isolate. `nlri_mixed` also had a distinct bug fixed in the same pass:
//! its early per-length address generation collided heavily at scale (only
//! 8 of 100,000 nominally-`/16` entries were actually distinct at n=500,000
//! — IPv4 only has 65,536 possible `/16` prefixes in total, and a naive
//! uniform 20% share across five lengths demanded far more than that).
//! The generator below uses a length distribution weighted toward `/24`
//! (roughly matching real BGP table shape) specifically so no length's
//! occurrence count ever approaches its address-space budget at any size
//! this file benchmarks — see `nlri_mixed`'s doc comment for the exact
//! bound.

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{hint::black_box, net::Ipv4Addr};

use ahash::AHashMap;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pathvector_rib::PeerId;
use pathvector_types::Nlri;
use routemap::RouteMap;

fn peer(n: u8) -> PeerId {
    use std::net::IpAddr;
    PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
}

/// The Nth `/32` in `10.0.0.0/8` — `BlockingArbiter`'s dominant shape, matches
/// `loc_rib_reconcile.rs::nlri_for`.
fn nlri_32(n: usize) -> Nlri<Ipv4Addr> {
    #[allow(clippy::cast_possible_truncation)]
    let b = ((n >> 16) & 0xff) as u8;
    #[allow(clippy::cast_possible_truncation)]
    let c = ((n >> 8) & 0xff) as u8;
    #[allow(clippy::cast_possible_truncation)]
    let d = (n & 0xff) as u8;
    format!("10.{b}.{c}.{d}/32").parse().unwrap()
}

/// Length distribution for [`nlri_mixed`], weighted toward `/24` rather
/// than a uniform split across the five lengths — both a closer match to
/// real internet BGP table shape, and (not coincidentally) the reason the
/// generator stays collision-free: a uniform 20% share of 500,000 calls
/// would demand 100,000 distinct `/16` prefixes, but IPv4 only has 65,536
/// `/16` prefixes in existence. At this file's largest size (500,000), the
/// worst case here is 5,000 `/16` occurrences (weight 1/100) — comfortably
/// under that 65,536 ceiling, and every other length has a proportionally
/// larger address-space budget for a smaller or equal occurrence count.
/// Weights sum to 100.
const MIXED_LEN_WEIGHTS: [(u8, u8); 5] = [(16, 1), (20, 4), (24, 60), (28, 25), (32, 10)];

/// A mixed-prefix-length NLRI matching a rough approximation of real
/// internet BGP table shape, for contrast with the `/32`-only shape above.
/// Guaranteed unique per length at every size this file benchmarks — see
/// `MIXED_LEN_WEIGHTS`'s doc comment for the bound. The network-bits value
/// is the count of prior calls that produced this same length (an
/// occurrence counter, not derived from `n` directly), placed directly in
/// the prefix's network-bit position, so no masking step can ever collide
/// two distinct occurrences of the same length.
fn nlri_mixed(n: usize) -> Nlri<Ipv4Addr> {
    let pattern: Vec<u8> = MIXED_LEN_WEIGHTS
        .iter()
        .flat_map(|&(len, weight)| std::iter::repeat_n(len, weight as usize))
        .collect();
    debug_assert_eq!(pattern.len(), 100);

    let pos = n % 100;
    let len = pattern[pos];
    let cycle = n / 100;
    // clippy::naive_bytecount wants the `bytecount` crate for SIMD-accelerated
    // counting — overkill for a 100-element slice counted once per call in
    // benchmark setup (outside the timed region).
    #[allow(clippy::naive_bytecount)]
    let count_in_full_cycle = pattern.iter().filter(|&&l| l == len).count();
    #[allow(clippy::naive_bytecount)]
    let count_before_pos = pattern[..pos].iter().filter(|&&l| l == len).count();
    let occurrence = cycle * count_in_full_cycle + count_before_pos;

    #[allow(clippy::cast_possible_truncation)]
    let network_bits = occurrence as u32;
    let addr = if len == 0 {
        0
    } else {
        network_bits << (32 - len)
    };
    Nlri::new(Ipv4Addr::from(addr), len).unwrap()
}

const SIZES: [usize; 3] = [10_000, 100_000, 500_000];

/// Pre-generates `n` NLRIs via `make_nlri` *before* the timed region begins.
fn pregenerate(make_nlri: fn(usize) -> Nlri<Ipv4Addr>, n: usize) -> Vec<Nlri<Ipv4Addr>> {
    (0..n).map(make_nlri).collect()
}

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("best_index_insert");

    for n in SIZES {
        for (shape, make_nlri) in [
            ("slash32", nlri_32 as fn(usize) -> Nlri<Ipv4Addr>),
            ("mixed", nlri_mixed as fn(usize) -> Nlri<Ipv4Addr>),
        ] {
            let nlris = pregenerate(make_nlri, n);

            group.bench_with_input(
                BenchmarkId::new(format!("routemap_{shape}"), n),
                &nlris,
                |b, nlris| {
                    b.iter_custom(|iters| {
                        let mut total = std::time::Duration::ZERO;
                        for _ in 0..iters {
                            let mut map: RouteMap<Ipv4Addr, PeerId> = RouteMap::new();
                            let start = std::time::Instant::now();
                            for nlri in nlris {
                                map.insert(nlri.prefix(), peer(1));
                            }
                            total += start.elapsed();
                            drop(black_box(map));
                        }
                        total
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("ahashmap_{shape}"), n),
                &nlris,
                |b, nlris| {
                    b.iter_custom(|iters| {
                        let mut total = std::time::Duration::ZERO;
                        for _ in 0..iters {
                            let mut map: AHashMap<Nlri<Ipv4Addr>, PeerId> = AHashMap::new();
                            let start = std::time::Instant::now();
                            for &nlri in nlris {
                                map.insert(nlri, peer(1));
                            }
                            total += start.elapsed();
                            drop(black_box(map));
                        }
                        total
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("best_index_get");

    for n in SIZES {
        for (shape, make_nlri) in [
            ("slash32", nlri_32 as fn(usize) -> Nlri<Ipv4Addr>),
            ("mixed", nlri_mixed as fn(usize) -> Nlri<Ipv4Addr>),
        ] {
            let nlris = pregenerate(make_nlri, n);
            let mut route_map: RouteMap<Ipv4Addr, PeerId> = RouteMap::new();
            let mut ahash_map: AHashMap<Nlri<Ipv4Addr>, PeerId> = AHashMap::new();
            for &nlri in &nlris {
                route_map.insert(nlri.prefix(), peer(1));
                ahash_map.insert(nlri, peer(1));
            }

            group.bench_with_input(
                BenchmarkId::new(format!("routemap_{shape}"), n),
                &nlris,
                |b, nlris| {
                    b.iter(|| {
                        for nlri in nlris {
                            black_box(route_map.get(nlri.prefix()));
                        }
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("ahashmap_{shape}"), n),
                &nlris,
                |b, nlris| {
                    b.iter(|| {
                        for nlri in nlris {
                            black_box(ahash_map.get(nlri));
                        }
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_remove(c: &mut Criterion) {
    let mut group = c.benchmark_group("best_index_remove");

    for n in SIZES {
        for (shape, make_nlri) in [
            ("slash32", nlri_32 as fn(usize) -> Nlri<Ipv4Addr>),
            ("mixed", nlri_mixed as fn(usize) -> Nlri<Ipv4Addr>),
        ] {
            let nlris = pregenerate(make_nlri, n);

            group.bench_with_input(
                BenchmarkId::new(format!("routemap_{shape}"), n),
                &nlris,
                |b, nlris| {
                    b.iter_custom(|iters| {
                        let mut total = std::time::Duration::ZERO;
                        for _ in 0..iters {
                            let mut map: RouteMap<Ipv4Addr, PeerId> = RouteMap::new();
                            for nlri in nlris {
                                map.insert(nlri.prefix(), peer(1));
                            }
                            let start = std::time::Instant::now();
                            for nlri in nlris {
                                black_box(map.remove(nlri.prefix()));
                            }
                            total += start.elapsed();
                            drop(map);
                        }
                        total
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("ahashmap_{shape}"), n),
                &nlris,
                |b, nlris| {
                    b.iter_custom(|iters| {
                        let mut total = std::time::Duration::ZERO;
                        for _ in 0..iters {
                            let mut map: AHashMap<Nlri<Ipv4Addr>, PeerId> = AHashMap::new();
                            for &nlri in nlris {
                                map.insert(nlri, peer(1));
                            }
                            let start = std::time::Instant::now();
                            for nlri in nlris {
                                black_box(map.remove(nlri));
                            }
                            total += start.elapsed();
                            drop(map);
                        }
                        total
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_insert, bench_get, bench_remove);
criterion_main!(benches);
