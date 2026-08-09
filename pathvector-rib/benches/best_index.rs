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
//! This is a measurement, not a decision — see the "Item 2" section of the
//! plan doc for the exit criteria before implementing a swap.

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

/// A mixed-prefix-length NLRI cycling through /16, /20, /24, /28, /32 —
/// matches a general internet-edge table's shape, for contrast with the
/// `/32`-only shape above. Host bits below the chosen length are masked out
/// so every generated prefix is a valid canonical network address.
fn nlri_mixed(n: usize) -> Nlri<Ipv4Addr> {
    const LENS: [u8; 5] = [16, 20, 24, 28, 32];
    let len = LENS[n % LENS.len()];
    let base = 0x0A00_0000u32.wrapping_add(u32::try_from(n).unwrap_or(u32::MAX));
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    let addr = Ipv4Addr::from(base & mask);
    format!("{addr}/{len}").parse().unwrap()
}

const SIZES: [usize; 3] = [10_000, 100_000, 500_000];

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("best_index_insert");

    for n in SIZES {
        for (shape, make_nlri) in [
            ("slash32", nlri_32 as fn(usize) -> Nlri<Ipv4Addr>),
            ("mixed", nlri_mixed as fn(usize) -> Nlri<Ipv4Addr>),
        ] {
            group.bench_with_input(
                BenchmarkId::new(format!("routemap_{shape}"), n),
                &n,
                |b, &n| {
                    b.iter_custom(|iters| {
                        let mut total = std::time::Duration::ZERO;
                        for _ in 0..iters {
                            let mut map: RouteMap<Ipv4Addr, PeerId> = RouteMap::new();
                            let start = std::time::Instant::now();
                            for i in 0..n {
                                map.insert(make_nlri(i).prefix(), peer(1));
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
                &n,
                |b, &n| {
                    b.iter_custom(|iters| {
                        let mut total = std::time::Duration::ZERO;
                        for _ in 0..iters {
                            let mut map: AHashMap<Nlri<Ipv4Addr>, PeerId> = AHashMap::new();
                            let start = std::time::Instant::now();
                            for i in 0..n {
                                map.insert(make_nlri(i), peer(1));
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
            let mut route_map: RouteMap<Ipv4Addr, PeerId> = RouteMap::new();
            let mut ahash_map: AHashMap<Nlri<Ipv4Addr>, PeerId> = AHashMap::new();
            for i in 0..n {
                route_map.insert(make_nlri(i).prefix(), peer(1));
                ahash_map.insert(make_nlri(i), peer(1));
            }

            group.bench_with_input(
                BenchmarkId::new(format!("routemap_{shape}"), n),
                &n,
                |b, &n| {
                    b.iter(|| {
                        for i in 0..n {
                            black_box(route_map.get(make_nlri(i).prefix()));
                        }
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("ahashmap_{shape}"), n),
                &n,
                |b, &n| {
                    b.iter(|| {
                        for i in 0..n {
                            black_box(ahash_map.get(&make_nlri(i)));
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
            group.bench_with_input(
                BenchmarkId::new(format!("routemap_{shape}"), n),
                &n,
                |b, &n| {
                    b.iter_custom(|iters| {
                        let mut total = std::time::Duration::ZERO;
                        for _ in 0..iters {
                            let mut map: RouteMap<Ipv4Addr, PeerId> = RouteMap::new();
                            for i in 0..n {
                                map.insert(make_nlri(i).prefix(), peer(1));
                            }
                            let start = std::time::Instant::now();
                            for i in 0..n {
                                black_box(map.remove(make_nlri(i).prefix()));
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
                &n,
                |b, &n| {
                    b.iter_custom(|iters| {
                        let mut total = std::time::Duration::ZERO;
                        for _ in 0..iters {
                            let mut map: AHashMap<Nlri<Ipv4Addr>, PeerId> = AHashMap::new();
                            for i in 0..n {
                                map.insert(make_nlri(i), peer(1));
                            }
                            let start = std::time::Instant::now();
                            for i in 0..n {
                                black_box(map.remove(&make_nlri(i)));
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
