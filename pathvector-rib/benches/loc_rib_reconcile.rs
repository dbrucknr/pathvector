//! `BlockingArbiter`-shaped `LocRib` benchmarks.
//!
//! `loc_rib_insert.rs` uses a mixed-prefix-length, two-competing-peers shape
//! representative of a general internet-edge table. This file instead models
//! a narrower workload: a companion reconciler (`BlockingArbiter`) that
//! originates almost entirely `/32` host routes sharing one attribute set,
//! via periodic desired-state reconciliation. See
//! `plans/blocking-arbiter-performance.md` for the full rationale.
//!
//! Establishes the "before" baseline for Phase 1's low-risk improvements —
//! the single-candidate best-path fast path and the idempotent-re-origination
//! `Unchanged` short-circuit in particular are measured directly here.

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{
    hint::black_box,
    net::{IpAddr, Ipv4Addr},
    time::Instant,
};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pathvector_rib::{LocRib, PeerId, Route, RouteBuilder, oracle::AlwaysReachable};
use pathvector_types::{AsPath, Community, LocalPref, NextHop, Nlri, Origin, PeerType};

fn peer(n: u8) -> PeerId {
    PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
}

/// The Nth `/32` host route in `10.0.0.0/8` — `BlockingArbiter`'s dominant
/// shape (locally originated host routes), unlike `loc_rib_insert.rs`'s
/// `/24` mixed-prefix shape. Supports up to ~16M distinct prefixes.
fn nlri_for(n: usize) -> Nlri<Ipv4Addr> {
    #[allow(clippy::cast_possible_truncation)]
    let b = ((n >> 16) & 0xff) as u8;
    #[allow(clippy::cast_possible_truncation)]
    let c = ((n >> 8) & 0xff) as u8;
    #[allow(clippy::cast_possible_truncation)]
    let d = (n & 0xff) as u8;
    format!("10.{b}.{c}.{d}/32").parse().unwrap()
}

/// One canonical attribute set shared by every route in the harness —
/// `BlockingArbiter`'s dominant case: every host route from the same source
/// carries the same next-hop and community.
fn shared_route(n: usize) -> Route<Ipv4Addr> {
    RouteBuilder::new(nlri_for(n), Origin::Igp, AsPath::new())
        .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)))
        .community(Community::from_parts(65001, 100))
        .peer_type(PeerType::Local)
        .build()
}

/// Same content as [`shared_route`] but with a different `LOCAL_PREF`, used
/// by the churn scenario to force a real best-path change without altering
/// the workload's overall shape.
fn shared_route_with_lp(n: usize, lp: u32) -> Route<Ipv4Addr> {
    RouteBuilder::new(nlri_for(n), Origin::Igp, AsPath::new())
        .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)))
        .community(Community::from_parts(65001, 100))
        .peer_type(PeerType::Local)
        .local_pref(LocalPref::new(lp))
        .build()
}

/// Populate a `LocRib` with `n` `/32` prefixes, each with exactly one
/// candidate (peer 1) — the dominant `BlockingArbiter` case, and the case
/// `LocRib::recompute_best`'s single-candidate fast path targets.
fn build_rib_single_candidate(n: usize) -> LocRib<Ipv4Addr> {
    let mut rib = LocRib::new();
    for i in 0..n {
        rib.insert(peer(1), shared_route(i), &AlwaysReachable);
    }
    rib
}

/// Same as [`build_rib_single_candidate`] but with two competing peers per
/// prefix — measures the general (non-fast-path) `recompute_best` cost
/// under the same `/32`, shared-attribute shape, for direct contrast.
fn build_rib_two_candidates(n: usize) -> LocRib<Ipv4Addr> {
    let mut rib = LocRib::new();
    for i in 0..n {
        rib.insert(peer(1), shared_route(i), &AlwaysReachable);
        rib.insert(peer(2), shared_route(i), &AlwaysReachable);
    }
    rib
}

const SIZES: [usize; 3] = [10_000, 100_000, 500_000];

fn bench_empty_to_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconcile_empty_to_full");

    for n in SIZES {
        group.bench_with_input(BenchmarkId::new("single_candidate", n), &n, |b, &n| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut rib = LocRib::new();
                    let start = Instant::now();
                    for i in 0..n {
                        black_box(rib.insert(peer(1), shared_route(i), &AlwaysReachable));
                    }
                    total += start.elapsed();
                    drop(rib); // outside the clock
                }
                total
            });
        });

        group.bench_with_input(BenchmarkId::new("two_candidates", n), &n, |b, &n| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut rib = LocRib::new();
                    let start = Instant::now();
                    for i in 0..n {
                        black_box(rib.insert(peer(1), shared_route(i), &AlwaysReachable));
                        black_box(rib.insert(peer(2), shared_route(i), &AlwaysReachable));
                    }
                    total += start.elapsed();
                    drop(rib);
                }
                total
            });
        });
    }

    group.finish();
}

/// `BlockingArbiter`'s periodic full desired-state reassertion: re-announce
/// every prefix with byte-identical content (aside from `received_at`, which
/// always differs — see `Route::content_eq`). Before Item 5, every one of
/// these is reported `Announced` with a full route clone; after, they should
/// short-circuit to `Unchanged`.
fn bench_idempotent_reorigination(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconcile_idempotent_reorigination");

    for n in SIZES {
        group.bench_with_input(BenchmarkId::new("single_candidate", n), &n, |b, &n| {
            b.iter_custom(|iters| {
                let mut rib = build_rib_single_candidate(n);
                let start = Instant::now();
                for _ in 0..iters {
                    for i in 0..n {
                        black_box(rib.insert(peer(1), shared_route(i), &AlwaysReachable));
                    }
                }
                let elapsed = start.elapsed();
                drop(rib);
                elapsed
            });
        });

        // Contrast case: the winning peer re-announcing identical content in
        // a two-candidate table exercises Item 5's `Unchanged` short-circuit
        // without Item 1's single-candidate fast path being involved.
        group.bench_with_input(BenchmarkId::new("two_candidates", n), &n, |b, &n| {
            b.iter_custom(|iters| {
                let mut rib = build_rib_two_candidates(n);
                let start = Instant::now();
                for _ in 0..iters {
                    for i in 0..n {
                        black_box(rib.insert(peer(1), shared_route(i), &AlwaysReachable));
                    }
                }
                let elapsed = start.elapsed();
                drop(rib);
                elapsed
            });
        });
    }

    group.finish();
}

/// Repeated 1% churn against an otherwise-stable full table: flips
/// `LOCAL_PREF` on 1% of prefixes each round, forcing a real best-path
/// change for those while leaving the rest idempotent.
fn bench_one_percent_churn(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconcile_one_percent_churn");

    for n in SIZES {
        let churn_n = (n / 100).max(1);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_custom(|iters| {
                let mut rib = build_rib_single_candidate(n);
                let start = Instant::now();
                #[allow(clippy::cast_possible_truncation)]
                for round in 0..(iters as usize) {
                    let lp = if round % 2 == 0 { 200u32 } else { 100u32 };
                    for i in 0..churn_n {
                        black_box(rib.insert(
                            peer(1),
                            shared_route_with_lp(i, lp),
                            &AlwaysReachable,
                        ));
                    }
                }
                let elapsed = start.elapsed();
                drop(rib);
                elapsed
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_empty_to_full,
    bench_idempotent_reorigination,
    bench_one_percent_churn
);
criterion_main!(benches);
