#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{
    hint::black_box,
    net::{IpAddr, Ipv4Addr},
};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pathvector_rib::{LocRib, PeerId, Route, RouteBuilder, oracle::AlwaysReachable};
use pathvector_types::{AsPath, Asn, LocalPref, NextHop, Nlri, Origin, PeerType};

fn peer(n: u8) -> PeerId {
    PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
}

fn nlri_for(prefix_idx: usize) -> Nlri<Ipv4Addr> {
    #[allow(clippy::cast_possible_truncation)]
    let b = (prefix_idx / 256) as u8;
    #[allow(clippy::cast_possible_truncation)]
    let c = (prefix_idx % 256) as u8;
    format!("10.{b}.{c}.0/24").parse().unwrap()
}

fn make_route(prefix_idx: usize, lp: u32, path_len: usize, pt: PeerType) -> Route<Ipv4Addr> {
    let asns = (0..path_len)
        .map(|i| Asn::new(65000 + u32::try_from(i).unwrap_or(u32::MAX)))
        .collect::<Vec<_>>();
    RouteBuilder::new(
        nlri_for(prefix_idx),
        Origin::Igp,
        AsPath::from_sequence(asns),
    )
    .local_pref(LocalPref::new(lp))
    .peer_type(pt)
    .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)))
    .build()
}

/// Populate a `LocRib` with `n` prefixes, two competing peers each.
fn build_rib(n: usize) -> LocRib<Ipv4Addr> {
    let mut rib = LocRib::new();
    for i in 0..n {
        rib.insert(
            peer(1),
            make_route(i, 200, 3, PeerType::External),
            &AlwaysReachable,
        );
        rib.insert(
            peer(2),
            make_route(i, 100, 2, PeerType::External),
            &AlwaysReachable,
        );
    }
    rib
}

/// Steady-state insert cost on a RIB built once per size.
///
/// `loc_rib_insert` rebuilds a RIB (up to ~1 M entries) per criterion sample,
/// so at 500k its per-insert number is dominated by cold-cache first touches
/// and varies run to run. These groups build the RIB once and run a long loop:
///
/// - `hot`: the same prefix every time, winner alternating between peers.
/// - `scattered`: a different prefix each time (stride walk over the whole
///   table, winner alternating per visit), so every insert touches cold
///   memory the way real churn across a full table does.
fn bench_loc_rib_insert_steady(c: &mut Criterion) {
    let mut group = c.benchmark_group("loc_rib_insert_steady");
    for n in [10_000usize, 100_000, 500_000] {
        let mut hot_rib = build_rib(n);
        let mut i = 0usize;
        group.bench_with_input(BenchmarkId::new("hot", n), &n, |b, _| {
            b.iter(|| {
                let lp = if i.is_multiple_of(2) { 300u32 } else { 50u32 };
                i += 1;
                black_box(hot_rib.insert(
                    peer(3),
                    make_route(0, lp, 1, PeerType::External),
                    &AlwaysReachable,
                ));
            });
        });
        drop(hot_rib);

        let mut rib = build_rib(n);
        let mut k = 0usize;
        group.bench_with_input(BenchmarkId::new("scattered", n), &n, |b, &n| {
            b.iter(|| {
                // 7919 is prime, so the walk visits every prefix before repeating.
                let idx = (k * 7919) % n;
                let lp = if (k / n).is_multiple_of(2) {
                    300u32
                } else {
                    50u32
                };
                k += 1;
                black_box(rib.insert(
                    peer(3),
                    make_route(idx, lp, 1, PeerType::External),
                    &AlwaysReachable,
                ));
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_loc_rib_insert_steady);
criterion_main!(benches);
