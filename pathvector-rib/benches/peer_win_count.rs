//! Per-peer best-path win count: the management read (`list_peers` /
//! `get_peer`, issue #106) and the copy-on-write clone it used to force.
//!
//! - `scan`  — the old read: walk every best route, count those won by the
//!   peer. O(table) per peer per call.
//! - `count` — `LocRib::best_win_count`: O(1).
//! - `clone` — `LocRib::clone`, the deep copy `Arc::make_mut` performs on the
//!   event loop when a reader holds the snapshot.

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{
    hint::black_box,
    net::{IpAddr, Ipv4Addr},
};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pathvector_rib::{LocRib, PeerId, RouteBuilder, oracle::AlwaysReachable};
use pathvector_types::{AsPath, Asn, NextHop, Nlri, Origin, PeerType};

const PEERS: u8 = 4;

fn peer(n: u8) -> PeerId {
    PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
}

/// `n` distinct /24s split evenly between `PEERS` peers (one candidate each).
fn build_rib(n: usize) -> LocRib<Ipv4Addr> {
    let mut rib = LocRib::new();
    for i in 0..n {
        #[allow(clippy::cast_possible_truncation)]
        let (a, b, c) = (
            (11 + i / 65_536) as u8,
            ((i / 256) % 256) as u8,
            (i % 256) as u8,
        );
        let nlri: Nlri<Ipv4Addr> = format!("{a}.{b}.{c}.0/24").parse().unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let owner = (i % usize::from(PEERS)) as u8 + 1;
        let route = RouteBuilder::new(
            nlri,
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65000)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)))
        .peer_type(PeerType::External)
        .build();
        rib.insert(peer(owner), route, &AlwaysReachable);
    }
    rib
}

fn bench_win_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_win_count");
    group.sample_size(10);
    for n in [100usize, 1_000, 10_000, 100_000, 1_000_000] {
        let rib = build_rib(n);
        let p = peer(1);
        assert_eq!(rib.best_win_count(&p), n / usize::from(PEERS));

        group.bench_with_input(BenchmarkId::new("scan", n), &rib, |b, rib| {
            b.iter(|| {
                black_box(
                    rib.best_routes()
                        .filter(|(nlri, _)| rib.best_peer(nlri) == Some(p))
                        .count(),
                )
            });
        });
        group.bench_with_input(BenchmarkId::new("count", n), &rib, |b, rib| {
            b.iter(|| black_box(rib.best_win_count(black_box(&p))));
        });
        group.bench_with_input(BenchmarkId::new("clone", n), &rib, |b, rib| {
            b.iter(|| black_box(rib.clone()));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_win_count);
criterion_main!(benches);
