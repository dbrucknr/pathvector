use std::{
    hint::black_box,
    net::{IpAddr, Ipv4Addr},
    time::Instant,
};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pathvector_rib::{LocRib, PeerId, Route, RouteBuilder};
use pathvector_types::{AsPath, Asn, LocalPref, NextHop, Nlri, Origin, PeerType};

fn peer(n: u8) -> PeerId {
    PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
}

fn nlri_for(prefix_idx: usize) -> Nlri<Ipv4Addr> {
    let b = (prefix_idx / 256) as u8;
    let c = (prefix_idx % 256) as u8;
    format!("10.{b}.{c}.0/24").parse().unwrap()
}

fn make_route(prefix_idx: usize, lp: u32, path_len: usize, pt: PeerType) -> Route<Ipv4Addr> {
    let asns = (0..path_len)
        .map(|i| Asn::new(65000 + i as u32))
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
        rib.insert(peer(1), make_route(i, 200, 3, PeerType::External));
        rib.insert(peer(2), make_route(i, 100, 2, PeerType::External));
    }
    rib
}

fn bench_loc_rib_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("loc_rib_insert");

    for n in [10_000usize, 100_000, 500_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            // iter_custom lets us build the RIB once outside the clock and drop
            // it after the clock stops — iter_batched includes drop time in the
            // measurement, which dominates at large N and swamps the insert cost.
            b.iter_custom(|iters| {
                let mut rib = build_rib(n);

                // Alternate local_pref so best-path changes on every other
                // iteration, keeping select_best fully exercised throughout.
                let start = Instant::now();
                for i in 0..(iters as usize) {
                    let lp = if i % 2 == 0 { 300u32 } else { 50u32 };
                    black_box(rib.insert(peer(3), make_route(0, lp, 1, PeerType::External)));
                }
                let elapsed = start.elapsed();

                drop(rib); // outside the clock
                elapsed
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_loc_rib_insert);
criterion_main!(benches);
