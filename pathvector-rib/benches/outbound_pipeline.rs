#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::net::{IpAddr, Ipv4Addr};

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use pathvector_rib::{AdjRibOut, PeerId, Route, RouteBuilder, outbound::prepare_outbound};
use pathvector_types::{
    AsPath, Asn, Community, ExtendedCommunity, LargeCommunity, LocalPref, Med, NextHop, Nlri,
    Origin, PeerType,
};

const LOCAL_AS: u32 = 65001;
const LOCAL_BGP_ID: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn peer(n: u8) -> PeerId {
    PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
}

/// Minimal route: 2-hop AS path, no communities.
/// Establishes the baseline clone cost.
fn minimal_route() -> Route<Ipv4Addr> {
    RouteBuilder::new(
        "10.1.0.0/24".parse::<Nlri<Ipv4Addr>>().unwrap(),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65003)]),
    )
    .local_pref(LocalPref::new(100))
    .peer_type(PeerType::External)
    .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
    .build()
}

/// Dense route: 15-hop AS path, 5 standard communities, 2 large communities,
/// 1 extended community (route-target), MED set.
/// Representative of a real IXP-learned prefix with policy markings applied.
fn dense_route() -> Route<Ipv4Addr> {
    RouteBuilder::new(
        "10.1.0.0/24".parse::<Nlri<Ipv4Addr>>().unwrap(),
        Origin::Igp,
        AsPath::from_sequence((0..15).map(|i| Asn::new(65002 + i)).collect()),
    )
    .local_pref(LocalPref::new(150))
    .med(Med::new(100))
    .peer_type(PeerType::External)
    .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
    .community(Community::new(0xFDE8_0064)) // 65000:100
    .community(Community::new(0xFDE8_00C8)) // 65000:200
    .community(Community::new(0xFDE8_012C)) // 65000:300
    .community(Community::new(0xFFFF_FF01)) // NO_EXPORT
    .community(Community::new(0xFDE9_0001)) // 65001:1
    .large_community(LargeCommunity::new(65000, 1, 100))
    .large_community(LargeCommunity::new(65000, 2, 200))
    .extended_community(ExtendedCommunity::route_target_as2(65000, 1))
    .build()
}

fn build_peers(n: usize) -> Vec<AdjRibOut<Ipv4Addr>> {
    (0..n)
        .map(|i| {
            let pt = if i % 2 == 0 {
                PeerType::External
            } else {
                PeerType::Internal
            };
            #[allow(clippy::cast_possible_truncation)]
            AdjRibOut::new(peer(i as u8 + 1), pt)
        })
        .collect()
}

fn run_pipeline(route: &Route<Ipv4Addr>, peers: &mut [AdjRibOut<Ipv4Addr>]) {
    for adj in peers.iter_mut() {
        let outbound = prepare_outbound(
            route.clone(),
            adj.peer_type(),
            LOCAL_AS,
            LOCAL_BGP_ID,
            false,
        );
        adj.insert(outbound);
    }
}

fn bench_outbound_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("outbound_pipeline");

    for n in [1usize, 10, 50] {
        group.bench_with_input(BenchmarkId::new("minimal", n), &n, |b, &n| {
            b.iter_batched(
                || (minimal_route(), build_peers(n)),
                |(route, mut peers)| run_pipeline(&route, &mut peers),
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("dense", n), &n, |b, &n| {
            b.iter_batched(
                || (dense_route(), build_peers(n)),
                |(route, mut peers)| run_pipeline(&route, &mut peers),
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_outbound_pipeline);
criterion_main!(benches);
