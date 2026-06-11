use std::net::{IpAddr, Ipv4Addr};

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use pathvector_rib::{AdjRibOut, PeerId, Route, RouteBuilder, outbound::prepare_outbound};
use pathvector_types::{AsPath, Asn, LocalPref, NextHop, Nlri, Origin, PeerType};

const LOCAL_AS: u32 = 65001;
const LOCAL_BGP_ID: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn peer(n: u8) -> PeerId {
    PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
}

fn source_route() -> Route<Ipv4Addr> {
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

fn build_peers(n: usize) -> Vec<AdjRibOut<Ipv4Addr>> {
    (0..n)
        .map(|i| {
            let pt = if i % 2 == 0 {
                PeerType::External
            } else {
                PeerType::Internal
            };
            AdjRibOut::new(peer(i as u8 + 1), pt)
        })
        .collect()
}

fn bench_outbound_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("outbound_pipeline");

    for n in [1usize, 10, 50] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || (source_route(), build_peers(n)),
                |(route, mut peers)| {
                    for adj in peers.iter_mut() {
                        let outbound =
                            prepare_outbound(route.clone(), adj.peer_type(), LOCAL_AS, LOCAL_BGP_ID);
                        adj.insert(outbound);
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_outbound_pipeline);
criterion_main!(benches);
