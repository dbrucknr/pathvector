#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pathvector_rib::{PeerId, Route, RouteBuilder, best_path::select_best};
use pathvector_types::{AsPath, Asn, LocalPref, Med, NextHop, Nlri, Origin, PeerType};

fn peer(n: u8) -> PeerId {
    PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
}

fn nlri(last: u8) -> Nlri<Ipv4Addr> {
    format!("10.0.{last}.0/24").parse().unwrap()
}

fn make_route(
    dest: u8,
    lp: u32,
    path_len: usize,
    pt: PeerType,
    med: Option<u32>,
) -> Route<Ipv4Addr> {
    #[allow(clippy::cast_possible_truncation)] // path_len <= 5; i never exceeds u32
    let asns = (0..path_len)
        .map(|i| Asn::new(65000 + i as u32))
        .collect::<Vec<_>>();
    let mut b = RouteBuilder::new(nlri(dest), Origin::Igp, AsPath::from_sequence(asns))
        .local_pref(LocalPref::new(lp))
        .peer_type(pt)
        .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)));
    if let Some(m) = med {
        b = b.med(Med::new(m));
    }
    b.build()
}

/// Build a candidate map with `n` routes that differ across all relevant
/// best-path attributes so that `select_best` exercises multiple steps.
fn build_candidates(n: usize) -> HashMap<PeerId, Route<Ipv4Addr>> {
    #[allow(clippy::cast_possible_truncation)] // n <= 100 in bench sizes
    (0..n)
        .map(|i| {
            let idx = i as u8;
            let lp = 100u32.saturating_add(u32::from(idx) * 10);
            let path_len = (usize::from(idx) % 5) + 1;
            let pt = if idx.is_multiple_of(3) {
                PeerType::External
            } else {
                PeerType::Internal
            };
            let med = if idx.is_multiple_of(2) {
                Some(u32::from(idx) * 100)
            } else {
                None
            };
            (peer(idx + 1), make_route(idx, lp, path_len, pt, med))
        })
        .collect()
}

fn bench_select_best(c: &mut Criterion) {
    let mut group = c.benchmark_group("select_best");

    for n in [2usize, 10, 100] {
        let candidates = build_candidates(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &candidates, |b, cands| {
            b.iter(|| select_best(cands));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_select_best);
criterion_main!(benches);
