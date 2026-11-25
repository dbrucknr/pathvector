//! Prefix-keyed RIB operations: insert, lookup and withdraw at 100 / 1k / 10k
//! prefixes, IPv4 and IPv6.
//!
//! Every RIB turns the caller's NLRI into a storage key at its boundary
//! (issue #71), so these are the operations that pay for that conversion.
//! Routes and lookup keys are built outside the timed section; each
//! measurement is one pass over all `n` prefixes (`Throughput::Elements(n)`).
//!
//! - `insert`       — `LocRib::insert` replacing one peer's route on every
//!   prefix of a two-peer table (best path is re-selected each time).
//! - `lookup`       — `LocRib::best`.
//! - `longest_match`— `LocRib::longest_match`.
//! - `withdraw`     — `LocRib::withdraw` of the winning peer's route on every
//!   prefix (the other candidate takes over).
//! - `adj_in`       — `AdjRibIn` insert, get and withdraw of every prefix.
//! - `adj_out`      — `AdjRibOut` insert, get and withdraw of every prefix.

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{
    hint::black_box,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use criterion::{
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
    measurement::WallTime,
};
use pathvector_rib::{
    AdjRibIn, AdjRibOut, LocRib, PeerId, Route, RouteBuilder, oracle::AlwaysReachable,
};
use pathvector_types::{AsPath, Asn, IpAddress, LocalPref, Nlri, Origin, PeerType};

const SIZES: [usize; 3] = [100, 1_000, 10_000];

fn peer(n: u8) -> PeerId {
    PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
}

/// The `i`-th distinct /24.
fn nlri_v4(i: usize) -> Nlri<Ipv4Addr> {
    let i = u32::try_from(i).expect("index fits u32");
    Nlri::new(Ipv4Addr::from((11u32 << 24) | (i << 8)), 24).expect("/24 is valid")
}

/// The `i`-th distinct /48.
fn nlri_v6(i: usize) -> Nlri<Ipv6Addr> {
    let base = 0x2001_0db8_u128 << 96;
    let i = u128::try_from(i).expect("index fits u128");
    Nlri::new(Ipv6Addr::from(base | (i << 80)), 48).expect("/48 is valid")
}

fn route<A: IpAddress>(nlri: Nlri<A>, lp: u32) -> Route<A> {
    RouteBuilder::new(
        nlri,
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65000), Asn::new(65001)]),
    )
    .local_pref(LocalPref::new(lp))
    .peer_type(PeerType::External)
    .build()
}

fn bench_family<A: IpAddress>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    family: &str,
    n: usize,
    nlri_for: fn(usize) -> Nlri<A>,
    addr_for: impl Fn(&Nlri<A>) -> A,
) {
    let nlris: Vec<Nlri<A>> = (0..n).map(nlri_for).collect();
    let addrs: Vec<A> = nlris.iter().map(addr_for).collect();
    let winners: Vec<Route<A>> = nlris.iter().map(|&p| route(p, 200)).collect();

    let mut rib = LocRib::new();
    for &p in &nlris {
        rib.insert(peer(1), route(p, 200), &AlwaysReachable);
        rib.insert(peer(2), route(p, 100), &AlwaysReachable);
    }
    assert_eq!(rib.len(), n, "benchmark RIB must hold n distinct prefixes");

    group.throughput(Throughput::Elements(u64::try_from(n).expect("n fits u64")));

    group.bench_function(BenchmarkId::new(format!("insert/{family}"), n), |b| {
        let mut rib = rib.clone();
        b.iter_batched(
            || winners.clone(),
            |routes| {
                for r in routes {
                    black_box(rib.insert(peer(1), r, &AlwaysReachable));
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function(BenchmarkId::new(format!("lookup/{family}"), n), |b| {
        b.iter(|| {
            for p in &nlris {
                black_box(rib.best(black_box(p)));
            }
        });
    });

    group.bench_function(
        BenchmarkId::new(format!("longest_match/{family}"), n),
        |b| {
            b.iter(|| {
                for &a in &addrs {
                    black_box(rib.longest_match(black_box(a)));
                }
            });
        },
    );

    group.bench_function(BenchmarkId::new(format!("withdraw/{family}"), n), |b| {
        b.iter_batched_ref(
            || rib.clone(),
            |rib| {
                for p in &nlris {
                    black_box(rib.withdraw(&peer(1), p, &AlwaysReachable));
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function(BenchmarkId::new(format!("adj_in/{family}"), n), |b| {
        let mut table: AdjRibIn<A> = AdjRibIn::new(peer(1));
        b.iter_batched(
            || winners.clone(),
            |routes| {
                for r in routes {
                    black_box(table.insert(r));
                }
                for p in &nlris {
                    black_box(table.get(black_box(p)));
                }
                for p in &nlris {
                    black_box(table.withdraw(black_box(p)));
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function(BenchmarkId::new(format!("adj_out/{family}"), n), |b| {
        let mut table: AdjRibOut<A> = AdjRibOut::new(peer(1), PeerType::Internal);
        b.iter_batched(
            || winners.clone(),
            |routes| {
                for r in routes {
                    black_box(table.insert(r));
                }
                for p in &nlris {
                    black_box(table.get(black_box(p)));
                }
                for p in &nlris {
                    black_box(table.withdraw(black_box(p)));
                }
            },
            BatchSize::LargeInput,
        );
    });
}

fn bench_prefix_keyed_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("prefix_keyed_ops");
    for n in SIZES {
        bench_family(&mut group, "v4", n, nlri_v4, |p| {
            Ipv4Addr::from(u32::from(p.prefix().ip()) | 1)
        });
        bench_family(&mut group, "v6", n, nlri_v6, |p| {
            Ipv6Addr::from(u128::from(p.prefix().ip()) | 1)
        });
    }
    group.finish();
}

criterion_group!(benches, bench_prefix_keyed_ops);
criterion_main!(benches);
