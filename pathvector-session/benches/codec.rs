use std::net::Ipv4Addr;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pathvector_session::message::{BgpMessage, PathAttribute, UpdateMessage};
use pathvector_types::{Aggregator, AsPath, Asn, Nlri, Origin};

// ── Fixture helpers ───────────────────────────────────────────────────────────

fn nlri(third: u8, fourth: u8) -> Nlri<Ipv4Addr> {
    format!("10.0.{third}.{fourth}/24").parse().unwrap()
}

fn base_attrs() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath::from_sequence(vec![
            Asn::new(65001),
            Asn::new(65002),
            Asn::new(65003),
        ])),
        PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
    ]
}

/// Build an UPDATE message announcing `n` IPv4 /24 prefixes.
fn build_update(n: usize) -> UpdateMessage {
    #[allow(clippy::cast_possible_truncation)]
    UpdateMessage {
        withdrawn: vec![],
        attributes: base_attrs(),
        announced: (0..n)
            .map(|i| nlri((i / 256) as u8, (i % 256) as u8))
            .collect(),
    }
}

/// Encode an `UpdateMessage` to a complete wire frame (19-byte header + body).
fn encode_update(msg: &UpdateMessage) -> Vec<u8> {
    BgpMessage::Update(msg.clone()).encode()
}

// ── Benchmark: encode ─────────────────────────────────────────────────────────

fn bench_encode_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_update");

    for n in [1usize, 100, 1000] {
        let msg = build_update(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &msg, |b, m| {
            b.iter(|| encode_update(m));
        });
    }

    group.finish();
}

// ── Benchmark: decode ─────────────────────────────────────────────────────────

fn bench_decode_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_update");

    for n in [1usize, 100, 1000] {
        let wire = encode_update(&build_update(n));
        group.bench_with_input(BenchmarkId::from_parameter(n), &wire, |b, w| {
            b.iter(|| BgpMessage::decode(w).unwrap());
        });
    }

    group.finish();
}

// ── Benchmark: decode, attribute-heavy ───────────────────────────────────────

/// One UPDATE, one prefix, with a realistic `AS_PATH` length and an `AGGREGATOR`:
/// the per-UPDATE cost of attribute validation (RFC 7606 / 7607 / 9774) shows
/// here rather than being hidden behind NLRI parsing.
fn bench_decode_update_long_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_update_path_len");

    for len in [4u32, 32, 128] {
        let mut msg = build_update(1);
        msg.attributes[1] = PathAttribute::AsPath(AsPath::from_sequence(
            (0..len).map(|i| Asn::new(65_000 + i)).collect(),
        ));
        msg.attributes
            .push(PathAttribute::Aggregator(Aggregator::new(
                Asn::new(65_000),
                Ipv4Addr::new(192, 0, 2, 2),
            )));
        let wire = encode_update(&msg);
        group.bench_with_input(BenchmarkId::from_parameter(len), &wire, |b, w| {
            b.iter(|| BgpMessage::decode(w).unwrap());
        });
    }

    group.finish();
}

// ── Benchmark: encode withdrawal ──────────────────────────────────────────────

fn bench_encode_withdraw(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_withdraw");

    for n in [1usize, 100, 1000] {
        #[allow(clippy::cast_possible_truncation)]
        let msg = UpdateMessage {
            withdrawn: (0..n)
                .map(|i| nlri((i / 256) as u8, (i % 256) as u8))
                .collect(),
            attributes: vec![],
            announced: vec![],
        };
        group.bench_with_input(BenchmarkId::from_parameter(n), &msg, |b, m| {
            b.iter(|| BgpMessage::Update(m.clone()).encode());
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_encode_update,
    bench_decode_update,
    bench_decode_update_long_path,
    bench_encode_withdraw
);
criterion_main!(benches);
