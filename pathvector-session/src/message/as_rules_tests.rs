//! Receive-side restrictions on AS numbers in UPDATE path attributes, from raw
//! wire bytes (so the expectations do not depend on this crate's encoder).
//!
//! RFC 7607 §2: "An UPDATE message that contains the AS number of zero in the
//! AS_PATH or AGGREGATOR attribute MUST be considered as malformed and be
//! handled by the procedures specified in [RFC7606]. An UPDATE message that
//! contains the AS number of zero in the AS4_PATH or AS4_AGGREGATOR attribute
//! MUST be considered as malformed and be handled by the procedures specified
//! in [RFC6793]."
//!
//! Those procedures:
//! * AS_PATH — RFC 7606 §7.2: treat-as-withdraw.
//! * AGGREGATOR — RFC 7606 §7.7: attribute discard.
//! * AS4_PATH, AS4_AGGREGATOR — RFC 6793 §6: attribute discard.
//!
//! RFC 9774 §3: "Unless explicitly configured by a network operator to do
//! otherwise [...] BGP speakers: [...] MUST use the "treat-as-withdraw" error
//! handling behavior per [RFC7606] upon reception of BGP UPDATE messages
//! containing AS_SETs or AS_CONFED_SETs in the AS_PATH or AS4_PATH". This
//! speaker offers no such configuration. The clause is unconditional about
//! AS4_PATH, so it also applies where RFC 6793 alone would merely discard the
//! attribute or segment: by §3(h) the stronger action wins.
//!
//! RFC 7606 §3(g): of a repeated attribute only the first occurrence counts.
//! §3(h): among several errors, the strongest action applies.

#![allow(clippy::doc_markdown)] // RFC prose and attribute names, not identifiers

use std::net::Ipv4Addr;

use pathvector_types::{Aggregator, AsPath, AsPathSegment, Asn, Nlri};
use proptest::prelude::*;

use super::{
    AsnWidth, AttributeErrorPolicy, BgpMessage, MAX_LEN_EXTENDED, MalformedUpdate, PathAttribute,
};

const AS_PATH: u8 = 2;
const AGGREGATOR: u8 = 7;
const AS4_PATH: u8 = 17;
const AS4_AGGREGATOR: u8 = 18;

const SET: u8 = 1;
const SEQUENCE: u8 = 2;
const CONFED_SEQUENCE: u8 = 3;
const CONFED_SET: u8 = 4;

const BOTH_WIDTHS: [AsnWidth; 2] = [AsnWidth::Two, AsnWidth::Four];

// ── Wire builders ────────────────────────────────────────────────────────────

fn attr(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![flags, type_code, u8::try_from(value.len()).unwrap()];
    out.extend_from_slice(value);
    out
}

fn push_asn(out: &mut Vec<u8>, asn: u32, width: AsnWidth) {
    match width {
        AsnWidth::Two => out.extend(u16::try_from(asn).unwrap().to_be_bytes()),
        AsnWidth::Four => out.extend(asn.to_be_bytes()),
    }
}

fn segments(segs: &[(u8, &[u32])], width: AsnWidth) -> Vec<u8> {
    let mut v = Vec::new();
    for &(kind, asns) in segs {
        v.push(kind);
        v.push(u8::try_from(asns.len()).unwrap());
        for &a in asns {
            push_asn(&mut v, a, width);
        }
    }
    v
}

fn as_path(segs: &[(u8, &[u32])], width: AsnWidth) -> Vec<u8> {
    attr(0x40, AS_PATH, &segments(segs, width))
}

fn as4_path(segs: &[(u8, &[u32])]) -> Vec<u8> {
    attr(0xc0, AS4_PATH, &segments(segs, AsnWidth::Four))
}

fn aggregator(asn: u32, width: AsnWidth) -> Vec<u8> {
    let mut v = Vec::new();
    push_asn(&mut v, asn, width);
    v.extend([10, 0, 0, 9]);
    attr(0xc0, AGGREGATOR, &v)
}

fn as4_aggregator(asn: u32) -> Vec<u8> {
    let mut v = asn.to_be_bytes().to_vec();
    v.extend([10, 0, 0, 8]);
    attr(0xc0, AS4_AGGREGATOR, &v)
}

/// An UPDATE announcing 192.0.2.0/24 with ORIGIN, NEXT_HOP and `attrs`.
fn frame(attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut block = attr(0x40, 1, &[0]);
    block.extend(attr(0x40, 3, &[10, 0, 0, 1]));
    for a in attrs {
        block.extend_from_slice(a);
    }
    let mut body = vec![0, 0];
    body.extend(u16::try_from(block.len()).unwrap().to_be_bytes());
    body.extend(block);
    body.extend([24, 192, 0, 2]);
    let mut out = vec![0xff; 16];
    out.extend(u16::try_from(19 + body.len()).unwrap().to_be_bytes());
    out.push(2);
    out.extend(body);
    out
}

fn decode(width: AsnWidth, attrs: &[Vec<u8>]) -> BgpMessage {
    BgpMessage::decode_with_limit_and_caps(&frame(attrs), MAX_LEN_EXTENDED, width).unwrap()
}

// ── Assertions ───────────────────────────────────────────────────────────────

fn prefix() -> Nlri<Ipv4Addr> {
    "192.0.2.0/24".parse().unwrap()
}

fn malformed(msg: BgpMessage) -> MalformedUpdate {
    match msg {
        BgpMessage::MalformedUpdate(m) => m,
        other => panic!("expected a malformed UPDATE, got {other:?}"),
    }
}

/// `(type code, policy)` of every recorded error, in order.
fn errors(m: &MalformedUpdate) -> Vec<(u8, AttributeErrorPolicy)> {
    m.errors
        .iter()
        .map(|e| (e.type_code, e.policy.clone()))
        .collect()
}

fn assert_treat_as_withdraw(msg: BgpMessage, type_code: u8) -> MalformedUpdate {
    let m = malformed(msg);
    assert!(m.treat_as_withdraw && !m.session_reset, "{m:?}");
    assert!(
        errors(&m).contains(&(type_code, AttributeErrorPolicy::TreatAsWithdraw)),
        "{m:?}"
    );
    m
}

/// Attribute discard of exactly `discarded`, with the route still announced.
fn assert_discard(msg: BgpMessage, discarded: &[u8]) -> MalformedUpdate {
    let m = malformed(msg);
    assert!(!m.treat_as_withdraw && !m.session_reset, "{m:?}");
    assert_eq!(m.update.announced, vec![prefix()]);
    assert_eq!(
        errors(&m),
        discarded
            .iter()
            .map(|&t| (t, AttributeErrorPolicy::AttributeDiscard))
            .collect::<Vec<_>>()
    );
    m
}

fn decoded_path(attrs: &[PathAttribute]) -> AsPath {
    attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p.clone()),
            _ => None,
        })
        .expect("AS_PATH")
}

fn decoded_aggregator(attrs: &[PathAttribute]) -> Option<Aggregator> {
    attrs.iter().find_map(|a| match a {
        PathAttribute::Aggregator(agg) => Some(*agg),
        _ => None,
    })
}

fn seq(asns: &[u32]) -> AsPathSegment {
    AsPathSegment::Sequence(asns.iter().copied().map(Asn::new).collect())
}

fn assert_no_as4_attributes(m: &MalformedUpdate) {
    assert!(
        !m.update.attributes.iter().any(|a| matches!(
            a,
            PathAttribute::As4Path(_) | PathAttribute::As4Aggregator { .. }
        )),
        "{m:?}"
    );
}

// ── AS 0 (RFC 7607) ──────────────────────────────────────────────────────────

#[test]
fn as_zero_anywhere_in_as_path_is_treat_as_withdraw() {
    for width in BOTH_WIDTHS {
        for kind in [SEQUENCE, SET, CONFED_SEQUENCE, CONFED_SET] {
            for asns in [[0, 65002, 65003], [65001, 0, 65003], [65001, 65002, 0]] {
                let msg = decode(width, &[as_path(&[(kind, &asns)], width)]);
                assert_treat_as_withdraw(msg, AS_PATH);
            }
        }
        // In a later segment too.
        let msg = decode(
            width,
            &[as_path(&[(SEQUENCE, &[65001]), (SEQUENCE, &[0])], width)],
        );
        assert_treat_as_withdraw(msg, AS_PATH);
    }
}

#[test]
fn as_zero_aggregator_is_discarded_and_the_route_kept() {
    for width in BOTH_WIDTHS {
        let msg = decode(
            width,
            &[
                as_path(&[(SEQUENCE, &[65001])], width),
                aggregator(0, width),
            ],
        );
        let m = assert_discard(msg, &[AGGREGATOR]);
        assert_eq!(decoded_aggregator(&m.update.attributes), None);
        assert_eq!(
            decoded_path(&m.update.attributes),
            AsPath::from_segments(vec![seq(&[65001])])
        );
    }
}

/// From a two-octet peer the AS4_PATH would be merged into AS_PATH; one
/// carrying AS 0 is discarded instead, so AS_TRANS stays.
#[test]
fn as_zero_in_as4_path_discards_as4_path() {
    let msg = decode(
        AsnWidth::Two,
        &[
            as_path(&[(SEQUENCE, &[65001, 23456])], AsnWidth::Two),
            as4_path(&[(SEQUENCE, &[0])]),
        ],
    );
    let m = assert_discard(msg, &[AS4_PATH]);
    assert_eq!(
        decoded_path(&m.update.attributes),
        AsPath::from_segments(vec![seq(&[65001, 23456])])
    );
    assert_no_as4_attributes(&m);
}

/// RFC 6793 §6 discards confederation segments from AS4_PATH, but a zero in
/// one still means the attribute "contains the AS number of zero".
#[test]
fn as_zero_in_an_as4_path_confed_segment_discards_as4_path() {
    let msg = decode(
        AsnWidth::Two,
        &[
            as_path(&[(SEQUENCE, &[65001, 23456])], AsnWidth::Two),
            as4_path(&[(CONFED_SEQUENCE, &[0]), (SEQUENCE, &[131_072])]),
        ],
    );
    let m = assert_discard(msg, &[AS4_PATH]);
    assert_eq!(
        decoded_path(&m.update.attributes),
        AsPath::from_segments(vec![seq(&[65001, 23456])])
    );
}

#[test]
fn as_zero_in_as4_aggregator_discards_as4_aggregator() {
    let msg = decode(
        AsnWidth::Two,
        &[
            as_path(&[(SEQUENCE, &[65001, 23456])], AsnWidth::Two),
            aggregator(23456, AsnWidth::Two),
            as4_aggregator(0),
            as4_path(&[(SEQUENCE, &[131_072])]),
        ],
    );
    let m = assert_discard(msg, &[AS4_AGGREGATOR]);
    // AGGREGATOR stays as received; AS4_PATH is unaffected.
    assert_eq!(
        decoded_aggregator(&m.update.attributes).map(|a| a.asn),
        Some(Asn::TRANS)
    );
    assert_eq!(
        decoded_path(&m.update.attributes),
        AsPath::from_segments(vec![seq(&[65001, 131_072])])
    );
    assert_no_as4_attributes(&m);
}

/// A discarded AGGREGATOR is treated as absent: AS4_AGGREGATOR then
/// supersedes nothing, and AS4_PATH is still used.
#[test]
fn as_zero_aggregator_from_a_two_octet_peer_leaves_as4_path_in_use() {
    let msg = decode(
        AsnWidth::Two,
        &[
            as_path(&[(SEQUENCE, &[65001, 23456])], AsnWidth::Two),
            aggregator(0, AsnWidth::Two),
            as4_aggregator(131_072),
            as4_path(&[(SEQUENCE, &[131_072])]),
        ],
    );
    let m = assert_discard(msg, &[AGGREGATOR]);
    assert_eq!(decoded_aggregator(&m.update.attributes), None);
    assert_eq!(
        decoded_path(&m.update.attributes),
        AsPath::from_segments(vec![seq(&[65001, 131_072])])
    );
}

// ── Repeated and multiple errors (RFC 7606 §3(g), §3(h)) ─────────────────────

#[test]
fn only_the_first_as_path_is_judged() {
    let width = AsnWidth::Four;
    let clean = as_path(&[(SEQUENCE, &[65001])], width);
    let zero = as_path(&[(SEQUENCE, &[0])], width);

    let m = assert_discard(decode(width, &[clean.clone(), zero.clone()]), &[AS_PATH]);
    assert_eq!(
        decoded_path(&m.update.attributes),
        AsPath::from_segments(vec![seq(&[65001])])
    );
    assert_treat_as_withdraw(decode(width, &[zero, clean]), AS_PATH);
}

#[test]
fn only_the_first_aggregator_is_judged() {
    let width = AsnWidth::Four;
    let path = as_path(&[(SEQUENCE, &[65001])], width);

    // Zero first: it is discarded as malformed, the repeat as a duplicate.
    let msg = decode(
        width,
        &[path.clone(), aggregator(0, width), aggregator(65001, width)],
    );
    let m = malformed(msg);
    assert!(!m.treat_as_withdraw, "{m:?}");
    assert_eq!(decoded_aggregator(&m.update.attributes), None);

    // Zero second: only the repeat is dropped.
    let msg = decode(
        width,
        &[path, aggregator(65001, width), aggregator(0, width)],
    );
    let m = assert_discard(msg, &[AGGREGATOR]);
    assert_eq!(
        decoded_aggregator(&m.update.attributes).map(|a| a.asn),
        Some(Asn::new(65001))
    );
}

#[test]
fn as_path_error_outranks_aggregator_discard() {
    let width = AsnWidth::Four;
    let msg = decode(
        width,
        &[as_path(&[(SEQUENCE, &[0])], width), aggregator(0, width)],
    );
    assert_treat_as_withdraw(msg, AS_PATH);
}

/// Non-zero AS numbers decode cleanly, including AS_TRANS and the largest.
#[test]
fn non_zero_as_numbers_are_accepted() {
    let width = AsnWidth::Four;
    let msg = decode(
        width,
        &[
            as_path(&[(SEQUENCE, &[1, 23456, u32::MAX])], width),
            aggregator(1, width),
        ],
    );
    assert!(matches!(msg, BgpMessage::Update(_)), "{msg:?}");
}

// ── AS_SET / AS_CONFED_SET (RFC 9774) ────────────────────────────────────────

#[test]
fn either_set_type_in_as_path_is_treat_as_withdraw() {
    for width in BOTH_WIDTHS {
        for kind in [SET, CONFED_SET] {
            for segs in [
                vec![(kind, &[65001u32, 65002][..])],
                // A single-member set is still a set.
                vec![(SEQUENCE, &[65001][..]), (kind, &[65002][..])],
                vec![(kind, &[65002][..]), (SEQUENCE, &[65001][..])],
            ] {
                let msg = decode(width, &[as_path(&segs, width)]);
                let m = assert_treat_as_withdraw(msg, AS_PATH);
                // The attribute is retained as received, for inspection.
                assert!(
                    decoded_path(&m.update.attributes)
                        .segments()
                        .iter()
                        .any(|s| matches!(s, AsPathSegment::Set(_) | AsPathSegment::ConfedSet(_))),
                    "{m:?}"
                );
            }
        }
    }
}

/// The reproduction in issue #110: confederation layout that is otherwise
/// well formed (RFC 5065 §5 leading AS_CONFED_SEQUENCE).
#[test]
fn confed_set_after_a_confed_sequence_is_treat_as_withdraw() {
    let width = AsnWidth::Four;
    let msg = decode(
        width,
        &[as_path(
            &[(CONFED_SEQUENCE, &[65010]), (CONFED_SET, &[65011, 65012])],
            width,
        )],
    );
    assert_treat_as_withdraw(msg, AS_PATH);
}

#[test]
fn either_set_type_in_as4_path_is_treat_as_withdraw_at_either_width() {
    for width in BOTH_WIDTHS {
        for kind in [SET, CONFED_SET] {
            let msg = decode(
                width,
                &[
                    as_path(&[(SEQUENCE, &[65001, 23456])], width),
                    as4_path(&[(kind, &[131_072])]),
                ],
            );
            assert_treat_as_withdraw(msg, AS4_PATH);
        }
    }
}

/// RFC 9774 names only the two set types: a confederation *sequence* in
/// AS4_PATH is still just discarded (RFC 6793 §6).
#[test]
fn confed_sequence_in_as4_path_is_still_only_discarded() {
    let msg = decode(
        AsnWidth::Two,
        &[
            as_path(&[(SEQUENCE, &[65001, 23456])], AsnWidth::Two),
            as4_path(&[(CONFED_SEQUENCE, &[65010]), (SEQUENCE, &[131_072])]),
        ],
    );
    let m = assert_discard(msg, &[AS4_PATH]);
    assert_eq!(
        decoded_path(&m.update.attributes),
        AsPath::from_segments(vec![seq(&[65001, 131_072])])
    );
}

/// Both violations in one AS4_PATH: the stronger action applies, and the
/// AS 0 is not merged into AS_PATH.
#[test]
fn set_and_as_zero_in_as4_path_is_treat_as_withdraw() {
    let msg = decode(
        AsnWidth::Two,
        &[
            as_path(&[(SEQUENCE, &[65001, 23456])], AsnWidth::Two),
            as4_path(&[(SET, &[0])]),
        ],
    );
    let m = assert_treat_as_withdraw(msg, AS4_PATH);
    assert!(!decoded_path(&m.update.attributes).contains(Asn::ZERO));
}

#[test]
fn a_set_in_a_repeated_as_path_is_ignored() {
    let width = AsnWidth::Four;
    let clean = as_path(&[(SEQUENCE, &[65001])], width);
    let set = as_path(&[(SET, &[65002])], width);
    assert_discard(decode(width, &[clean.clone(), set.clone()]), &[AS_PATH]);
    assert_treat_as_withdraw(decode(width, &[set, clean]), AS_PATH);
}

proptest! {
    /// Over every layout of up to four segments: withdrawn exactly when a set
    /// segment or AS 0 appears, clean otherwise.
    #[test]
    fn prop_as_path_verdict(
        segs in proptest::collection::vec(
            (
                prop_oneof![Just(SET), Just(SEQUENCE), Just(CONFED_SEQUENCE), Just(CONFED_SET)],
                proptest::collection::vec(prop_oneof![1 => Just(0u32), 20 => 1u32..=65_535], 1..4),
            ),
            0..4,
        ),
        four in any::<bool>(),
    ) {
        let width = if four { AsnWidth::Four } else { AsnWidth::Two };
        let borrowed: Vec<(u8, &[u32])> = segs.iter().map(|(k, a)| (*k, a.as_slice())).collect();
        let prohibited = segs
            .iter()
            .any(|(k, a)| matches!(*k, SET | CONFED_SET) || a.contains(&0));
        let update = match decode(width, &[as_path(&borrowed, width)]) {
            BgpMessage::Update(u) => {
                prop_assert!(!prohibited);
                u
            }
            BgpMessage::MalformedUpdate(m) => {
                prop_assert!(prohibited);
                prop_assert!(m.treat_as_withdraw);
                m.update
            }
            other => return Err(TestCaseError::fail(format!("{other:?}"))),
        };
        // Whatever the verdict, the segments are represented as received.
        let want: Vec<_> = segs
            .iter()
            .map(|(kind, asns)| {
                let asns = asns.iter().copied().map(Asn::new).collect();
                match *kind {
                    SET => AsPathSegment::Set(asns),
                    SEQUENCE => AsPathSegment::Sequence(asns),
                    CONFED_SEQUENCE => AsPathSegment::ConfedSequence(asns),
                    _ => AsPathSegment::ConfedSet(asns),
                }
            })
            .collect();
        prop_assert_eq!(decoded_path(&update.attributes), AsPath::from_segments(want));
    }
}
