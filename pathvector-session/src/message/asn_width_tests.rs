//! Wire-level proof for issue #95: `AS_PATH` / `AGGREGATOR` / AS4_* handling at
//! each negotiated [`AsnWidth`] (RFC 6793, RFC 7606 §§7.2, 7.7).
//!
//! Every expected byte string below is written out by hand from the RFC
//! text (RFC 4271 §4.3 attribute and segment layout, RFC 6793 §§4.1-4.2.3, 6)
//! — never produced by running the codec under test — and every decode is
//! driven from raw bytes, so a codec that is wrong in both directions
//! consistently cannot pass.
//!
//! Constants used throughout: 65001 = `0xFDE9`, 65002 = `0xFDEA`,
//! 65000 = `0xFDE8`, `AS_TRANS` 23456 = `0x5BA0`, 131072 = `0x0002_0000`,
//! 131073 = `0x0002_0001`.

use std::net::Ipv4Addr;

use pathvector_types::{Aggregator, AsPath, AsPathSegment, Asn, Nlri, Origin};

use super::{
    AsnWidth, AttributeDecodeError, AttributeErrorPolicy, BgpMessage, MAX_LEN_EXTENDED,
    MalformedUpdate, PathAttribute, UpdateMessage,
};

// ── Frame builders (hand-rolled, independent of the encoder) ─────────────────

const ORIGIN_IGP: [u8; 4] = [0x40, 0x01, 0x01, 0x00];
const NEXT_HOP_192_0_2_1: [u8; 7] = [0x40, 0x03, 0x04, 192, 0, 2, 1];
/// NLRI 198.51.100.0/24.
const NLRI_198_51_100_0_24: [u8; 4] = [24, 198, 51, 100];

fn frame_update(attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8, 0]; // withdrawn routes length
    body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
    body.extend_from_slice(attrs);
    body.extend_from_slice(nlri);
    let mut f = vec![0xFF; 16];
    f.extend_from_slice(&u16::try_from(19 + body.len()).unwrap().to_be_bytes());
    f.push(2);
    f.extend_from_slice(&body);
    f
}

/// ORIGIN + `AS_PATH` (+ `extra` attributes) + `NEXT_HOP`, announcing one prefix.
fn legacy_update(as_path_value: &[u8], extra: &[&[u8]]) -> Vec<u8> {
    let mut attrs = ORIGIN_IGP.to_vec();
    attrs.extend_from_slice(&attr(0x40, 2, as_path_value));
    for e in extra {
        attrs.extend_from_slice(e);
    }
    attrs.extend_from_slice(&NEXT_HOP_192_0_2_1);
    frame_update(&attrs, &NLRI_198_51_100_0_24)
}

/// One path attribute TLV (extended length is used automatically).
fn attr(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    if value.len() > 255 {
        v.push(flags | 0x10);
        v.push(type_code);
        v.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    } else {
        v.push(flags);
        v.push(type_code);
        v.push(u8::try_from(value.len()).unwrap());
    }
    v.extend_from_slice(value);
    v
}

fn decode(frame: &[u8], width: AsnWidth) -> BgpMessage {
    BgpMessage::decode_with_limit_and_caps(frame, MAX_LEN_EXTENDED, width).unwrap()
}

fn asns(v: &[u32]) -> Vec<Asn> {
    v.iter().map(|&a| Asn::new(a)).collect()
}
fn seq(v: &[u32]) -> AsPathSegment {
    AsPathSegment::Sequence(asns(v))
}
fn set(v: &[u32]) -> AsPathSegment {
    AsPathSegment::Set(asns(v))
}
fn cseq(v: &[u32]) -> AsPathSegment {
    AsPathSegment::ConfedSequence(asns(v))
}
fn path(segs: Vec<AsPathSegment>) -> AsPath {
    AsPath::from_segments(segs)
}

fn prefix() -> Nlri<Ipv4Addr> {
    Nlri::new(Ipv4Addr::new(198, 51, 100, 0), 24).unwrap()
}

/// The UPDATE the legacy helpers announce, with the given `AS_PATH` and any
/// `extra` attributes inserted after `AS_PATH` (before `NEXT_HOP`).
fn expected_update(as_path: AsPath, extra: Vec<PathAttribute>) -> UpdateMessage {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(as_path),
    ];
    attributes.extend(extra);
    attributes.push(PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)));
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced: vec![prefix()],
    }
}

fn expect_clean(frame: &[u8], width: AsnWidth) -> UpdateMessage {
    match decode(frame, width) {
        BgpMessage::Update(u) => u,
        other => panic!("expected a clean UPDATE, got {other:?}"),
    }
}

fn expect_malformed(frame: &[u8], width: AsnWidth) -> MalformedUpdate {
    match decode(frame, width) {
        BgpMessage::MalformedUpdate(m) => m,
        other => panic!("expected a MalformedUpdate, got {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Receive, two-octet session (peer without the four-octet AS capability)
// ═════════════════════════════════════════════════════════════════════════════

/// Issue #95's exact reproduction. RFC 6793 §4.2 / RFC 4271 §4.3: to an OLD
/// speaker `AS_PATH` carries two-octet ASNs, so `02 01 fd ea` is
/// `AS_SEQUENCE`, one AS, 65002 — a perfectly normal path, not a truncation.
#[test]
fn issue_95_reproduction_two_octet_as_path_decodes_as_65002() {
    let frame = legacy_update(&[0x02, 0x01, 0xfd, 0xea], &[]);
    assert_eq!(
        expect_clean(&frame, AsnWidth::Two),
        expected_update(path(vec![seq(&[65002])]), vec![]),
    );
}

/// The same bytes under a four-octet session really are truncated (one ASN
/// needs four octets): the width, not the bytes, decides. RFC 7606 §7.2
/// overrun → treat-as-withdraw.
#[test]
fn the_same_two_octet_bytes_are_malformed_on_a_four_octet_session() {
    let frame = legacy_update(&[0x02, 0x01, 0xfd, 0xea], &[]);
    let m = expect_malformed(&frame, AsnWidth::Four);
    assert!(m.treat_as_withdraw);
    assert_eq!(m.errors.len(), 1);
    assert_eq!(m.errors[0].type_code, 2);
    // Withdrawn NLRI preserved so the transport can withdraw them.
    assert_eq!(m.update.announced, vec![prefix()]);
}

/// A longer legacy path whose bytes happen to be a *valid* four-octet
/// encoding: the old reader silently produced garbage ASNs instead of an
/// error. Bytes: `AS_SEQUENCE`(2): 1, 2 then `AS_SET`(1): 3, all two-octet:
/// `02 02 0001 0002 | 01 01 0003` — read as four-octet it is one segment of
/// AS 0x00010002 and AS 0x01010003.
#[test]
fn multi_segment_legacy_path_is_not_misparsed_as_four_octet() {
    let value = [
        0x02, 0x02, 0x00, 0x01, 0x00, 0x02, // AS_SEQUENCE 1 2
        0x01, 0x01, 0x00, 0x03, // AS_SET 3
    ];
    let frame = legacy_update(&value, &[]);
    assert_eq!(
        expect_clean(&frame, AsnWidth::Two),
        expected_update(path(vec![seq(&[1, 2]), set(&[3])]), vec![]),
    );
    // Documents the failure mode being fixed: at the wrong width the very
    // same bytes decode "successfully" to nonsense.
    let wrong = expect_clean(&frame, AsnWidth::Four);
    assert_eq!(
        wrong,
        expected_update(path(vec![seq(&[0x0001_0002, 0x0101_0003])]), vec![]),
    );
}

/// RFC 5065 / RFC 4271 §4.3: all four segment types decode at two octets.
#[test]
fn all_four_segment_types_decode_at_two_octets() {
    let value = [
        0x03, 0x01, 0xfd, 0xe8, // AS_CONFED_SEQUENCE 65000
        0x04, 0x02, 0xfd, 0xe8, 0xfd, 0xe9, // AS_CONFED_SET 65000 65001
        0x02, 0x02, 0xfd, 0xea, 0x5b, 0xa0, // AS_SEQUENCE 65002 AS_TRANS
        0x01, 0x01, 0xfd, 0xe9, // AS_SET 65001
    ];
    let got = expect_clean(&legacy_update(&value, &[]), AsnWidth::Two);
    assert_eq!(
        got,
        expected_update(
            path(vec![
                cseq(&[65000]),
                AsPathSegment::ConfedSet(asns(&[65000, 65001])),
                seq(&[65002, 23456]),
                set(&[65001]),
            ]),
            vec![],
        ),
    );
}

/// The empty `AS_PATH` of an iBGP-originated route is valid at either width.
#[test]
fn empty_as_path_is_valid_at_both_widths() {
    for w in [AsnWidth::Two, AsnWidth::Four] {
        let got = expect_clean(&legacy_update(&[], &[]), w);
        assert_eq!(got, expected_update(AsPath::new(), vec![]));
    }
}

/// RFC 4271 §4.3: the segment length is one octet, so 255 is the maximum
/// count. A maximal segment decodes at both widths (2 + 255×w octets: an
/// extended-length attribute).
#[test]
fn maximal_255_asn_segment_decodes_at_both_widths() {
    let mut two = vec![0x02, 255];
    let mut four = vec![0x02, 255];
    for i in 0..255u32 {
        two.extend_from_slice(&u16::try_from(1000 + i).unwrap().to_be_bytes());
        four.extend_from_slice(&(70_000 + i).to_be_bytes());
    }
    let want_two: Vec<u32> = (0..255).map(|i| 1000 + i).collect();
    let want_four: Vec<u32> = (0..255).map(|i| 70_000 + i).collect();
    assert_eq!(
        expect_clean(&legacy_update(&two, &[]), AsnWidth::Two),
        expected_update(path(vec![seq(&want_two)]), vec![]),
    );
    assert_eq!(
        expect_clean(&legacy_update(&four, &[]), AsnWidth::Four),
        expected_update(path(vec![seq(&want_four)]), vec![]),
    );
}

// ── RFC 7606 §7.2 malformed AS_PATH at both widths ───────────────────────────

fn assert_as_path_treat_as_withdraw(value: &[u8], width: AsnWidth, detail: &str) {
    let m = expect_malformed(&legacy_update(value, &[]), width);
    assert!(m.treat_as_withdraw, "{value:02x?} at {width:?}");
    assert!(!m.session_reset);
    assert_eq!(
        m.errors,
        vec![AttributeDecodeError {
            type_code: 2,
            policy: AttributeErrorPolicy::TreatAsWithdraw,
            detail: match detail {
                "overrun" => "truncated ASN in AS_PATH segment",
                "zero" => "AS_PATH segment has zero length",
                "type" => "unknown AS_PATH segment type",
                "underrun" => "attribute value truncated",
                other => panic!("{other}"),
            },
        }],
        "{value:02x?} at {width:?}"
    );
}

#[test]
fn rfc7606_overrun_is_treat_as_withdraw_at_both_widths() {
    // "an overrun where the Path Segment Length field of the last segment
    // encountered would cause the Attribute Length to be exceeded"
    assert_as_path_treat_as_withdraw(&[0x02, 0x02, 0xfd, 0xea, 0xfd], AsnWidth::Two, "overrun");
    assert_as_path_treat_as_withdraw(
        &[0x02, 0x02, 0, 0, 0xfd, 0xea, 0, 0],
        AsnWidth::Four,
        "overrun",
    );
}

#[test]
fn rfc7606_zero_length_segment_is_treat_as_withdraw_at_both_widths() {
    // "It has a Path Segment Length field of zero."
    assert_as_path_treat_as_withdraw(&[0x02, 0x00], AsnWidth::Two, "zero");
    assert_as_path_treat_as_withdraw(&[0x02, 0x00], AsnWidth::Four, "zero");
    // ... also after a good segment.
    assert_as_path_treat_as_withdraw(&[0x02, 0x01, 0xfd, 0xea, 0x01, 0x00], AsnWidth::Two, "zero");
}

#[test]
fn rfc7606_unknown_segment_type_is_treat_as_withdraw_at_both_widths() {
    assert_as_path_treat_as_withdraw(&[0x05, 0x01, 0xfd, 0xea], AsnWidth::Two, "type");
    assert_as_path_treat_as_withdraw(&[0x00, 0x01, 0, 0, 0xfd, 0xea], AsnWidth::Four, "type");
}

#[test]
fn rfc7606_single_trailing_octet_underrun_is_treat_as_withdraw() {
    // "there is only a single octet remaining (not enough ... for even an
    // empty segment header)"
    assert_as_path_treat_as_withdraw(&[0x02, 0x01, 0xfd, 0xea, 0x02], AsnWidth::Two, "underrun");
}

// ── AGGREGATOR width (RFC 7606 §7.7, RFC 6793 §4.1) ──────────────────────────

#[test]
fn aggregator_is_two_octet_asn_on_a_two_octet_session() {
    let agg = attr(0xC0, 7, &[0xfd, 0xe9, 10, 0, 0, 1]);
    let got = expect_clean(&legacy_update(&[], &[&agg]), AsnWidth::Two);
    assert_eq!(
        got,
        expected_update(
            AsPath::new(),
            vec![PathAttribute::Aggregator(Aggregator::new(
                Asn::new(65001),
                Ipv4Addr::new(10, 0, 0, 1)
            ))]
        )
    );
}

// ── AS4_PATH / AS4_AGGREGATOR from an OLD peer (RFC 6793 §4.2.3) ─────────────

const AS4_PATH_FLAGS: u8 = 0xC0; // optional transitive
const AS_TRANS_PATH: [u8; 6] = [0x02, 0x02, 0xfd, 0xe8, 0x5b, 0xa0]; // 65000 AS_TRANS

/// RFC 6793 §4.2.3, equal-length case: `AS_PATH` = [65000, `AS_TRANS`],
/// `AS4_PATH` = [65000, 131072] -> the true path [65000, 131072]; the `AS4_PATH`
/// attribute itself is consumed.
#[test]
fn as4_path_is_merged_into_as_path_from_an_old_peer() {
    let as4 = attr(
        AS4_PATH_FLAGS,
        17,
        &[0x02, 0x02, 0x00, 0x00, 0xfd, 0xe8, 0x00, 0x02, 0x00, 0x00],
    );
    let got = expect_clean(&legacy_update(&AS_TRANS_PATH, &[&as4]), AsnWidth::Two);
    assert_eq!(
        got,
        expected_update(path(vec![seq(&[65000, 131_072])]), vec![])
    );
}

/// §4.2.3 prepend case: an OLD AS (64512 = 0xFC00) sat between us and the
/// four-octet origin. `AS_PATH` = [64512, `AS_TRANS`] (N=2), `AS4_PATH` =
/// [131072] (M=1) -> take 1 leading AS and prepend: [64512, 131072].
#[test]
fn as4_path_shorter_than_as_path_is_prefixed_with_the_leading_as_path_hops() {
    let as_path = [0x02, 0x02, 0xfc, 0x00, 0x5b, 0xa0];
    let as4 = attr(AS4_PATH_FLAGS, 17, &[0x02, 0x01, 0x00, 0x02, 0x00, 0x00]);
    let got = expect_clean(&legacy_update(&as_path, &[&as4]), AsnWidth::Two);
    assert_eq!(
        got,
        expected_update(path(vec![seq(&[64512, 131_072])]), vec![])
    );
}

/// §4.2.3: "If the number of AS numbers in the `AS_PATH` attribute is less
/// than the number of AS numbers in the `AS4_PATH` attribute, then the
/// `AS4_PATH` attribute SHALL be ignored."
#[test]
fn as4_path_longer_than_as_path_is_ignored() {
    let as_path = [0x02, 0x01, 0x5b, 0xa0];
    let as4 = attr(
        AS4_PATH_FLAGS,
        17,
        &[0x02, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01],
    );
    let got = expect_clean(&legacy_update(&as_path, &[&as4]), AsnWidth::Two);
    assert_eq!(got, expected_update(path(vec![seq(&[23456])]), vec![]));
}

/// A leading `AS_CONFED_SEQUENCE` in `AS_PATH` is prepended (§4.2.3) while the
/// `AS4_PATH` replaces the `AS_TRANS`-bearing remainder.
#[test]
fn leading_confed_segment_survives_the_merge() {
    let as_path = [
        0x03, 0x01, 0xfd, 0xf2, // AS_CONFED_SEQUENCE 65010
        0x02, 0x01, 0x5b, 0xa0, // AS_SEQUENCE AS_TRANS
    ];
    let as4 = attr(AS4_PATH_FLAGS, 17, &[0x02, 0x01, 0x00, 0x02, 0x00, 0x00]);
    let got = expect_clean(&legacy_update(&as_path, &[&as4]), AsnWidth::Two);
    assert_eq!(
        got,
        expected_update(path(vec![cseq(&[65010]), seq(&[131_072])]), vec![])
    );
}

/// RFC 6793 §6: confederation segments "MUST NOT be carried in the `AS4_PATH`
/// ... MUST discard these path segments, adjust the relevant attribute
/// fields accordingly, and continue processing the UPDATE message. This case
/// SHOULD be logged" — the segment is dropped, the rest of `AS4_PATH` is used,
/// the UPDATE is not withdrawn, and an attribute-discard entry records it.
#[test]
fn confed_segments_in_as4_path_are_discarded_and_logged_not_fatal() {
    let as4 = attr(
        AS4_PATH_FLAGS,
        17,
        &[
            0x03, 0x01, 0x00, 0x00, 0xfd, 0xf2, // AS_CONFED_SEQUENCE 65010 (illegal here)
            0x02, 0x01, 0x00, 0x02, 0x00, 0x00, // AS_SEQUENCE 131072
        ],
    );
    let as_path = [0x02, 0x01, 0x5b, 0xa0];
    let m = expect_malformed(&legacy_update(&as_path, &[&as4]), AsnWidth::Two);
    assert!(!m.treat_as_withdraw && !m.session_reset);
    assert_eq!(
        m.errors,
        vec![AttributeDecodeError {
            type_code: 17,
            policy: AttributeErrorPolicy::AttributeDiscard,
            detail: "AS_CONFED segment in AS4_PATH discarded (RFC 6793 §6)",
        }]
    );
    assert_eq!(
        m.update,
        expected_update(path(vec![seq(&[131_072])]), vec![])
    );
}

/// RFC 6793 §6: a malformed `AS4_PATH` is *discarded* (not treat-as-withdraw):
/// too short / odd length, zero-length segment, or undefined segment type.
/// `AS_PATH` is then used as-is.
#[test]
fn malformed_as4_path_is_attribute_discard_and_as_path_is_untouched() {
    let cases: [(&str, &[u8]); 5] = [
        ("empty (< 6)", &[]),
        ("length 5 (odd and < 6)", &[0x02, 0x01, 0x00, 0x00, 0x01]),
        (
            "zero-length segment",
            &[0x02, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01],
        ),
        (
            "undefined segment type",
            &[0x09, 0x01, 0x00, 0x02, 0x00, 0x00],
        ),
        (
            "segment overruns attribute",
            &[0x02, 0x02, 0x00, 0x02, 0x00, 0x00],
        ),
    ];
    for (name, value) in cases {
        let as4 = attr(AS4_PATH_FLAGS, 17, value);
        let m = expect_malformed(
            &legacy_update(&[0x02, 0x01, 0x5b, 0xa0], &[&as4]),
            AsnWidth::Two,
        );
        assert!(!m.treat_as_withdraw && !m.session_reset, "{name}");
        assert_eq!(m.errors.len(), 1, "{name}: {:?}", m.errors);
        assert_eq!(m.errors[0].type_code, 17, "{name}");
        assert_eq!(
            m.errors[0].policy,
            AttributeErrorPolicy::AttributeDiscard,
            "{name}"
        );
        assert_eq!(
            m.update,
            expected_update(path(vec![seq(&[23456])]), vec![]),
            "{name}"
        );
    }
}

/// RFC 6793 §4.2.3, `AGGREGATOR` rules. `AS_TRANS` in `AGGREGATOR` means the real
/// aggregator is in `AS4_AGGREGATOR`, which replaces it.
#[test]
fn as4_aggregator_replaces_an_as_trans_aggregator() {
    let agg = attr(0xC0, 7, &[0x5b, 0xa0, 10, 0, 0, 1]);
    let agg4 = attr(0xC0, 18, &[0x00, 0x02, 0x00, 0x00, 10, 0, 0, 1]);
    let got = expect_clean(&legacy_update(&[], &[&agg, &agg4]), AsnWidth::Two);
    assert_eq!(
        got,
        expected_update(
            AsPath::new(),
            vec![PathAttribute::Aggregator(Aggregator::new(
                Asn::new(131_072),
                Ipv4Addr::new(10, 0, 0, 1)
            ))]
        )
    );
}

/// §4.2.3: "if the AS number in the `AGGREGATOR` attribute is not `AS_TRANS`,
/// then: the `AS4_AGGREGATOR` attribute and the `AS4_PATH` attribute SHALL be
/// ignored, the `AGGREGATOR` attribute SHALL be taken ..., and the `AS_PATH`
/// attribute SHALL be taken as the AS path information."
#[test]
fn non_trans_aggregator_makes_as4_aggregator_and_as4_path_ignored() {
    let agg = attr(0xC0, 7, &[0xfd, 0xe9, 10, 0, 0, 1]); // 65001, not AS_TRANS
    let agg4 = attr(0xC0, 18, &[0x00, 0x02, 0x00, 0x00, 10, 0, 0, 9]);
    let as4 = attr(AS4_PATH_FLAGS, 17, &[0x02, 0x01, 0x00, 0x02, 0x00, 0x00]);
    let got = expect_clean(
        &legacy_update(&[0x02, 0x01, 0x5b, 0xa0], &[&agg, &agg4, &as4]),
        AsnWidth::Two,
    );
    assert_eq!(
        got,
        expected_update(
            path(vec![seq(&[23456])]),
            vec![PathAttribute::Aggregator(Aggregator::new(
                Asn::new(65001),
                Ipv4Addr::new(10, 0, 0, 1)
            ))]
        )
    );
}

/// A lone `AS4_AGGREGATOR` has no `AGGREGATOR` to supersede: it is dropped and
/// never leaks to the rest of the system.
#[test]
fn lone_as4_aggregator_is_dropped() {
    let agg4 = attr(0xC0, 18, &[0x00, 0x02, 0x00, 0x00, 10, 0, 0, 1]);
    let got = expect_clean(&legacy_update(&[], &[&agg4]), AsnWidth::Two);
    assert_eq!(got, expected_update(AsPath::new(), vec![]));
}

// ═════════════════════════════════════════════════════════════════════════════
// Receive, four-octet session: AS4_* MUST be discarded (RFC 6793 §4.1, §6)
// ═════════════════════════════════════════════════════════════════════════════

/// "A NEW BGP speaker that receives the `AS4_PATH` attribute or the
/// `AS4_AGGREGATOR` attribute in an UPDATE message from another NEW BGP
/// speaker MUST discard the path attribute and continue processing the
/// UPDATE message. This case SHOULD be logged locally for analysis."
/// Well-formed but policy-violating input (CLAUDE.md item 5): the `AS_PATH`
/// stays authoritative, the update is *not* withdrawn, neither attribute
/// reaches the caller, and each discard is reported for logging.
#[test]
fn as4_attributes_from_a_four_octet_peer_are_discarded_and_logged() {
    let as_path = [0x02, 0x01, 0x00, 0x00, 0xfd, 0xea]; // 65002
    let agg = attr(0xC0, 7, &[0x00, 0x00, 0xfd, 0xe9, 10, 0, 0, 1]);
    let as4 = attr(AS4_PATH_FLAGS, 17, &[0x02, 0x01, 0x00, 0x02, 0x00, 0x00]);
    let agg4 = attr(0xC0, 18, &[0x00, 0x02, 0x00, 0x00, 10, 0, 0, 9]);
    let m = expect_malformed(
        &legacy_update(&as_path, &[&agg, &as4, &agg4]),
        AsnWidth::Four,
    );
    assert!(!m.treat_as_withdraw && !m.session_reset);
    let mut logged: Vec<u8> = m.errors.iter().map(|e| e.type_code).collect();
    logged.sort_unstable();
    assert_eq!(logged, vec![17, 18]);
    assert!(
        m.errors
            .iter()
            .all(|e| e.policy == AttributeErrorPolicy::AttributeDiscard)
    );
    assert_eq!(
        m.update,
        expected_update(
            path(vec![seq(&[65002])]),
            vec![PathAttribute::Aggregator(Aggregator::new(
                Asn::new(65001),
                Ipv4Addr::new(10, 0, 0, 1)
            ))]
        )
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Send, exact wire bytes
// ═════════════════════════════════════════════════════════════════════════════

/// Just the path-attribute block of an encoded UPDATE.
fn attr_block(frame: &[u8]) -> &[u8] {
    let withdrawn = usize::from(u16::from_be_bytes([frame[19], frame[20]]));
    let at = 21 + withdrawn;
    let len = usize::from(u16::from_be_bytes([frame[at], frame[at + 1]]));
    &frame[at + 2..at + 2 + len]
}

fn update_with(attrs: Vec<PathAttribute>) -> BgpMessage {
    BgpMessage::Update(UpdateMessage {
        withdrawn: vec![],
        attributes: attrs,
        announced: vec![prefix()],
    })
}

fn p(v: Vec<AsPathSegment>) -> PathAttribute {
    PathAttribute::AsPath(path(v))
}

/// RFC 6793 §4.2.2: "MUST send the AS path information in the `AS_PATH`
/// attribute encoded with two-octet AS numbers".
#[test]
fn two_octet_session_encodes_two_octet_as_path() {
    let msg = update_with(vec![p(vec![seq(&[65002, 65001])])]);
    let bytes = msg.encode_with(AsnWidth::Two);
    assert_eq!(
        attr_block(&bytes),
        &[0x40, 0x02, 0x06, 0x02, 0x02, 0xfd, 0xea, 0xfd, 0xe9]
    );
    // Whole message, byte for byte: header(19) + wd len(2) + attr len(2) +
    // AS_PATH TLV(9) + NLRI(4).
    let mut want = vec![0xFF; 16];
    want.extend_from_slice(&[0x00, 36, 2, 0, 0, 0, 9]);
    want.extend_from_slice(&[0x40, 0x02, 0x06, 0x02, 0x02, 0xfd, 0xea, 0xfd, 0xe9]);
    want.extend_from_slice(&[24, 198, 51, 100]);
    assert_eq!(bytes, want);
    // ... and a four-octet session still writes four.
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Four)),
        &[
            0x40, 0x02, 0x0a, 0x02, 0x02, 0, 0, 0xfd, 0xea, 0, 0, 0xfd, 0xe9
        ]
    );
}

/// §4.2.2: a non-mappable ASN is written as `AS_TRANS`, "and the NEW BGP
/// speaker MUST also send the AS path information in the `AS4_PATH` attribute
/// (encoded with four-octet AS numbers)".
#[test]
fn non_mappable_asn_becomes_as_trans_with_as4_path_generated() {
    let msg = update_with(vec![p(vec![seq(&[65001, 131_072])])]);
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Two)),
        &[
            0x40, 0x02, 0x06, 0x02, 0x02, 0xfd, 0xe9, 0x5b, 0xa0, // AS_PATH
            0xC0, 0x11, 0x0a, 0x02, 0x02, 0x00, 0x00, 0xfd, 0xe9, 0x00, 0x02, 0x00,
            0x00, // AS4_PATH
        ]
    );
}

/// The daemon already hands the codec an `AS_TRANS`-substituted `AS_PATH` plus
/// its own `AS4_PATH` attribute; the codec must not add a second `AS4_PATH`.
#[test]
fn caller_supplied_as4_path_is_not_duplicated() {
    let msg = update_with(vec![
        p(vec![seq(&[65001, 23456])]),
        PathAttribute::As4Path(path(vec![seq(&[65001, 131_072])])),
    ]);
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Two)),
        &[
            0x40, 0x02, 0x06, 0x02, 0x02, 0xfd, 0xe9, 0x5b, 0xa0, 0xC0, 0x11, 0x0a, 0x02, 0x02,
            0x00, 0x00, 0xfd, 0xe9, 0x00, 0x02, 0x00, 0x00,
        ]
    );
}

/// §4.2.2: `AS4_PATH` "MUST NOT" be sent "where all of the AS path
/// information is composed of mappable four-octet AS numbers only".
#[test]
fn no_as4_path_when_every_asn_is_mappable() {
    let msg = update_with(vec![p(vec![seq(&[65535, 23456, 1])])]);
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Two)),
        &[
            0x40, 0x02, 0x08, 0x02, 0x03, 0xff, 0xff, 0x5b, 0xa0, 0x00, 0x01
        ]
    );
}

/// §4.2.2: confederation segments are excluded from the `AS4_PATH` being
/// constructed, but stay (two-octet) in `AS_PATH`.
#[test]
fn generated_as4_path_excludes_confed_segments() {
    let msg = update_with(vec![p(vec![cseq(&[65010]), seq(&[131_072])])]);
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Two)),
        &[
            0x40, 0x02, 0x08, 0x03, 0x01, 0xfd, 0xf2, 0x02, 0x01, 0x5b, 0xa0, // AS_PATH
            0xC0, 0x11, 0x06, 0x02, 0x01, 0x00, 0x02, 0x00, 0x00, // AS4_PATH: no confed
        ]
    );
}

/// A non-mappable ASN that lives only in a confederation segment needs no
/// `AS4_PATH`: the `AS4_PATH` would carry nothing the `AS_PATH`'s non-confed
/// content does not.
#[test]
fn no_as4_path_when_only_confed_segments_are_non_mappable() {
    let msg = update_with(vec![p(vec![cseq(&[131_072]), seq(&[65001])])]);
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Two)),
        &[
            0x40, 0x02, 0x08, 0x03, 0x01, 0x5b, 0xa0, 0x02, 0x01, 0xfd, 0xe9
        ]
    );
}

/// §4.2.2: "if the aggregating Autonomous System's AS number is a
/// non-mappable four-octet AS number, then the speaker MUST use the
/// `AS4_AGGREGATOR` attribute and set the AS number field in the existing
/// `AGGREGATOR` attribute to ... `AS_TRANS`."
#[test]
fn non_mappable_aggregator_uses_as_trans_and_as4_aggregator() {
    let agg = PathAttribute::Aggregator(Aggregator::new(
        Asn::new(131_072),
        Ipv4Addr::new(10, 0, 0, 1),
    ));
    let msg = update_with(vec![p(vec![]), agg]);
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Two)),
        &[
            0x40, 0x02, 0x00, // empty AS_PATH
            0xC0, 0x07, 0x06, 0x5b, 0xa0, 10, 0, 0, 1, // AGGREGATOR: AS_TRANS
            0xC0, 0x12, 0x08, 0x00, 0x02, 0x00, 0x00, 10, 0, 0, 1, // AS4_AGGREGATOR
        ]
    );
}

/// "Note that if the AS number is mappable, then the `AS4_AGGREGATOR`
/// attribute MUST NOT be sent."
#[test]
fn mappable_aggregator_is_six_bytes_with_no_as4_aggregator() {
    let agg =
        PathAttribute::Aggregator(Aggregator::new(Asn::new(65001), Ipv4Addr::new(10, 0, 0, 1)));
    let msg = update_with(vec![p(vec![]), agg]);
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Two)),
        &[0x40, 0x02, 0x00, 0xC0, 0x07, 0x06, 0xfd, 0xe9, 10, 0, 0, 1]
    );
    // Four-octet session: eight bytes.
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Four)),
        &[
            0x40, 0x02, 0x00, 0xC0, 0x07, 0x08, 0, 0, 0xfd, 0xe9, 10, 0, 0, 1
        ]
    );
}

/// `AS4_PATH` is four-octet on every session, even when the caller supplies it
/// for a two-octet peer.
#[test]
fn as4_path_stays_four_octet_on_a_two_octet_session() {
    let msg = update_with(vec![
        p(vec![seq(&[23456])]),
        PathAttribute::As4Path(path(vec![seq(&[131_072])])),
    ]);
    let block = attr_block(&msg.encode_with(AsnWidth::Two)).to_vec();
    assert!(block.ends_with(&[0xC0, 0x11, 0x06, 0x02, 0x01, 0x00, 0x02, 0x00, 0x00]));
}

/// RFC 6793 §4.1: `AS4_PATH` / `AS4_AGGREGATOR` "MUST NOT be carried in an
/// UPDATE message between NEW BGP speakers" — a caller who attaches them for
/// a four-octet peer anyway gets neither on the wire.
#[test]
fn as4_attributes_are_never_sent_on_a_four_octet_session() {
    let msg = update_with(vec![
        p(vec![seq(&[65001, 131_072])]),
        PathAttribute::As4Path(path(vec![seq(&[65001, 131_072])])),
        PathAttribute::As4Aggregator {
            asn: 131_072,
            bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        },
    ]);
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Four)),
        &[
            0x40, 0x02, 0x0a, 0x02, 0x02, 0, 0, 0xfd, 0xe9, 0x00, 0x02, 0x00, 0x00
        ]
    );
}

// ── 255-ASN segment limit on encode (RFC 4271 §4.3) ──────────────────────────

fn parse_segment_counts(as_path_value: &[u8], width: usize) -> Vec<(u8, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < as_path_value.len() {
        let t = as_path_value[i];
        let n = usize::from(as_path_value[i + 1]);
        out.push((t, n));
        i += 2 + n * width;
    }
    assert_eq!(i, as_path_value.len(), "segments must tile the attribute");
    out
}

/// A 300-ASN `AS_SEQUENCE` cannot fit one segment (count is one octet); a
/// bare `len as u8` would write 44 and corrupt the framing. It must split
/// into 255 + 45 at either width and decode back to the same flat path.
#[test]
fn oversized_sequence_splits_into_255_asn_segments_at_both_widths() {
    let flat: Vec<u32> = (0..300).map(|i| 1000 + i).collect();
    let msg = update_with(vec![p(vec![seq(&flat)])]);
    for width in [AsnWidth::Two, AsnWidth::Four] {
        let bytes = msg.encode_with(width);
        let block = attr_block(&bytes);
        // extended-length AS_PATH: flags 0x50, type 2, 2-byte length.
        assert_eq!(&block[..2], &[0x50, 0x02], "{width:?}");
        let len = usize::from(u16::from_be_bytes([block[2], block[3]]));
        let value = &block[4..4 + len];
        assert_eq!(
            parse_segment_counts(value, width.octets()),
            vec![(2, 255), (2, 45)],
            "{width:?}"
        );
        // Decode: same ASNs in order, path length preserved.
        let got = expect_clean(&bytes, width);
        let PathAttribute::AsPath(round) = &got.attributes[0] else {
            panic!("AS_PATH first")
        };
        let flat_back: Vec<u32> = round
            .segments()
            .iter()
            .flat_map(|s| s.asns().iter().map(|a| a.as_u32()))
            .collect();
        assert_eq!(flat_back, flat, "{width:?}");
        assert_eq!(round.path_length(), 300, "{width:?}");
    }
}

/// A segment of exactly 255 is written unsplit; empty segments (which RFC
/// 7606 §7.2 calls malformed) are never emitted.
#[test]
fn exactly_255_is_unsplit_and_empty_segments_are_skipped() {
    let flat: Vec<u32> = (0..255).map(|i| 1000 + i).collect();
    let msg = update_with(vec![p(vec![seq(&[]), seq(&flat), set(&[])])]);
    let bytes = msg.encode_with(AsnWidth::Two);
    let block = attr_block(&bytes);
    let len = usize::from(u16::from_be_bytes([block[2], block[3]]));
    assert_eq!(parse_segment_counts(&block[4..4 + len], 2), vec![(2, 255)]);
}

// ═════════════════════════════════════════════════════════════════════════════
// Round trips across the width boundary
// ═════════════════════════════════════════════════════════════════════════════

/// Our encoder -> a legacy peer's view -> our decoder: a NEW speaker sends a
/// path with four-octet ASNs to an OLD peer and the same route is later
/// received back from an OLD speaker that forwarded `AS_PATH` and `AS4_PATH`
/// unchanged. The merged result is the original path (RFC 6793's whole
/// point).
#[test]
fn encode_for_old_peer_then_decode_as_old_peer_recovers_the_true_path() {
    let original = path(vec![
        seq(&[65001, 131_072, 4_200_000_001, 65002]),
        set(&[7, 70_000]),
    ]);
    let msg = update_with(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(original.clone()),
        PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
    ]);
    let wire = msg.encode_with(AsnWidth::Two);
    // Decoding at the same (two-octet) width merges AS4_PATH back.
    let BgpMessage::Update(u) = decode(&wire, AsnWidth::Two) else {
        panic!("clean update expected")
    };
    assert_eq!(u.attributes[1], PathAttribute::AsPath(original));
    assert!(
        !u.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::As4Path(_)))
    );
}

/// RFC 6793 §6 calls an AS4_PATH shorter than 6 octets malformed, so an
/// empty one (e.g. a caller that stripped confederation segments from a
/// path that had only those) must never be written — and it must not
/// suppress the generation of a real one either.
#[test]
fn empty_as4_path_is_never_written() {
    let msg = update_with(vec![
        p(vec![seq(&[65001])]),
        PathAttribute::As4Path(AsPath::new()),
    ]);
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Two)),
        &[0x40, 0x02, 0x04, 0x02, 0x01, 0xfd, 0xe9]
    );
    let msg = update_with(vec![
        p(vec![seq(&[131_072])]),
        PathAttribute::As4Path(AsPath::new()),
    ]);
    assert_eq!(
        attr_block(&msg.encode_with(AsnWidth::Two)),
        &[
            0x40, 0x02, 0x04, 0x02, 0x01, 0x5b, 0xa0, 0xC0, 0x11, 0x06, 0x02, 0x01, 0x00, 0x02,
            0x00, 0x00
        ]
    );
}
