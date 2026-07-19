use std::net::Ipv4Addr;

use proptest::prelude::*;

use crate::{AsPath, Asn, Community, LargeCommunity, LocalPref, Med, Nlri, Origin};

// ── Strategies ─────────────────────────────────────────────────────────────

prop_compose! {
    /// Generates an arbitrary ASN across the full 32-bit range.
    fn arb_asn()(val in 0u32..=u32::MAX) -> Asn {
        Asn::new(val)
    }
}

prop_compose! {
    /// Generates an AS path of 0–8 hops as a single Sequence segment.
    ///
    /// All generated paths have a simple structure (one Sequence) to keep
    /// invariant reasoning straightforward. Complex segment types (Set,
    /// ConfedSequence) are covered by targeted unit tests.
    fn arb_as_path()(
        asns in proptest::collection::vec(1u32..=65535, 0..=8),
    ) -> AsPath {
        if asns.is_empty() {
            AsPath::new()
        } else {
            AsPath::from_sequence(asns.into_iter().map(Asn::new).collect())
        }
    }
}

prop_compose! {
    /// Generates an arbitrary standard community across the full 32-bit range.
    fn arb_community()(val in 0u32..=u32::MAX) -> Community {
        Community::new(val)
    }
}

prop_compose! {
    /// Generates an arbitrary large community with independent 32-bit fields.
    fn arb_large_community()(
        ga  in 0u32..=u32::MAX,
        ld1 in 0u32..=u32::MAX,
        ld2 in 0u32..=u32::MAX,
    ) -> LargeCommunity {
        LargeCommunity::new(ga, ld1, ld2)
    }
}

prop_compose! {
    /// Generates an arbitrary masked IPv4 NLRI with prefix length 0–32.
    fn arb_nlri()(
        a    in 0u8..=255,
        b    in 0u8..=255,
        mask in 0u8..=32,
    ) -> Nlri<Ipv4Addr> {
        // masked() zeroes host bits so the prefix is in canonical CIDR form.
        Nlri::new(Ipv4Addr::new(a, b, 0, 0), mask).unwrap().masked()
    }
}

// ── Asn invariants ─────────────────────────────────────────────────────────

proptest! {
    /// Converting a u32 to Asn and back always roundtrips exactly.
    #[test]
    fn prop_asn_u32_roundtrip(val in 0u32..=u32::MAX) {
        let asn = Asn::new(val);
        prop_assert_eq!(u32::from(asn), val);
    }

    /// An ASN is four-byte if and only if its value exceeds the 16-bit limit.
    ///
    /// This matters for wire encoding: 4-byte ASNs require special handling
    /// when talking to 2-byte-only peers (AS_TRANS substitution, RFC 6793).
    #[test]
    fn prop_asn_is_four_byte_iff_exceeds_u16(val in 0u32..=u32::MAX) {
        prop_assert_eq!(Asn::new(val).is_four_byte(), val > u32::from(u16::MAX));
    }

    /// Private ASNs fall in exactly the two IANA-defined private ranges.
    ///
    /// Private ASNs must be stripped on export to the public internet.
    /// Testing the boundary conditions ensures strip-on-export logic is not
    /// applied to public ASNs or extended beyond the private ranges.
    #[test]
    fn prop_asn_is_private_matches_defined_ranges(val in 0u32..=u32::MAX) {
        let in_2b_range = (64512..=65534).contains(&val);
        let in_4b_range = (4_200_000_000..=4_294_967_294).contains(&val);
        prop_assert_eq!(Asn::new(val).is_private(), in_2b_range || in_4b_range);
    }
}

// ── AsPath invariants ───────────────────────────────────────────────────────

proptest! {
    /// A path built from a Sequence of N ASNs has path_length exactly N.
    ///
    /// AS_SEQUENCE segments contribute one per ASN to the BGP path length
    /// used in best-path selection (RFC 4271 §9.1.2.2).
    #[test]
    fn prop_aspath_from_sequence_length_equals_asn_count(
        asns in proptest::collection::vec(1u32..=65535, 0..=8),
    ) {
        let path = if asns.is_empty() {
            AsPath::new()
        } else {
            AsPath::from_sequence(asns.iter().copied().map(Asn::new).collect())
        };
        prop_assert_eq!(path.path_length(), asns.len());
    }

    /// Prepending an ASN always increases path_length by exactly 1.
    ///
    /// This invariant holds regardless of the path's current structure:
    /// an empty path, a Sequence of any size, or a path with a Set as its
    /// first segment all increase by exactly 1. The underlying `prepend()`
    /// either inserts into an existing Sequence or creates a new one of
    /// length 1 — both contribute exactly 1 to path_length.
    #[test]
    fn prop_aspath_prepend_increases_length_by_one(
        mut path in arb_as_path(),
        asn in arb_asn(),
    ) {
        let before = path.path_length();
        path.prepend(asn);
        prop_assert_eq!(path.path_length(), before + 1);
    }

    /// After prepending an ASN, contains() returns true for that ASN.
    #[test]
    fn prop_aspath_prepend_then_contains(
        mut path in arb_as_path(),
        asn_val in 1u32..=65535,
    ) {
        let asn = Asn::new(asn_val);
        path.prepend(asn);
        prop_assert!(path.contains(asn));
    }

    /// Prepending an ASN never changes the RFC 6811 origin AS of a
    /// non-empty path.
    ///
    /// `prepend` only ever touches the *first* segment (see its own doc
    /// comment); `origin_as` is derived solely from the *last* segment
    /// (RFC 6811 §2). For a non-empty path those are different segments
    /// (or the same single segment growing in place, which doesn't change
    /// its *last* element either), so prepending can't affect the result.
    #[test]
    fn prop_aspath_prepend_preserves_origin_as(
        mut path in arb_as_path(),
        asn in arb_asn(),
        local_as in arb_asn(),
    ) {
        // `arb_as_path()` only ever generates an empty path or a single
        // Sequence segment (see its own doc comment), so `path_length() ==
        // 0` is an exact proxy for "empty" here — it wouldn't be for an
        // arbitrary AsPath (a confederation-only path also has length 0).
        let was_empty = path.path_length() == 0;
        let origin_before = path.origin_as(local_as);
        path.prepend(asn);
        // origin_as only changes if the path was empty before: RFC 6811 §2
        // substitutes `local_as` for an empty AS_PATH, so it goes from
        // Some(local_as) to Some(asn) once `asn` is prepended. For
        // non-empty paths it must be unchanged.
        if !was_empty {
            prop_assert_eq!(path.origin_as(local_as), origin_before);
        }
    }
}

// ── Community invariants ────────────────────────────────────────────────────

proptest! {
    /// from_parts(high, low) roundtrips through .high() and .low().
    ///
    /// The standard community is a 32-bit value split into two 16-bit halves.
    /// The high half is conventionally the operator's ASN; the low half is a
    /// locally meaningful value. These invariants ensure the bit-packing is
    /// exact with no information loss.
    #[test]
    fn prop_community_from_parts_roundtrip(
        high in 0u16..=u16::MAX,
        low  in 0u16..=u16::MAX,
    ) {
        let c = Community::from_parts(high, low);
        prop_assert_eq!(c.high(), high);
        prop_assert_eq!(c.low(), low);
    }

    /// Community::new(v).as_u32() == v for all v.
    #[test]
    fn prop_community_new_as_u32_roundtrip(val in 0u32..=u32::MAX) {
        prop_assert_eq!(Community::new(val).as_u32(), val);
    }

    /// A community is well-known iff its high half is 0xFFFF.
    ///
    /// Well-known communities (NO_EXPORT, NO_ADVERTISE, etc.) use 0xFFFF
    /// in the high half because 65535 is not a valid public ASN, guaranteeing
    /// no collision with operator-defined communities.
    #[test]
    fn prop_community_is_well_known_iff_high_is_ffff(
        high in 0u16..=u16::MAX,
        low  in 0u16..=u16::MAX,
    ) {
        let c = Community::from_parts(high, low);
        prop_assert_eq!(c.is_well_known(), high == 0xFFFF);
    }

    /// From<u32> and From<Community> for u32 are inverses.
    #[test]
    fn prop_community_from_u32_roundtrip(val in 0u32..=u32::MAX) {
        let c = Community::from(val);
        prop_assert_eq!(u32::from(c), val);
    }
}

// ── LargeCommunity invariants ───────────────────────────────────────────────

proptest! {
    /// to_bytes / from_bytes roundtrip is lossless.
    ///
    /// Large communities are carried as 12-byte wire values. Any large
    /// community must survive serialisation to bytes and deserialisation
    /// back to an identical struct. This matters for BMP and session
    /// message encoding.
    #[test]
    fn prop_large_community_bytes_roundtrip(lc in arb_large_community()) {
        prop_assert_eq!(LargeCommunity::from_bytes(lc.to_bytes()), lc);
    }

    /// The three fields are stored and retrieved independently.
    #[test]
    fn prop_large_community_fields_independent(
        ga  in 0u32..=u32::MAX,
        ld1 in 0u32..=u32::MAX,
        ld2 in 0u32..=u32::MAX,
    ) {
        let lc = LargeCommunity::new(ga, ld1, ld2);
        prop_assert_eq!(lc.global_administrator, ga);
        prop_assert_eq!(lc.local_data_1, ld1);
        prop_assert_eq!(lc.local_data_2, ld2);
    }
}

// ── Nlri invariants ─────────────────────────────────────────────────────────

proptest! {
    /// prefix_len() matches the mask used to construct the Nlri.
    #[test]
    fn prop_nlri_prefix_len_roundtrip(
        a    in 0u8..=255,
        b    in 0u8..=255,
        mask in 0u8..=32,
    ) {
        let nlri = Nlri::new(Ipv4Addr::new(a, b, 0, 0), mask).unwrap();
        prop_assert_eq!(nlri.prefix_len(), mask);
    }

    /// The masked network address is always contained within its own prefix.
    ///
    /// This is a fundamental property of CIDR: the network address of a
    /// prefix is the smallest address in that prefix's range. Any prefix-list
    /// match that checks network containment must satisfy this.
    #[test]
    fn prop_nlri_network_address_contains_itself(nlri in arb_nlri()) {
        prop_assert!(nlri.contains(nlri.prefix().ip()));
    }

    /// A prefix is always self-overlapping.
    #[test]
    fn prop_nlri_overlaps_self(nlri in arb_nlri()) {
        prop_assert!(nlri.overlaps(&nlri));
    }

    /// is_default_route() is true iff prefix_len is 0.
    ///
    /// The default route (0.0.0.0/0 or ::/0) has prefix length 0 and matches
    /// every address. It is commonly advertised by ISPs to customers who do
    /// not need the full routing table.
    #[test]
    fn prop_nlri_is_default_route_iff_mask_zero(nlri in arb_nlri()) {
        prop_assert_eq!(nlri.is_default_route(), nlri.prefix_len() == 0);
    }

    /// is_host_route() is true iff prefix_len is 32 (for IPv4).
    ///
    /// Host routes (/32) cover exactly one address. They are used for
    /// loopback advertisement, blackhole routing, and ECMP next-hop
    /// resolution.
    #[test]
    fn prop_nlri_is_host_route_iff_mask_is_32(nlri in arb_nlri()) {
        prop_assert_eq!(nlri.is_host_route(), nlri.prefix_len() == 32);
    }
}

// ── Origin invariants ───────────────────────────────────────────────────────

proptest! {
    /// Origin::from_u8(origin.as_u8()) is always Some(origin).
    ///
    /// Every valid Origin variant must survive the wire byte roundtrip.
    /// If this fails, a parsed BGP UPDATE could silently lose origin
    /// information.
    #[test]
    fn prop_origin_as_u8_roundtrip(origin_byte in 0u8..=2u8) {
        let origin = Origin::from_u8(origin_byte).unwrap();
        prop_assert_eq!(origin.as_u8(), origin_byte);
        prop_assert_eq!(Origin::from_u8(origin.as_u8()), Some(origin));
    }

    /// Origin::from_u8 returns None for any value outside [0, 2].
    #[test]
    fn prop_origin_from_u8_none_outside_range(byte in 3u8..=u8::MAX) {
        prop_assert_eq!(Origin::from_u8(byte), None);
    }
}

// ── LocalPref / Med ordering invariants ────────────────────────────────────

proptest! {
    /// LocalPref ordering is consistent with the underlying u32.
    ///
    /// Best-path selection favours higher LOCAL_PREF. The ordering on
    /// the type must match the semantics the decision algorithm relies on.
    #[test]
    fn prop_local_pref_ordering_matches_u32(a in 0u32..=u32::MAX, b in 0u32..=u32::MAX) {
        prop_assert_eq!(
            LocalPref::new(a).cmp(&LocalPref::new(b)),
            a.cmp(&b)
        );
    }

    /// Med ordering is consistent with the underlying u32.
    ///
    /// Best-path selection favours lower MED. The ordering on the type must
    /// match so callers can compare MEDs directly without unwrapping.
    #[test]
    fn prop_med_ordering_matches_u32(a in 0u32..=u32::MAX, b in 0u32..=u32::MAX) {
        prop_assert_eq!(
            Med::new(a).cmp(&Med::new(b)),
            a.cmp(&b)
        );
    }
}
