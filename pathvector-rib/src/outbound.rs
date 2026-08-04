use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use pathvector_types::{Asn, Community, NextHop, PeerType};

use crate::Route;

/// Returns `true` if `communities` carries an RFC 1997 well-known community
/// that forbids advertising the route to a peer of `peer_type`.
///
/// - `NO_ADVERTISE`: "MUST NOT be advertised to other BGP peers" — blocks
///   every peer, internal or external.
/// - `NO_EXPORT`: "MUST NOT be advertised outside a BGP confederation
///   boundary (a stand-alone autonomous system that is not part of a
///   confederation should be considered a confederation itself)" — blocks
///   only genuinely external (`External`) peers. A confederation-member
///   (`ConfedMember`, RFC 5065) peer is, by definition, still inside the
///   confederation boundary, so `NO_EXPORT` does NOT block it.
/// - `NO_EXPORT_SUBCONFED`: "MUST NOT be advertised to external BGP peers
///   (this includes peers in other members autonomous systems inside a BGP
///   confederation)" — explicitly blocks both `External` and `ConfedMember`.
#[must_use]
pub fn is_export_suppressed(communities: &[Community], peer_type: PeerType) -> bool {
    communities.iter().any(|c| {
        c.is_no_advertise()
            || (c.is_no_export() && peer_type == PeerType::External)
            || (c.is_no_export_subconfed()
                && matches!(peer_type, PeerType::External | PeerType::ConfedMember))
    })
}

/// Applies eBGP outbound transforms to a route clone before insertion into
/// `AdjRibOut` or serialisation into an UPDATE message:
///
/// - `External`: strip confederation segments (RFC 5065 §4.1(c) — before
///   prepending, not after; see the `ConfedMember` branch's doc comment for
///   why this order matters), then prepend `public_as` to `AS_PATH` (RFC
///   4271 §9.2.1.2). Rewrite `NEXT_HOP` to `local_next_hop`. Strip
///   `LOCAL_PREF` (RFC 4271 §5.1.5 — must not be sent to eBGP peers).
/// - `ConfedMember` (RFC 5065 §4.1(b)): prepend `local_as` (the Member-AS
///   Number, not `public_as`) into a `ConfedSequence` segment instead of
///   `AS_PATH`'s public `Sequence`. `NEXT_HOP` is left unchanged by default
///   (§5.1) — only rewritten when `next_hop_self`, same as `Internal`.
///   `LOCAL_PREF` is preserved (§5.2 removes the eBGP-only restriction).
/// - `Internal`/`Local`: unchanged, except `NEXT_HOP` is rewritten to
///   `local_next_hop` when `next_hop_self` is true — required when a route
///   reflector sits between iBGP clients that cannot reach the original
///   eBGP next-hop directly.
///
/// `local_as` is this daemon's own (possibly private) Member-AS Number;
/// `public_as` is the AS number advertised to genuine external peers —
/// the confederation identifier when confederations are configured, or
/// `local_as` again when they are not. Callers resolve which value is
/// which; this function does not know whether a confederation is
/// configured.
#[must_use]
pub fn prepare_outbound(
    mut route: Route<Ipv4Addr>,
    peer_type: PeerType,
    local_as: u32,
    public_as: u32,
    local_next_hop: Ipv4Addr,
    next_hop_self: bool,
) -> Route<Ipv4Addr> {
    match peer_type {
        PeerType::External => {
            route.as_path = Arc::new(route.as_path.strip_confed_segments());
            Arc::make_mut(&mut route.as_path).prepend(Asn::new(public_as));
            route.next_hop = Some(NextHop::V4(local_next_hop));
            route.local_pref = None;
        }
        PeerType::ConfedMember => {
            Arc::make_mut(&mut route.as_path).prepend_confed(Asn::new(local_as));
            if next_hop_self {
                route.next_hop = Some(NextHop::V4(local_next_hop));
            }
        }
        PeerType::Internal | PeerType::Local => {
            if next_hop_self {
                route.next_hop = Some(NextHop::V4(local_next_hop));
            }
        }
    }
    route
}

/// Applies eBGP outbound transforms to an IPv6 route clone. See
/// [`prepare_outbound`] for the full per-`peer_type` behavior — this is the
/// same logic against `Ipv6Addr` `NEXT_HOP`s (RFC 4760 §4.3).
///
/// When `local_ipv6` is `None`, `NEXT_HOP` rewrites are skipped entirely
/// (both the `External` and `next_hop_self` cases); callers are
/// responsible for suppressing the route outbound if the peer cannot reach
/// the original next-hop.
#[must_use]
pub fn prepare_outbound_v6(
    mut route: Route<Ipv6Addr>,
    peer_type: PeerType,
    local_as: u32,
    public_as: u32,
    local_ipv6: Option<Ipv6Addr>,
    next_hop_self: bool,
) -> Route<Ipv6Addr> {
    match peer_type {
        PeerType::External => {
            route.as_path = Arc::new(route.as_path.strip_confed_segments());
            Arc::make_mut(&mut route.as_path).prepend(Asn::new(public_as));
            if let Some(addr) = local_ipv6 {
                route.next_hop = Some(NextHop::V6(addr));
            }
            route.local_pref = None;
        }
        PeerType::ConfedMember => {
            Arc::make_mut(&mut route.as_path).prepend_confed(Asn::new(local_as));
            if next_hop_self && let Some(addr) = local_ipv6 {
                route.next_hop = Some(NextHop::V6(addr));
            }
        }
        PeerType::Internal | PeerType::Local => {
            if next_hop_self && let Some(addr) = local_ipv6 {
                route.next_hop = Some(NextHop::V6(addr));
            }
        }
    }
    route
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RouteBuilder;
    use pathvector_types::{AsPath, LocalPref, Nlri, Origin};

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    #[test]
    fn test_prepare_outbound_ebgp_transforms_route() {
        let local_as = 65000_u32;
        let local_next_hop = Ipv4Addr::new(10, 0, 0, 1);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .build();

        let out = prepare_outbound(
            route,
            PeerType::External,
            local_as,
            local_as,
            local_next_hop,
            false,
        );

        assert_eq!(out.as_path.path_length(), 1);
        assert_eq!(out.next_hop, Some(NextHop::V4(local_next_hop)));
        assert!(out.local_pref.is_none());
    }

    #[test]
    fn test_prepare_outbound_ibgp_leaves_route_unchanged() {
        let local_as = 65000_u32;
        let local_next_hop = Ipv4Addr::new(10, 0, 0, 1);
        let lp = LocalPref::new(100);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .local_pref(lp)
            .build();

        let out = prepare_outbound(
            route,
            PeerType::Internal,
            local_as,
            local_as,
            local_next_hop,
            false,
        );

        assert_eq!(out.as_path.path_length(), 0);
        assert!(out.next_hop.is_none());
        assert_eq!(out.local_pref, Some(lp));
    }

    fn nlri6(s: &str) -> Nlri<Ipv6Addr> {
        s.parse().unwrap()
    }

    #[test]
    fn test_prepare_outbound_v6_ebgp_transforms_route() {
        let local_as = 65000_u32;
        let local_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .local_pref(LocalPref::new(100))
            .next_hop(NextHop::V6("2001:db8::9".parse().unwrap()))
            .build();

        let out = prepare_outbound_v6(
            route,
            PeerType::External,
            local_as,
            local_as,
            Some(local_v6),
            false,
        );

        assert_eq!(out.as_path.path_length(), 1);
        assert_eq!(out.next_hop, Some(NextHop::V6(local_v6)));
        assert!(out.local_pref.is_none());
    }

    #[test]
    fn test_prepare_outbound_v6_ibgp_leaves_route_unchanged() {
        let local_as = 65000_u32;
        let lp = LocalPref::new(100);
        let orig_nh: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .local_pref(lp)
            .next_hop(NextHop::V6(orig_nh))
            .build();

        let out = prepare_outbound_v6(route, PeerType::Internal, local_as, local_as, None, false);

        assert_eq!(out.as_path.path_length(), 0);
        assert_eq!(out.next_hop, Some(NextHop::V6(orig_nh)));
        assert_eq!(out.local_pref, Some(lp));
    }

    #[test]
    fn test_prepare_outbound_v6_ebgp_no_local_ipv6_does_not_rewrite() {
        let local_as = 65000_u32;
        let orig_nh: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6(orig_nh))
            .build();

        let out = prepare_outbound_v6(route, PeerType::External, local_as, local_as, None, false);

        // AS_PATH is still prepended; NEXT_HOP is left as-is.
        assert_eq!(out.as_path.path_length(), 1);
        assert_eq!(out.next_hop, Some(NextHop::V6(orig_nh)));
    }

    #[test]
    fn test_prepare_outbound_next_hop_self_rewrites_ibgp_next_hop() {
        let local_as = 65000_u32;
        let local_next_hop = Ipv4Addr::new(10, 0, 0, 2);
        let orig_nh = Ipv4Addr::new(192, 0, 2, 1);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(orig_nh))
            .build();

        let out = prepare_outbound(
            route,
            PeerType::Internal,
            local_as,
            local_as,
            local_next_hop,
            true,
        );

        assert_eq!(out.next_hop, Some(NextHop::V4(local_next_hop)));
        assert_eq!(out.as_path.path_length(), 0, "iBGP must not prepend AS");
    }

    #[test]
    fn test_prepare_outbound_next_hop_self_false_leaves_ibgp_unchanged() {
        let local_as = 65000_u32;
        let local_next_hop = Ipv4Addr::new(10, 0, 0, 2);
        let orig_nh = Ipv4Addr::new(192, 0, 2, 1);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(orig_nh))
            .build();

        let out = prepare_outbound(
            route,
            PeerType::Internal,
            local_as,
            local_as,
            local_next_hop,
            false,
        );

        assert_eq!(out.next_hop, Some(NextHop::V4(orig_nh)));
    }

    #[test]
    fn test_prepare_outbound_v6_next_hop_self_rewrites_ibgp_next_hop() {
        let local_as = 65000_u32;
        let local_v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let orig_nh: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6(orig_nh))
            .build();

        let out = prepare_outbound_v6(
            route,
            PeerType::Internal,
            local_as,
            local_as,
            Some(local_v6),
            true,
        );

        assert_eq!(out.next_hop, Some(NextHop::V6(local_v6)));
        assert_eq!(out.as_path.path_length(), 0, "iBGP must not prepend AS");
    }

    #[test]
    fn test_prepare_outbound_v6_next_hop_self_no_local_ipv6_no_rewrite() {
        let local_as = 65000_u32;
        let orig_nh: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6(orig_nh))
            .build();

        // next_hop_self=true but no local_ipv6 — cannot rewrite, route is unchanged
        let out = prepare_outbound_v6(route, PeerType::Internal, local_as, local_as, None, true);

        assert_eq!(out.next_hop, Some(NextHop::V6(orig_nh)));
    }

    // ── RFC 5065 §4.1(c): strip-then-prepend ordering for External peers ────

    #[test]
    fn test_external_strips_confed_before_prepending_public_as() {
        // A route that already carries a leading ConfedSequence (e.g.
        // relayed from a ConfedMember peer) must have that segment
        // stripped BEFORE `public_as` is prepended — otherwise the strip
        // (done later by AdjRibOut::insert) leaves two separate Sequence
        // segments instead of one canonically-merged one.
        use pathvector_types::AsPathSegment;
        let local_as = 65001_u32;
        let public_as = 64500_u32; // confederation identifier
        let local_next_hop = Ipv4Addr::new(10, 0, 0, 1);
        let path = AsPath::from_segments(vec![
            AsPathSegment::ConfedSequence(vec![pathvector_types::Asn::new(65100)]),
            AsPathSegment::Sequence(vec![pathvector_types::Asn::new(100)]),
        ]);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, path).build();

        let out = prepare_outbound(
            route,
            PeerType::External,
            local_as,
            public_as,
            local_next_hop,
            false,
        );

        // Exactly one Sequence segment: [public_as, 100] — not two separate
        // segments from prepending onto an un-stripped confed-leading path.
        assert_eq!(out.as_path.segments().len(), 1);
        match &out.as_path.segments()[0] {
            AsPathSegment::Sequence(asns) => {
                assert_eq!(
                    asns,
                    &[
                        pathvector_types::Asn::new(public_as),
                        pathvector_types::Asn::new(100)
                    ]
                );
            }
            other => panic!("expected a single merged Sequence segment, got {other:?}"),
        }
    }

    #[test]
    fn test_external_prepends_public_as_not_local_as() {
        // When a confederation is configured, External peers must see
        // `public_as` (the confederation identifier) prepended — not
        // `local_as` (the private Member-AS Number).
        let local_as = 65001_u32; // private Member-AS Number
        let public_as = 64500_u32; // confederation identifier
        let local_next_hop = Ipv4Addr::new(10, 0, 0, 1);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();

        let out = prepare_outbound(
            route,
            PeerType::External,
            local_as,
            public_as,
            local_next_hop,
            false,
        );

        assert_eq!(
            out.as_path.segments()[0].asns(),
            &[pathvector_types::Asn::new(public_as)]
        );
    }

    // ── RFC 5065 §4.1(b)/§5.1/§5.2: ConfedMember branch ──────────────────────

    #[test]
    fn test_confed_member_prepends_into_confed_sequence() {
        use pathvector_types::AsPathSegment;
        let local_as = 65001_u32;
        let public_as = 64500_u32;
        let local_next_hop = Ipv4Addr::new(10, 0, 0, 1);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();

        let out = prepare_outbound(
            route,
            PeerType::ConfedMember,
            local_as,
            public_as,
            local_next_hop,
            false,
        );

        assert_eq!(out.as_path.segments().len(), 1);
        assert!(matches!(
            out.as_path.segments()[0],
            AsPathSegment::ConfedSequence(_)
        ));
        assert_eq!(
            out.as_path.segments()[0].asns(),
            &[pathvector_types::Asn::new(local_as)]
        );
        // Confed segments don't count toward path length.
        assert_eq!(out.as_path.path_length(), 0);
    }

    #[test]
    fn test_confed_member_next_hop_unchanged_by_default() {
        // RFC 5065 §5.1: "by default it is unchanged" — unlike External,
        // ConfedMember must NOT get NEXT_HOP rewritten unless next_hop_self.
        let local_as = 65001_u32;
        let public_as = 64500_u32;
        let local_next_hop = Ipv4Addr::new(10, 0, 0, 1);
        let orig_nh = Ipv4Addr::new(192, 0, 2, 1);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(orig_nh))
            .build();

        let out = prepare_outbound(
            route,
            PeerType::ConfedMember,
            local_as,
            public_as,
            local_next_hop,
            false,
        );

        assert_eq!(out.next_hop, Some(NextHop::V4(orig_nh)));
    }

    #[test]
    fn test_confed_member_next_hop_self_rewrites() {
        let local_as = 65001_u32;
        let public_as = 64500_u32;
        let local_next_hop = Ipv4Addr::new(10, 0, 0, 1);
        let orig_nh = Ipv4Addr::new(192, 0, 2, 1);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(orig_nh))
            .build();

        let out = prepare_outbound(
            route,
            PeerType::ConfedMember,
            local_as,
            public_as,
            local_next_hop,
            true,
        );

        assert_eq!(out.next_hop, Some(NextHop::V4(local_next_hop)));
    }

    #[test]
    fn test_confed_member_local_pref_preserved() {
        // RFC 5065 §5.2: the eBGP-only LOCAL_PREF restriction is removed
        // for confederation-member peers.
        let local_as = 65001_u32;
        let public_as = 64500_u32;
        let local_next_hop = Ipv4Addr::new(10, 0, 0, 1);
        let lp = LocalPref::new(150);
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .local_pref(lp)
            .build();

        let out = prepare_outbound(
            route,
            PeerType::ConfedMember,
            local_as,
            public_as,
            local_next_hop,
            false,
        );

        assert_eq!(out.local_pref, Some(lp));
    }

    #[test]
    fn test_confed_member_v6_prepends_into_confed_sequence() {
        use pathvector_types::AsPathSegment;
        let local_as = 65001_u32;
        let public_as = 64500_u32;
        let local_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new()).build();

        let out = prepare_outbound_v6(
            route,
            PeerType::ConfedMember,
            local_as,
            public_as,
            Some(local_v6),
            false,
        );

        assert!(matches!(
            out.as_path.segments()[0],
            AsPathSegment::ConfedSequence(_)
        ));
        assert_eq!(out.as_path.path_length(), 0);
    }
}
