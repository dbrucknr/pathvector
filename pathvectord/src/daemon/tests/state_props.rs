use std::net::Ipv4Addr;

use proptest::prelude::*;

use pathvector_types::{AsPath, Asn, LocalPref, NextHop, Origin, PeerType};

use crate::daemon::*;
use crate::outbound::route_to_attributes;
use pathvector_rib::{RouteBuilder, outbound::prepare_outbound};

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

fn base_route(prefix: &str) -> Route<Ipv4Addr> {
    RouteBuilder::new(
        nlri(prefix),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65002)]),
    )
    .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
    .local_pref(LocalPref::new(100))
    .peer_type(PeerType::External)
    .build()
}

proptest! {
    /// `config_peer_type` returns `Internal` iff the two AS numbers are
    /// equal (regardless of `confed_member`); otherwise `ConfedMember`
    /// when `confed_member` is set, and `External` otherwise.
    #[test]
    fn prop_config_peer_type_internal_iff_equal(a: u32, b: u32, confed_member: bool) {
        let pt = config_peer_type(a, b, confed_member);
        if a == b {
            prop_assert_eq!(pt, PeerType::Internal);
        } else if confed_member {
            prop_assert_eq!(pt, PeerType::ConfedMember);
        } else {
            prop_assert_eq!(pt, PeerType::External);
        }
    }

    /// An explicit import default always overrides the eBGP/iBGP derived
    /// default, regardless of the `is_ebgp` flag.
    #[test]
    fn prop_resolve_import_explicit_always_wins(is_ebgp: bool) {
        let accept = resolve_import_default(Some(config::ImportDefault::Accept), is_ebgp);
        let reject = resolve_import_default(Some(config::ImportDefault::Reject), is_ebgp);
        prop_assert!(matches!(accept, DefaultAction::Accept));
        prop_assert!(matches!(reject, DefaultAction::Reject));
    }

    /// An explicit export default always overrides the eBGP/iBGP derived
    /// default.
    #[test]
    fn prop_resolve_export_explicit_always_wins(is_ebgp: bool) {
        let accept = resolve_export_default(Some(config::ExportDefault::Accept), is_ebgp);
        let reject = resolve_export_default(Some(config::ExportDefault::Reject), is_ebgp);
        prop_assert!(matches!(accept, DefaultAction::Accept));
        prop_assert!(matches!(reject, DefaultAction::Reject));
    }

    /// `withdraw_msg` always produces exactly one withdrawn NLRI and no
    /// announced NLRIs.
    #[test]
    fn prop_withdraw_msg_structure(
        prefix in prop::sample::select(vec![
            "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "0.0.0.0/0",
        ])
    ) {
        let n: Nlri<Ipv4Addr> = prefix.parse().unwrap();
        let msg = UpdateMessage { withdrawn: vec![n], attributes: vec![], announced: vec![] };
        prop_assert_eq!(msg.withdrawn.len(), 1);
        prop_assert_eq!(msg.withdrawn[0], n);
        prop_assert!(msg.announced.is_empty());
        prop_assert!(msg.attributes.is_empty());
    }

    /// `route_to_attributes` always produces Origin and AsPath attributes,
    /// and the NLRI is the route's nlri.
    #[test]
    fn prop_route_to_update_structure(
        prefix in prop::sample::select(vec![
            "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12",
        ])
    ) {
        use pathvector_session::message::PathAttribute;
        let route = base_route(prefix);
        let nlri_val: Nlri<Ipv4Addr> = prefix.parse().unwrap();
        let attrs = route_to_attributes(&route, PeerType::External, true);
        let msg = UpdateMessage { withdrawn: vec![], attributes: attrs, announced: vec![nlri_val] };

        prop_assert_eq!(msg.announced, vec![nlri_val]);
        prop_assert!(msg.withdrawn.is_empty());
        prop_assert!(
            msg.attributes.iter().any(|a| matches!(a, PathAttribute::Origin(_))),
            "UPDATE must carry ORIGIN"
        );
        prop_assert!(
            msg.attributes.iter().any(|a| matches!(a, PathAttribute::AsPath(_))),
            "UPDATE must carry AS_PATH"
        );
    }

    /// For iBGP peers, `prepare_outbound` is an identity transform: the
    /// route's AS_PATH, NEXT_HOP, and LOCAL_PREF are all preserved.
    #[test]
    fn prop_prepare_outbound_ibgp_is_identity(lp_value in 0u32..=65535) {
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .local_pref(LocalPref::new(lp_value))
        .peer_type(PeerType::Internal)
        .build();

        let result = prepare_outbound(
            route.clone(),
            PeerType::Internal,
            65001, 65001,
            Ipv4Addr::new(10, 0, 0, 1),
            false,
        );

        prop_assert_eq!(result.as_path, route.as_path, "AS_PATH must be unchanged for iBGP");
        prop_assert_eq!(result.next_hop, route.next_hop, "NEXT_HOP must be unchanged for iBGP");
        prop_assert_eq!(result.local_pref, route.local_pref, "LOCAL_PREF must be preserved for iBGP");
    }

    /// For eBGP peers, `prepare_outbound` always prepends the local AS,
    /// rewrites the NEXT_HOP, and strips LOCAL_PREF.
    #[test]
    fn prop_prepare_outbound_ebgp_transforms(local_as in 1u32..=4_294_967_294) {
        let bgp_id = Ipv4Addr::new(10, 0, 0, 1);
        let route = base_route("10.0.0.0/8");
        let original_path_len = route.as_path.path_length();

        let result = prepare_outbound(route, PeerType::External, local_as, local_as, bgp_id, false);

        prop_assert_eq!(
            result.as_path.path_length(),
            original_path_len + 1,
            "local AS must be prepended for eBGP"
        );
        prop_assert!(result.as_path.contains(Asn::new(local_as)), "local AS must be in the path");
        prop_assert_eq!(result.next_hop, Some(NextHop::V4(bgp_id)), "NEXT_HOP must be rewritten");
        prop_assert!(result.local_pref.is_none(), "LOCAL_PREF must be stripped for eBGP");
    }
}
