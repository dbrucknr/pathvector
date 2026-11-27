use super::*;

#[test]
fn test_prepare_outbound_ebgp_prepends_local_as() {
    let route = ebgp_route_with_lp("10.0.0.0/8");
    let out = prepare_outbound(route, PeerType::External, 65001, 65001, bgp_id(), false);
    assert_eq!(out.as_path.path_length(), 2);
    assert!(out.as_path.contains(Asn::new(65001)));
    assert!(out.as_path.contains(Asn::new(65002)));
}

#[test]
fn test_prepare_outbound_ebgp_rewrites_next_hop() {
    let route = ebgp_route_with_lp("10.0.0.0/8");
    let out = prepare_outbound(route, PeerType::External, 65001, 65001, bgp_id(), false);
    assert_eq!(out.next_hop, Some(NextHop::V4(bgp_id())));
}

#[test]
fn test_prepare_outbound_ebgp_strips_local_pref() {
    let route = ebgp_route_with_lp("10.0.0.0/8");
    let out = prepare_outbound(route, PeerType::External, 65001, 65001, bgp_id(), false);
    assert!(
        out.local_pref.is_none(),
        "LOCAL_PREF must be stripped for eBGP"
    );
}

#[test]
fn test_prepare_outbound_ibgp_preserves_attributes() {
    let route = ibgp_route("10.0.0.0/8");
    let out = prepare_outbound(
        route.clone(),
        PeerType::Internal,
        65001,
        65001,
        bgp_id(),
        false,
    );
    assert_eq!(out.as_path.path_length(), route.as_path.path_length());
    assert_eq!(out.local_pref, route.local_pref);
    assert_eq!(out.next_hop, route.next_hop);
}

// ── route_to_attributes ───────────────────────────────────────────────────

fn route_to_update_for_test(route: &Route<Ipv4Addr>) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: route_to_attributes(route, PeerType::External, true),
        announced: vec![route.nlri],
    }
}

#[test]
fn test_route_to_update_contains_mandatory_attributes() {
    let route = RouteBuilder::new(
        nlri("10.0.0.0/8"),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65001)]),
    )
    .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
    .build();

    let msg = route_to_update_for_test(&route);
    assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
    assert!(msg.withdrawn.is_empty());
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Origin(_)))
    );
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::AsPath(_)))
    );
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::NextHop(_)))
    );
}

#[test]
fn test_route_to_update_omits_absent_optional_attributes() {
    let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();
    let msg = route_to_update_for_test(&route);
    assert!(
        !msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(_)))
    );
    assert!(
        !msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Med(_)))
    );
}

#[test]
fn test_route_to_update_includes_all_optional_attributes() {
    let route = RouteBuilder::new(
        nlri("10.0.0.0/8"),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65001)]),
    )
    .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
    .local_pref(LP::new(150))
    .med(Med::new(100))
    .community(Community::new(0xFFFF_FF01))
    .large_community(LargeCommunity::new(65001, 1, 1))
    .extended_community(ExtendedCommunity::route_target_as2(65001, 1))
    .atomic_aggregate()
    .aggregator(Aggregator::new(Asn::new(65001), Ipv4Addr::new(1, 1, 1, 1)))
    .build();

    // Use Internal peer type so MED and reflector attributes are not stripped.
    let msg = UpdateMessage {
        withdrawn: vec![],
        attributes: route_to_attributes(&route, PeerType::Internal, true),
        announced: vec![route.nlri],
    };
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(_)))
    );
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Med(_)))
    );
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Communities(_)))
    );
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LargeCommunities(_)))
    );
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::ExtendedCommunities(_)))
    );
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::AtomicAggregate))
    );
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Aggregator(_)))
    );
}

// Finding F (RFC 4456 §8) and G (RFC 4271 §5.1.4) — eBGP attribute stripping.
// ORIGINATOR_ID, CLUSTER_LIST, and MED MUST be stripped before advertising to eBGP peers.

#[test]
fn test_route_to_attributes_ebgp_strips_med() {
    let route = RouteBuilder::new(
        nlri("10.0.0.0/8"),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65001)]),
    )
    .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
    .med(Med::new(100))
    .build();

    let attrs = route_to_attributes(&route, PeerType::External, true);
    assert!(
        !attrs.iter().any(|a| matches!(a, PathAttribute::Med(_))),
        "MED must be stripped for eBGP peers (RFC 4271 §5.1.4)"
    );
}

#[test]
fn test_route_to_attributes_ibgp_preserves_med() {
    let route = RouteBuilder::new(
        nlri("10.0.0.0/8"),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65001)]),
    )
    .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
    .med(Med::new(100))
    .build();

    let attrs = route_to_attributes(&route, PeerType::Internal, true);
    assert!(
        attrs.iter().any(|a| matches!(a, PathAttribute::Med(_))),
        "MED must be preserved for iBGP peers"
    );
}

#[test]
fn test_route_to_attributes_ebgp_strips_originator_id_and_cluster_list() {
    let mut route = RouteBuilder::new(
        nlri("10.0.0.0/8"),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65001)]),
    )
    .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
    .build();
    route.rare_mut().originator_id = Some("1.1.1.1".parse::<Ipv4Addr>().unwrap());
    route.rare_mut().cluster_list = vec![0x0101_0101u32];

    let attrs = route_to_attributes(&route, PeerType::External, true);
    assert!(
        !attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::OriginatorId(_))),
        "ORIGINATOR_ID must be stripped for eBGP peers (RFC 4456 §8)"
    );
    assert!(
        !attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::ClusterList(_))),
        "CLUSTER_LIST must be stripped for eBGP peers (RFC 4456 §8)"
    );
}

#[test]
fn test_route_to_attributes_ibgp_preserves_rr_attributes() {
    let mut route = RouteBuilder::new(
        nlri("10.0.0.0/8"),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65001)]),
    )
    .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
    .build();
    route.rare_mut().originator_id = Some("1.1.1.1".parse::<Ipv4Addr>().unwrap());
    route.rare_mut().cluster_list = vec![0x0101_0101u32];

    let attrs = route_to_attributes(&route, PeerType::Internal, true);
    assert!(
        attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::OriginatorId(_))),
        "ORIGINATOR_ID must be preserved for iBGP peers"
    );
    assert!(
        attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::ClusterList(_))),
        "CLUSTER_LIST must be preserved for iBGP peers"
    );
}
