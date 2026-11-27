use super::*;

// Finding C — RFC 4271 §5.1.3 / §9.1.2: NEXT_HOP validation.
// Routes with invalid next-hops (unspecified, loopback, multicast, broadcast)
// must be dropped.

#[test]
fn test_invalid_next_hop_unspecified_is_rejected() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::NextHop(Ipv4Addr::UNSPECIFIED), // 0.0.0.0
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert!(
        rib.is_empty(),
        "route with 0.0.0.0 NEXT_HOP must be rejected (RFC 4271 §5.1.3)"
    );
}

#[test]
fn test_invalid_next_hop_multicast_is_rejected() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::NextHop(Ipv4Addr::new(224, 0, 0, 1)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert!(
        rib.is_empty(),
        "route with multicast NEXT_HOP must be rejected (RFC 4271 §5.1.3)"
    );
}

#[test]
fn test_invalid_next_hop_broadcast_is_rejected() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::NextHop(Ipv4Addr::BROADCAST),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert!(
        rib.is_empty(),
        "route with broadcast NEXT_HOP must be rejected (RFC 4271 §5.1.3)"
    );
}

#[test]
fn test_invalid_next_hop_v6_unspecified_is_rejected() {
    let mut ari = fresh_ari();
    let mut rib = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6(Ipv6Addr::UNSPECIFIED), // ::
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                }),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &accept_all_v6(),
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );
    assert!(
        rib_v6.is_empty(),
        "IPv6 route with :: NEXT_HOP must be rejected (RFC 4271 §5.1.3)"
    );
}

#[test]
fn test_invalid_next_hop_v6_multicast_is_rejected() {
    let mut ari = fresh_ari();
    let mut rib = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("ff02::1".parse().unwrap()), // multicast
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                }),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &accept_all_v6(),
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );
    assert!(
        rib_v6.is_empty(),
        "IPv6 route with multicast NEXT_HOP must be rejected (RFC 4271 §5.1.3)"
    );
}

#[test]
fn test_valid_next_hop_is_accepted() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert_eq!(rib.len(), 1, "route with valid NEXT_HOP must be accepted");
}

#[test]
fn test_valid_next_hop_v6_link_local_is_accepted() {
    // Link-local (fe80::/10) is a valid next-hop in single-hop eBGP sessions
    // (GoBGP, BIRD both use it). Must not be rejected.
    let mut ari = fresh_ari();
    let mut rib = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("fe80::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                }),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &accept_all_v6(),
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );
    assert_eq!(
        rib_v6.len(),
        1,
        "link-local IPv6 next-hop must be accepted (used by GoBGP/BIRD)"
    );
}

#[test]
fn test_invalid_next_hop_v6_with_link_local_bad_global_rejected() {
    // V6WithLinkLocal: if the global address is :: (unspecified), drop.
    let mut ari = fresh_ari();
    let mut rib = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6WithLinkLocal {
                        global: Ipv6Addr::UNSPECIFIED, // ::
                        link_local: "fe80::1".parse().unwrap(),
                    },
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                }),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &accept_all_v6(),
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );
    assert!(
        rib_v6.is_empty(),
        "V6WithLinkLocal with unspecified global must be rejected"
    );
}

#[test]
fn test_invalid_next_hop_v6_with_link_local_multicast_link_local_rejected() {
    // V6WithLinkLocal: if the link-local field is multicast, drop.
    let mut ari = fresh_ari();
    let mut rib = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6WithLinkLocal {
                        global: "2001:db8::1".parse().unwrap(),
                        link_local: "ff02::1".parse().unwrap(), // multicast
                    },
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                }),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &accept_all_v6(),
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );
    assert!(
        rib_v6.is_empty(),
        "V6WithLinkLocal with multicast link-local must be rejected (RFC 2545 §3)"
    );
}

// Finding C-remaining — RFC 4271 §5.1.3: NEXT_HOP must not equal the
// receiving router's own address.

#[test]
fn test_next_hop_own_address_is_rejected() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    let own_addr: Ipv4Addr = "192.0.2.1".parse().unwrap();
    let mut ari_v6: AdjRibIn<Ipv6Addr> = AdjRibIn::new(peer());
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Accept);
    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::NextHop(own_addr),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &policy_v6,
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None,           // confederation_id
        Some(own_addr), // local interface address matches NEXT_HOP
        None,
    );
    assert!(
        rib.is_empty(),
        "route with NEXT_HOP == own address must be rejected (RFC 4271 §5.1.3)"
    );
}

#[test]
fn test_next_hop_different_from_own_address_is_accepted() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    let own_addr: Ipv4Addr = "192.0.2.1".parse().unwrap();
    let peer_addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let mut ari_v6: AdjRibIn<Ipv6Addr> = AdjRibIn::new(peer());
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Accept);
    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::NextHop(peer_addr),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &policy_v6,
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None,           // confederation_id
        Some(own_addr), // NEXT_HOP differs from own address — valid
        None,
    );
    assert_eq!(
        rib.len(),
        1,
        "route with NEXT_HOP != own address must be accepted"
    );
}
