use super::*;

#[test]
fn test_rr_client_route_reflected_to_other_client() {
    let client_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let client_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_rr_state(65001, 1, &[client_a, client_b], &[]);

    state.on_established(
        IpAddr::V4(client_a),
        client_a,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(client_b),
        client_b,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    // Client A sends a route; it should be reflected to Client B
    state.on_route_update(IpAddr::V4(client_a), update_announce("192.0.2.0/24"));
    state.flush_pending();

    let msg = receivers
        .get_mut(&IpAddr::V4(client_b))
        .unwrap()
        .try_recv()
        .expect("route from client A must be reflected to client B");
    assert_eq!(msg.announced, vec![nlri("192.0.2.0/24")]);

    // Must NOT be sent back to Client A (split-horizon)
    assert!(
        receivers
            .get_mut(&IpAddr::V4(client_a))
            .unwrap()
            .try_recv()
            .is_err(),
        "route must not be reflected back to originating client"
    );
}

#[test]
fn test_rr_client_route_reflected_to_non_client_ibgp() {
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let nc: Ipv4Addr = "10.0.0.4".parse().unwrap();
    let (mut state, mut receivers) = make_rr_state(65001, 1, &[client], &[nc]);

    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(IpAddr::V4(nc), nc, PeerType::Internal, 65001, 90, &[], None);
    drain_all(&mut receivers);

    state.on_route_update(IpAddr::V4(client), update_announce("192.0.2.0/24"));
    state.flush_pending();

    let msg = receivers
        .get_mut(&IpAddr::V4(nc))
        .unwrap()
        .try_recv()
        .expect("route from client must be reflected to non-client iBGP");
    assert_eq!(msg.announced, vec![nlri("192.0.2.0/24")]);
}

#[test]
fn test_rr_non_client_ibgp_route_reflected_to_client() {
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let nc: Ipv4Addr = "10.0.0.4".parse().unwrap();
    let (mut state, mut receivers) = make_rr_state(65001, 1, &[client], &[nc]);

    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(IpAddr::V4(nc), nc, PeerType::Internal, 65001, 90, &[], None);
    drain_all(&mut receivers);

    // Non-client iBGP sends a route; it should be reflected to the client
    state.on_route_update(IpAddr::V4(nc), update_announce("192.0.2.0/24"));
    state.flush_pending();

    let msg = receivers
        .get_mut(&IpAddr::V4(client))
        .unwrap()
        .try_recv()
        .expect("route from non-client iBGP must be reflected to client");
    assert_eq!(msg.announced, vec![nlri("192.0.2.0/24")]);
}

#[test]
fn test_rr_non_client_ibgp_to_non_client_ibgp_still_blocked() {
    let nc1: Ipv4Addr = "10.0.0.4".parse().unwrap();
    let nc2: Ipv4Addr = "10.0.0.5".parse().unwrap();
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let (mut state, mut receivers) = make_rr_state(65001, 1, &[client], &[nc1, nc2]);

    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(nc1),
        nc1,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(nc2),
        nc2,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    // Non-client nc1 sends a route; nc2 must NOT receive it
    state.on_route_update(IpAddr::V4(nc1), update_announce("192.0.2.0/24"));
    state.flush_pending();

    assert!(
        receivers
            .get_mut(&IpAddr::V4(nc2))
            .unwrap()
            .try_recv()
            .is_err(),
        "non-client iBGP routes must not be re-advertised to other non-client iBGP peers"
    );
    // But client should receive it
    receivers
        .get_mut(&IpAddr::V4(client))
        .unwrap()
        .try_recv()
        .expect("non-client iBGP route must be reflected to client");
}

#[test]
fn test_rr_loop_detection_discards_update() {
    let cluster_id: u32 = 42;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let other: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client, other], &[]);

    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(other),
        other,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    // UPDATE from client containing our own cluster_id in CLUSTER_LIST
    let looped = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::new()),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 1, 1)),
            PathAttribute::ClusterList(vec![cluster_id]),
        ],
        announced: vec![nlri("192.0.2.0/24")],
    };
    state.on_route_update(IpAddr::V4(client), looped);

    // Route must NOT be installed or propagated
    assert_eq!(state.rib.loc_rib.len(), 0, "looped route must be discarded");
    assert!(
        receivers
            .get_mut(&IpAddr::V4(other))
            .unwrap()
            .try_recv()
            .is_err(),
        "looped route must not be propagated"
    );
}

#[test]
fn test_rr_originator_id_and_cluster_list_set_on_reflected_route() {
    let cluster_id: u32 = 99;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let other: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client, other], &[]);

    // Simulate OPEN: client's BGP ID is 10.0.0.2
    Arc::make_mut(&mut state.rib)
        .peer_bgp_ids
        .insert(IpAddr::V4(client), client);

    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(other),
        other,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    state.on_route_update(IpAddr::V4(client), update_announce("192.0.2.0/24"));
    state.flush_pending();

    let msg = receivers
        .get_mut(&IpAddr::V4(other))
        .unwrap()
        .try_recv()
        .expect("reflected UPDATE expected");

    let has_originator = msg
        .attributes
        .iter()
        .any(|a| matches!(a, PathAttribute::OriginatorId(id) if *id == client));
    assert!(
        has_originator,
        "reflected route must carry ORIGINATOR_ID = client BGP ID"
    );

    let has_cluster = msg
        .attributes
        .iter()
        .any(|a| matches!(a, PathAttribute::ClusterList(list) if list.contains(&cluster_id)));
    assert!(
        has_cluster,
        "reflected route must carry cluster_id in CLUSTER_LIST"
    );
}

/// Regression test for the RFC 4271 §9.1.2.2 (f) best-path fix: proves
/// the peer's BGP Identifier (learned at `Established`, tracked in
/// `rib.peer_bgp_ids`) is actually threaded onto the `Route` built by a
/// real `on_route_update` call. `best_path::prefer()`'s own unit tests
/// construct `Route`s directly via `RouteBuilder::peer_bgp_id(...)` and
/// would keep passing even if this daemon-level wiring were missing
/// entirely — this test is what actually proves the two are connected.
#[test]
fn test_route_carries_peer_bgp_id_from_established_session() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let peer_bgp_id = Ipv4Addr::new(9, 9, 9, 9);
    let (mut state, _receivers) = make_state(65001, &[(peer_ip, 65002)]);

    state.on_established(
        peer_ip,
        peer_bgp_id,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    state.on_route_update(peer_ip, update_announce("192.0.2.0/24"));

    let route = state
        .rib
        .loc_rib
        .best(&nlri("192.0.2.0/24"))
        .expect("route must be installed");
    assert_eq!(
        route.peer_bgp_id,
        Some(peer_bgp_id),
        "Route::peer_bgp_id must be populated from rib.peer_bgp_ids at \
         ingest time, so RFC 4271 §9.1.2.2 step (f) has real data to compare"
    );
}

// RFC 4456 §8: discard when ORIGINATOR_ID == local BGP ID.
#[test]
fn test_rr_originator_id_loop_detection_discards_update() {
    let cluster_id: u32 = 7;
    let local_bgp_id: Ipv4Addr = "1.2.3.4".parse().unwrap();
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let other: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client, other], &[]);
    Arc::make_mut(&mut state.rib).local_bgp_id = local_bgp_id;

    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(other),
        other,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    // UPDATE carries ORIGINATOR_ID equal to our own BGP ID — routing loop.
    let looped = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::new()),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 1, 1)),
            PathAttribute::OriginatorId(local_bgp_id),
        ],
        announced: vec![nlri("192.0.3.0/24")],
    };
    state.on_route_update(IpAddr::V4(client), looped);

    assert_eq!(
        state.rib.loc_rib.len(),
        0,
        "route with ORIGINATOR_ID == local BGP ID must be discarded (RFC 4456 §8)"
    );
    assert!(
        receivers
            .get_mut(&IpAddr::V4(other))
            .unwrap()
            .try_recv()
            .is_err(),
        "looped route must not be propagated to other peers"
    );
}

// RFC 4456 §8: CLUSTER_LIST loop detection applies to non-client iBGP peers too.
#[test]
fn test_rr_cluster_list_loop_detection_applies_to_non_client_ibgp() {
    let cluster_id: u32 = 55;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let non_client: Ipv4Addr = "10.0.0.10".parse().unwrap();
    // non_client is iBGP but not in the rr_clients set
    let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client], &[non_client]);

    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(non_client),
        non_client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    // UPDATE from the non-client iBGP peer, already carrying our cluster_id.
    let looped = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::new()),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 1, 1)),
            PathAttribute::ClusterList(vec![cluster_id]),
        ],
        announced: vec![nlri("10.99.0.0/24")],
    };
    state.on_route_update(IpAddr::V4(non_client), looped);

    assert_eq!(
        state.rib.loc_rib.len(),
        0,
        "CLUSTER_LIST loop detection must apply to non-client iBGP peers (RFC 4456 §8)"
    );
    assert!(
        receivers
            .get_mut(&IpAddr::V4(client))
            .unwrap()
            .try_recv()
            .is_err(),
        "looped route from non-client must not be reflected to client"
    );
}

// RFC 4456 §8: non-client iBGP → client reflection injects correct attributes.
#[test]
fn test_rr_non_client_ibgp_to_client_injects_rr_attrs() {
    let cluster_id: u32 = 11;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let non_client: Ipv4Addr = "10.0.0.10".parse().unwrap();
    let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client], &[non_client]);

    Arc::make_mut(&mut state.rib)
        .peer_bgp_ids
        .insert(IpAddr::V4(non_client), non_client);

    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(non_client),
        non_client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    state.on_route_update(IpAddr::V4(non_client), update_announce("172.16.0.0/24"));
    state.flush_pending();

    let msg = receivers
        .get_mut(&IpAddr::V4(client))
        .unwrap()
        .try_recv()
        .expect("reflected UPDATE expected from non-client → client");

    let has_originator = msg
        .attributes
        .iter()
        .any(|a| matches!(a, PathAttribute::OriginatorId(id) if *id == non_client));
    assert!(
        has_originator,
        "ORIGINATOR_ID must be set when reflecting non-client iBGP route to client"
    );
    let has_cluster = msg
        .attributes
        .iter()
        .any(|a| matches!(a, PathAttribute::ClusterList(list) if list.contains(&cluster_id)));
    assert!(
        has_cluster,
        "CLUSTER_LIST must contain cluster_id when reflecting non-client iBGP route to client"
    );
}

// ── RFC 4456 §8 IPv6 route paths ─────────────────────────────────────────

fn nlri_v6_rr(s: &str) -> Nlri<Ipv6Addr> {
    s.parse().unwrap()
}

fn route_v6_ibgp(prefix: &str) -> Route<Ipv6Addr> {
    use pathvector_types::{AsPath, Origin};
    RouteBuilder::new(nlri_v6_rr(prefix), Origin::Igp, AsPath::new())
        .peer_type(PeerType::Internal)
        .build()
}

// Inject a v6 route from `src_peer` into loc_rib_v6 and mark `src_peer` as
// the iBGP source so split-horizon has a peer to look up.
fn inject_v6_route(state: &mut DaemonState, src_peer: Ipv4Addr, prefix: &str) {
    let peer_id = PeerId::new(IpAddr::V4(src_peer));
    let mut route = route_v6_ibgp(prefix);
    // As on ingest: reflecting it needs the source's BGP Identifier.
    route.peer_bgp_id = Some(src_peer);
    state.rib_insert_v6(peer_id, route);
    Arc::make_mut(&mut state.rib)
        .peer_types
        .insert(IpAddr::V4(src_peer), PeerType::Internal);
}

// RFC 4456 §8: adj_ribs_out_v6 must use new_reflecting for all iBGP peers
// when the daemon acts as an RR (set during add_peer, not just at startup).
#[test]
fn test_rr_v6_adj_rib_out_is_reflecting_for_ibgp_peer() {
    let cluster_id: u32 = 5;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let non_client: Ipv4Addr = "10.0.0.10".parse().unwrap();
    let (state, _receivers) = make_rr_state(65001, cluster_id, &[client], &[non_client]);

    let client_aro_v6 = state.adj_ribs_out_v6.get(&IpAddr::V4(client)).unwrap();
    assert!(
        client_aro_v6.reflects(),
        "adj_ribs_out_v6 for RR client must use reflecting mode"
    );
    let nc_aro_v6 = state.adj_ribs_out_v6.get(&IpAddr::V4(non_client)).unwrap();
    assert!(
        nc_aro_v6.reflects(),
        "adj_ribs_out_v6 for non-client iBGP peer must use reflecting mode when acting as RR"
    );
}

// RFC 4456 §8: adj_ribs_out_v6 is reset to new_reflecting on reconnect.
#[test]
fn test_rr_v6_adj_rib_out_reflecting_restored_after_reconnect() {
    let cluster_id: u32 = 5;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let (mut state, _receivers) = make_rr_state(65001, cluster_id, &[client], &[]);

    // Simulate a session teardown and re-establish.
    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    let aro_v6 = state.adj_ribs_out_v6.get(&IpAddr::V4(client)).unwrap();
    assert!(
        aro_v6.reflects(),
        "adj_ribs_out_v6 must be reflecting after reconnect when acting as RR"
    );
}

// RFC 4456 §8: propagate_to_all_peers_v6 must block non-client → non-client.
#[test]
fn test_rr_v6_split_horizon_blocks_non_client_to_non_client() {
    let cluster_id: u32 = 3;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let nc1: Ipv4Addr = "10.0.0.10".parse().unwrap();
    let nc2: Ipv4Addr = "10.0.0.11".parse().unwrap();
    let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client], &[nc1, nc2]);

    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(nc1),
        nc1,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(nc2),
        nc2,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    // Mark nc1 and nc2 as IPv6-capable so propagate_to_all_peers_v6 includes them.
    state.ipv6_capable_peers.insert(IpAddr::V4(nc1));
    state.ipv6_capable_peers.insert(IpAddr::V4(nc2));
    state.ipv6_capable_peers.insert(IpAddr::V4(client));

    // Inject a v6 route sourced from nc1 (non-client iBGP).
    inject_v6_route(&mut state, nc1, "2001:db8::/32");
    state.propagate_to_all_peers_v6(&[nlri_v6_rr("2001:db8::/32")]);
    state.flush_pending();

    // nc2 (non-client iBGP) must NOT receive the route.
    assert!(
        receivers
            .get_mut(&IpAddr::V4(nc2))
            .unwrap()
            .try_recv()
            .is_err(),
        "non-client iBGP → non-client iBGP must be blocked for IPv6 routes (RFC 4456 §8)"
    );
    // client MUST receive the route.
    assert!(
        receivers
            .get_mut(&IpAddr::V4(client))
            .unwrap()
            .try_recv()
            .is_ok(),
        "non-client iBGP → client must be allowed for IPv6 routes (RFC 4456 §8)"
    );
}

// Regression test: propagate_to_all_peers_v6 must sync prefixes_advertised
// itself. Before the fix, only propagate_to_all_peers (v4) called
// sync_advertised, so a v6-only propagation event (no preceding or
// following v4 call) left prefixes_advertised with no entry at all for
// the receiving peer, even though the route was correctly queued for
// the wire in adj_ribs_out_v6.
#[test]
fn test_v6_only_propagation_syncs_prefixes_advertised() {
    // Both peers are eBGP (distinct remote AS from local_as and from each
    // other) so the scenario can't be confused with iBGP full-mesh
    // split-horizon, which would otherwise block source → dest here
    // regardless of this test's fix.
    let cluster_id: u32 = 9;
    let source: Ipv4Addr = "10.0.0.20".parse().unwrap();
    let dest: Ipv4Addr = "10.0.0.21".parse().unwrap();
    let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[], &[source, dest]);

    state.on_established(
        IpAddr::V4(source),
        source,
        PeerType::External,
        65099,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(dest),
        dest,
        PeerType::External,
        65098,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    state.ipv6_capable_peers.insert(IpAddr::V4(source));
    state.ipv6_capable_peers.insert(IpAddr::V4(dest));
    // eBGP peers need a local IPv6 next-hop to announce to (propagate_prefix_v6
    // silently suppresses eBGP announcements without one — see its doc comment).
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

    assert_eq!(
        state.rib.prefixes_advertised.get(&IpAddr::V4(dest)),
        Some(&0),
        "sanity check: prefixes_advertised must start at 0 for dest \
         (set by on_established's own sync, before the v6 route exists)"
    );

    // Inject a v6 route sourced from `source` and propagate it — no v4
    // call before or after, matching the on_route_update code path when
    // an UPDATE carries only IPv6 NLRIs (affected_v6 non-empty, affected
    // empty).
    let peer_id = PeerId::new(IpAddr::V4(source));
    let route = RouteBuilder::new(
        nlri_v6_rr("2001:db8::/32"),
        pathvector_types::Origin::Igp,
        pathvector_types::AsPath::new(),
    )
    .peer_type(PeerType::External)
    .build();
    state.rib_insert_v6(peer_id, route);
    state.propagate_to_all_peers_v6(&[nlri_v6_rr("2001:db8::/32")]);

    assert_eq!(
        state.rib.prefixes_advertised.get(&IpAddr::V4(dest)),
        Some(&1),
        "prefixes_advertised for dest must reflect the queued v6 route \
         immediately after a v6-only propagate_to_all_peers_v6 call, \
         without needing a separate v4 event to resync it"
    );
}

// RFC 4456 §8: on_established full-table dump must apply split-horizon for v6.
#[test]
fn test_rr_v6_established_dump_applies_split_horizon() {
    let cluster_id: u32 = 3;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let nc1: Ipv4Addr = "10.0.0.10".parse().unwrap();
    let nc2: Ipv4Addr = "10.0.0.11".parse().unwrap();
    let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client], &[nc1, nc2]);

    // nc1 connects and we add a v6 route sourced from nc1.
    state.on_established(
        IpAddr::V4(nc1),
        nc1,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    inject_v6_route(&mut state, nc1, "2001:db8:1::/48");

    // nc2 now connects — full-table dump should NOT send the nc1 route to nc2.
    // Pass MultiProtocol IPv6 capability so the v6 dump fires.
    let caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
    state.on_established(
        IpAddr::V4(nc2),
        nc2,
        PeerType::Internal,
        65001,
        90,
        &caps,
        None,
    );

    // on_established sends an IPv4 EOR (empty UpdateMessage) and for v6-capable
    // peers an IPv6 EOR (UpdateMessage with empty MP_UNREACH_NLRI, RFC 4724 §2).
    // Drain both EOR markers, then verify no actual route UPDATE arrived.
    // A route UPDATE would carry non-empty `announced` or non-empty prefixes in
    // MP_REACH_NLRI; a pure EOR has only empty MP_UNREACH_NLRI (or nothing).
    let rx = receivers.get_mut(&IpAddr::V4(nc2)).unwrap();
    let mut route_received = false;
    while let Ok(m) = rx.try_recv() {
        let has_announced_nlri = !m.announced.is_empty();
        let has_mp_reach = m
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::MpReachNlri(mp) if !mp.prefixes.is_empty()));
        if has_announced_nlri || has_mp_reach {
            route_received = true;
        }
    }
    assert!(
        !route_received,
        "v6 full-table dump must not send non-client iBGP routes to another non-client (RFC 4456 §8)"
    );
}

// ── Invariant: adj_ribs_out and adj_ribs_out_v6 always agree on reflects() ─

/// Asserts the RFC 4456 reflecting-parity invariant for every peer in `state`:
/// `adj_ribs_out[p].reflects() == adj_ribs_out_v6[p].reflects()`.
///
/// Call this after any operation that creates or resets outbound RIBs.
fn assert_reflects_parity(state: &DaemonState) {
    for (peer_ip, aro_v4) in &state.adj_ribs_out {
        if let Some(aro_v6) = state.adj_ribs_out_v6.get(peer_ip) {
            assert_eq!(
                aro_v4.reflects(),
                aro_v6.reflects(),
                "peer {peer_ip}: adj_ribs_out.reflects()={} but adj_ribs_out_v6.reflects()={} — \
                 IPv4 and IPv6 outbound tables must always have matching reflecting mode (RFC 4456 §8)",
                aro_v4.reflects(),
                aro_v6.reflects(),
            );
        }
    }
}

#[test]
fn invariant_reflects_parity_after_new() {
    let cluster_id = 1;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let nc: Ipv4Addr = "10.0.0.10".parse().unwrap();
    let (state, _) = make_rr_state(65001, cluster_id, &[client], &[nc]);
    assert_reflects_parity(&state);
}

#[test]
fn invariant_reflects_parity_after_on_established() {
    let cluster_id = 1;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let nc: Ipv4Addr = "10.0.0.10".parse().unwrap();
    let (mut state, _) = make_rr_state(65001, cluster_id, &[client], &[nc]);
    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    assert_reflects_parity(&state);
    state.on_established(IpAddr::V4(nc), nc, PeerType::Internal, 65001, 90, &[], None);
    assert_reflects_parity(&state);
}

#[test]
fn invariant_reflects_parity_after_peer_down_and_reconnect() {
    let cluster_id = 1;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_rr_state(65001, cluster_id, &[client], &[]);
    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    assert_reflects_parity(&state);
    // Simulate teardown then re-establish (on_terminated resets AdjRibOut)
    state.on_terminated(IpAddr::V4(client), TerminationReason::Unclean, false);
    // on_established rebuilds the tables for the next session
    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    assert_reflects_parity(&state);
}

#[test]
fn invariant_reflects_parity_after_add_peer() {
    let cluster_id = 1;
    let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_rr_state(65001, cluster_id, &[client], &[]);
    // Dynamically add a new iBGP peer (same AS = iBGP)
    let new_peer = config::PeerConfig {
        address: "10.0.0.99".parse().unwrap(),
        port: 179,
        remote_as: 65001,
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Accept),
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    };
    let (tx, _rx) = mpsc::channel(64);
    state.add_peer(&new_peer, tx);
    assert_reflects_parity(&state);
}
