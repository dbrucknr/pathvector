use super::*;

// ── pathvectord_bgp_import_policy_rejected_total (Gap 3) ─────────────────

fn import_reject_counter<'a>(snap: &'a MetricsSnapshot, peer_ip: &str) -> Option<&'a DebugValue> {
    snap.get(&(
        "pathvectord_bgp_import_policy_rejected_total".to_string(),
        vec![("peer".to_string(), peer_ip.to_string())],
    ))
}

#[test]
fn test_handle_update_reject_increments_import_reject_metric() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    let snap = capture(|| {
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![],
                announced: vec![nlri("192.0.2.0/24")],
            },
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );
    });
    assert_eq!(
        import_reject_counter(&snap, "10.0.0.1"),
        Some(&DebugValue::Counter(1)),
        "one route rejected by a reject-all import policy must increment the metric"
    );
    assert_eq!(rib.len(), 0, "sanity check: the route really was rejected");
}

/// The single most important test in this gap: a BLACKHOLE-community
/// route bypasses import policy entirely by design (RFC 7999) — it must
/// NOT be counted as an import-policy rejection, even though it also
/// increments the *local* `rejected` counter used for the existing log
/// line. Conflating the two would make an operator think their import
/// policy is rejecting routes when blackhole handling is working
/// exactly as intended.
#[test]
fn test_handle_update_blackhole_route_does_not_increment_import_reject_metric() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    let snap = capture(|| {
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::Communities(vec![Community::BLACKHOLE]),
                ],
                announced: vec![nlri("192.0.2.0/24")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
    });
    assert!(
        import_reject_counter(&snap, "10.0.0.1").is_none(),
        "a BLACKHOLE route must never be counted as an import-policy rejection"
    );
}

#[test]
fn test_reapply_import_policy_reject_increments_import_reject_metric() {
    let mut ari = fresh_ari();
    ari.insert(route_v4("192.0.2.0/24"));
    ari.insert(route_v4("198.51.100.0/24"));
    let mut rib = LocRib::new();
    let snap = capture(|| {
        let _ = reapply_without_blackholes(
            peer(),
            &ari,
            &mut rib,
            &reject_all(),
            &test_gate(),
            &AlwaysReachable,
        );
    });
    assert_eq!(
        import_reject_counter(&snap, "10.0.0.1"),
        Some(&DebugValue::Counter(2)),
        "reapply_import_policy must report its batch-total rejected count"
    );
}

#[test]
fn test_reapply_import_policy_v6_reject_increments_import_reject_metric() {
    let mut ari: AdjRibIn<Ipv6Addr> = AdjRibIn::new(peer());
    ari.insert(route_v6("2001:db8::/32"));
    let mut rib: LocRib<Ipv6Addr> = LocRib::new();
    let snap = capture(|| {
        let _ = reapply_without_blackholes(
            peer(),
            &ari,
            &mut rib,
            &reject_all_v6(),
            &test_gate(),
            &AlwaysReachable,
        );
    });
    assert_eq!(
        import_reject_counter(&snap, "10.0.0.1"),
        Some(&DebugValue::Counter(1))
    );
}
