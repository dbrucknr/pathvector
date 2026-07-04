//! End-to-end test for RFC 4724 §4.2 IPv6 GR deadline-expiry re-propagation.
//!
//! Regression coverage for the `on_gr_deadline_expired` IPv6 fix
//! (CHANGELOG.md 2026-07-03): the function correctly withdrew IPv6 routes
//! from the kernel FIB and pathvectord's own Loc-RIB when a GR-capable
//! peer's restart window expired without re-establishment, but the loop
//! that notifies *other* BGP peers of the withdrawal only iterated IPv4
//! prefixes. Other peers never received a real BGP WITHDRAW for IPv6
//! routes that were only reachable via the expired peer, even though the
//! kernel FIB and Loc-RIB were already correct.
//!
//! Topology: see [`pathvector_e2e::GrIpv6ObserverHarness`].

use std::{process::Command, time::Duration};

use pathvector_client::DaemonClient;
use pathvector_e2e::{
    GrIpv6ObserverHarness, wait_for_gobgp_rib_entry_v6, wait_for_gobgp_rib_withdrawn_v6,
    wait_for_route_with_diagnostics,
};

/// GoBGP-source announces an IPv6-only prefix, which pathvectord installs
/// and re-advertises to GoBGP-observer. GoBGP-source is then killed with
/// SIGKILL (unclean termination — no NOTIFICATION), opening a GR restart
/// window. While the window is open the route must still be visible at the
/// observer (pathvectord is holding it). Once the window expires,
/// pathvectord must send a real BGP WITHDRAW to the observer — this is the
/// exact behavior the fix added.
#[tokio::test]
async fn gr_deadline_expiry_sends_v6_withdrawal_to_observer() {
    let mut h = GrIpv6ObserverHarness::new(10).await;

    // GoBGP-source announces an IPv6-only prefix.
    let status = Command::new("docker")
        .args(["exec", &h.source_id])
        .args([
            "gobgp",
            "global",
            "rib",
            "-a",
            "ipv6",
            "add",
            "2001:db8:dead::/48",
            "nexthop",
            "2001:db8::1",
            "origin",
            "igp",
        ])
        .status()
        .expect("docker exec gobgp source v6 announce");
    assert!(
        status.success(),
        "gobgp source v6 announce failed: {status}"
    );

    // Step 1: verify the route reaches pathvectord's own Loc-RIB first, so a
    // failure here (import side) can't be confused with a failure at the
    // observer (export side). Dumps pathvectord's logs on timeout.
    let pathvectord_id = h.pathvectord_id.clone();
    wait_for_route_with_diagnostics(
        &mut h.client,
        "2001:db8:dead::/48",
        Duration::from_secs(15),
        Some(&pathvectord_id),
    )
    .await
    .expect("v6 route did not appear in pathvectord's own Loc-RIB within 15 s");

    // Step 2: must reach GoBGP-observer's real RIB over the wire before we
    // can test what happens to it on GR deadline expiry.
    if let Err(e) = wait_for_gobgp_rib_entry_v6(
        &h.observer_id,
        "2001:db8:dead::/48",
        Duration::from_secs(15),
    )
    .await
    {
        let observer_state = h
            .client
            .get_peer(std::net::IpAddr::V4(h.observer_addr))
            .await;
        panic!(
            "v6 route reached pathvectord's own Loc-RIB but never reached the \
             observer's real RIB within 15 s -- export to the observer is broken: {e}\n\
             --- pathvectord's own view of the observer peer ---\n{observer_state:#?}",
        );
    }

    // Kill GoBGP-source with SIGKILL — no BGP NOTIFICATION is sent. The
    // kernel closes the TCP socket with a RST, which pathvectord sees as an
    // unclean termination. Because GoBGP-source advertised restart-time=10,
    // pathvectord must open a 10 s GR window and keep the route (including
    // at the observer) rather than withdrawing it immediately.
    Command::new("docker")
        .args(["kill", &h.source_id])
        .status()
        .expect("docker kill (SIGKILL) gobgpd-source");

    // The route must still be present at the observer shortly after the
    // kill — pathvectord is holding it during the GR window, and holding a
    // route means continuing to advertise it, not silently going quiet.
    let out = Command::new("docker")
        .args([
            "exec",
            &h.observer_id,
            "gobgp",
            "global",
            "rib",
            "-a",
            "ipv6",
        ])
        .output()
        .expect("docker exec gobgp observer rib check");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("2001:db8:dead::/48"),
        "v6 route was withdrawn from observer immediately after unclean disconnect; \
         expected pathvectord to open a 10 s GR window and hold it"
    );

    // After the restart window expires, the observer must receive a real
    // BGP WITHDRAW — this is the exact behavior on_gr_deadline_expired's
    // IPv6 re-propagation loop adds. Allow 20 s: 10 s window + generous
    // buffer for processing lag.
    wait_for_gobgp_rib_withdrawn_v6(
        &h.observer_id,
        "2001:db8:dead::/48",
        Duration::from_secs(20),
    )
    .await
    .expect(
        "observer never received a WITHDRAW for the v6 route after the GR restart \
         window expired -- on_gr_deadline_expired must re-propagate IPv6 withdrawals \
         to other peers, not just remove the route from its own Loc-RIB",
    );
}
