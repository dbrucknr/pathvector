//! End-to-end tests for kernel FIB integration (Gap 8).
//!
//! Verifies that pathvectord installs and withdraws `RTPROT_BGP` routes in the
//! Linux kernel routing table (`RT_TABLE_MAIN`, table 254) as BGP prefixes are
//! announced and withdrawn by a peer.
//!
//! These tests require `CAP_NET_ADMIN` in the pathvectord container (granted by
//! [`FibHarness`]) so that `FibWriter` can issue `RTM_NEWROUTE` / `RTM_DELROUTE`
//! via netlink. Route presence is asserted via `ip route show table 254 proto bgp`
//! executed inside the container with `docker exec`.

use std::time::Duration;

use pathvector_e2e::{
    FibHarness, wait_for_kernel_blackhole_route, wait_for_kernel_blackhole_route_withdrawn,
    wait_for_kernel_route, wait_for_kernel_route_withdrawn, wait_for_route,
    wait_for_route_withdrawn,
};

/// A prefix announced by GoBGP must appear in both pathvectord's Loc-RIB
/// (gRPC) and the Linux kernel FIB (`RTPROT_BGP`, table 254).
#[tokio::test]
async fn announced_route_installed_in_kernel_fib() {
    let mut h = FibHarness::new().await;

    h.gobgp_announce("10.100.0.0/24", &h.gobgp_ip.to_string());

    // Wait for the route to reach the Loc-RIB first — confirms BGP processing
    // completed before we check the kernel.
    wait_for_route(&mut h.client, "10.100.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.100.0.0/24 did not appear in Loc-RIB within 15 s");

    // Assert the route was installed in the kernel FIB with RTPROT_BGP.
    wait_for_kernel_route(&h.pathvectord_id, "10.100.0.0/24", Duration::from_secs(10))
        .await
        .expect("10.100.0.0/24 was not installed in kernel FIB (proto bgp) within 10 s");
}

/// When GoBGP withdraws a prefix, pathvectord must remove the corresponding
/// `RTPROT_BGP` route from the kernel FIB.
#[tokio::test]
async fn withdrawn_route_removed_from_kernel_fib() {
    let mut h = FibHarness::new().await;

    h.gobgp_announce("10.200.0.0/24", &h.gobgp_ip.to_string());

    wait_for_kernel_route(&h.pathvectord_id, "10.200.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.200.0.0/24 was not installed in kernel FIB within 15 s");

    h.gobgp_withdraw("10.200.0.0/24");

    // Wait for the Loc-RIB withdrawal first.
    wait_for_route_withdrawn(&mut h.client, "10.200.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.200.0.0/24 was not withdrawn from Loc-RIB within 15 s");

    // Assert the kernel route is gone.
    wait_for_kernel_route_withdrawn(&h.pathvectord_id, "10.200.0.0/24", Duration::from_secs(10))
        .await
        .expect("10.200.0.0/24 was not removed from kernel FIB (proto bgp) within 10 s");
}

/// Multiple prefixes announced simultaneously must all appear in the kernel FIB.
#[tokio::test]
async fn multiple_routes_installed_in_kernel_fib() {
    let h = FibHarness::new().await;

    let prefixes = ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"];
    for prefix in prefixes {
        h.gobgp_announce(prefix, &h.gobgp_ip.to_string());
    }

    for prefix in prefixes {
        wait_for_kernel_route(&h.pathvectord_id, prefix, Duration::from_secs(15))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
}

// ── RFC 7999 BLACKHOLE kernel null routes ─────────────────────────────────────

/// A prefix tagged with the BLACKHOLE community (RFC 7999) must appear in the
/// kernel routing table as a `blackhole` route (`RTN_BLACKHOLE`, not unicast).
/// This proves the actual netlink call reaches the kernel, not just that the
/// daemon method is called (which is covered by unit tests).
#[tokio::test]
async fn blackhole_route_installed_as_kernel_null_route() {
    let h = FibHarness::new().await;

    h.gobgp_announce_blackhole("192.0.2.0/24");

    wait_for_kernel_blackhole_route(&h.pathvectord_id, "192.0.2.0/24", Duration::from_secs(15))
        .await
        .expect("192.0.2.0/24 (BLACKHOLE) was not installed as a kernel null route within 15 s");
}

/// When GoBGP withdraws a BLACKHOLE-tagged prefix, the kernel null route must
/// be removed. This is the e2e counterpart of the `blackhole_route_withdrawal_removes_kernel_null_route` unit test.
#[tokio::test]
async fn blackhole_route_withdrawn_removes_kernel_null_route() {
    let h = FibHarness::new().await;

    h.gobgp_announce_blackhole("192.0.3.0/24");

    wait_for_kernel_blackhole_route(&h.pathvectord_id, "192.0.3.0/24", Duration::from_secs(15))
        .await
        .expect("192.0.3.0/24 (BLACKHOLE) was not installed in kernel FIB within 15 s");

    h.gobgp_withdraw("192.0.3.0/24");

    wait_for_kernel_blackhole_route_withdrawn(
        &h.pathvectord_id,
        "192.0.3.0/24",
        Duration::from_secs(15),
    )
    .await
    .expect("192.0.3.0/24 (BLACKHOLE) null route was not removed from kernel FIB within 15 s");
}

/// A BLACKHOLE prefix must NOT appear as a unicast route in the kernel FIB —
/// only the `blackhole` entry must exist.
#[tokio::test]
async fn blackhole_route_is_not_installed_as_unicast() {
    let h = FibHarness::new().await;

    h.gobgp_announce_blackhole("192.0.4.0/24");

    wait_for_kernel_blackhole_route(&h.pathvectord_id, "192.0.4.0/24", Duration::from_secs(15))
        .await
        .expect("192.0.4.0/24 (BLACKHOLE) kernel null route did not appear within 15 s");

    // Verify the BGP table entry for this prefix is `blackhole` only — no `via`
    // nexthop. Restrict to `table 254 proto bgp` so we only see BGP-installed
    // routes and don't pick up routes from other tables or protocols.
    let output = std::process::Command::new("docker")
        .args([
            "exec",
            &h.pathvectord_id,
            "ip",
            "route",
            "show",
            "table",
            "254",
            "proto",
            "bgp",
            "192.0.4.0/24",
        ])
        .output()
        .expect("docker exec ip route show table 254 proto bgp 192.0.4.0/24");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("blackhole"),
        "BLACKHOLE prefix must appear as a kernel blackhole route in table 254 proto bgp; got: {text}"
    );
    assert!(
        !text.contains("via"),
        "BLACKHOLE prefix must not be installed as a unicast (via) route in table 254 proto bgp; got: {text}"
    );
}
