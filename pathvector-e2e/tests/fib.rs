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

use pathvector_client::DaemonClient;
use pathvector_e2e::{
    FibHarness, assert_no_kernel_route_family, scrape_metrics_text,
    wait_for_kernel_blackhole_route, wait_for_kernel_blackhole_route_family,
    wait_for_kernel_blackhole_route_withdrawn, wait_for_kernel_route,
    wait_for_kernel_route_absent_family, wait_for_kernel_route_withdrawn, wait_for_metric,
    wait_for_route, wait_for_route_withdrawn,
};

/// The BLACKHOLE agreement every blackhole test below configures: the GoBGP
/// session may blackhole anything under these (RFC 7999 §3.3 — `blackhole_authorized_prefixes`
/// is both the agreement to honor BLACKHOLE and the authorized scope).
const BLACKHOLE_SCOPE: [&str; 3] = ["192.0.0.0/16", "10.0.0.0/8", "2001:db8:ffff::/48"];

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
    let h = FibHarness::new_with_blackhole(&BLACKHOLE_SCOPE).await;

    h.gobgp_announce_blackhole("192.0.2.0/24");

    wait_for_kernel_blackhole_route(&h.pathvectord_id, "192.0.2.0/24", Duration::from_secs(15))
        .await
        .expect("192.0.2.0/24 (BLACKHOLE) was not installed as a kernel null route within 15 s");
}

/// When GoBGP withdraws a BLACKHOLE-tagged prefix, the kernel null route must
/// be removed. This is the e2e counterpart of the `blackhole_route_withdrawal_removes_kernel_null_route` unit test.
#[tokio::test]
async fn blackhole_route_withdrawn_removes_kernel_null_route() {
    let h = FibHarness::new_with_blackhole(&BLACKHOLE_SCOPE).await;

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
    let h = FibHarness::new_with_blackhole(&BLACKHOLE_SCOPE).await;

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

/// RFC 7999 §3.3 condition 2 / §4: with no `blackhole_authorized_prefixes` —
/// the default — a BLACKHOLE-tagged announcement from GoBGP must leave the
/// kernel untouched: no null route, and not a unicast route either. The
/// ordinary route announced *after* it proves the earlier UPDATE was processed
/// (BGP is an ordered stream), so "absent" is not just "not yet".
#[tokio::test]
async fn blackhole_without_agreement_leaves_the_kernel_untouched() {
    let h = FibHarness::new().await;

    h.gobgp_announce_blackhole("192.0.5.0/24");
    h.gobgp_announce("10.110.0.0/24", &h.gobgp_ip.to_string());
    wait_for_kernel_route(&h.pathvectord_id, "10.110.0.0/24", Duration::from_secs(15))
        .await
        .expect("marker route 10.110.0.0/24 was not installed within 15 s");

    assert_no_kernel_route_family(
        &h.pathvectord_id,
        "192.0.5.0/24",
        false,
        Duration::from_secs(3),
    )
    .await;
}

/// RFC 7999 §3.3 condition 1: an agreed session still honors only prefixes
/// covered by the authorized scope. 198.51.100.0/24 is outside every
/// `BLACKHOLE_SCOPE` entry.
#[tokio::test]
async fn blackhole_outside_the_authorized_scope_leaves_the_kernel_untouched() {
    let h = FibHarness::new_with_blackhole(&BLACKHOLE_SCOPE).await;

    h.gobgp_announce_blackhole("198.51.100.0/24");
    h.gobgp_announce_blackhole("192.0.6.0/24"); // in scope: the ordering marker
    wait_for_kernel_blackhole_route(&h.pathvectord_id, "192.0.6.0/24", Duration::from_secs(15))
        .await
        .expect("in-scope marker blackhole was not installed within 15 s");

    assert_no_kernel_route_family(
        &h.pathvectord_id,
        "198.51.100.0/24",
        false,
        Duration::from_secs(3),
    )
    .await;
}

/// RFC 7999 §3.3: the typical blackhole is a host route, and the agreement is
/// what authorizes it — the session's import default here is the daemon's
/// harness default (accept), but the null route is programmed by the agreement,
/// not by policy. IPv4 `/32`: installed as `RTN_BLACKHOLE`, then removed when
/// the peer withdraws it.
#[tokio::test]
async fn authorized_ipv4_host_blackhole_is_installed_and_withdrawn() {
    let h = FibHarness::new_with_blackhole(&BLACKHOLE_SCOPE).await;

    h.gobgp_announce_blackhole("192.0.7.77/32");
    wait_for_kernel_blackhole_route_family(
        &h.pathvectord_id,
        "192.0.7.77/32",
        false,
        Duration::from_secs(15),
    )
    .await
    .expect("IPv4 /32 (BLACKHOLE) was not installed as a kernel null route within 15 s");

    h.gobgp_withdraw("192.0.7.77/32");
    wait_for_kernel_route_absent_family(
        &h.pathvectord_id,
        "192.0.7.77/32",
        false,
        Duration::from_secs(15),
    )
    .await
    .expect("IPv4 /32 null route was not removed after the peer withdrew it");
}

/// IPv6 counterpart: an authorized `/128` BLACKHOLE (received in an
/// `MP_REACH_NLRI`) becomes a kernel `blackhole` route, and is removed when
/// withdrawn. A denied IPv6 request (outside the scope) installs nothing.
#[tokio::test]
async fn authorized_ipv6_host_blackhole_is_installed_withdrawn_and_scoped() {
    let h = FibHarness::new_with_blackhole(&BLACKHOLE_SCOPE).await;

    h.gobgp_announce_blackhole_v6("2001:db8:aaaa::1/128"); // outside the scope
    h.gobgp_announce_blackhole_v6("2001:db8:ffff::77/128");
    wait_for_kernel_blackhole_route_family(
        &h.pathvectord_id,
        "2001:db8:ffff::77/128",
        true,
        Duration::from_secs(15),
    )
    .await
    .expect("IPv6 /128 (BLACKHOLE) was not installed as a kernel null route within 15 s");
    assert_no_kernel_route_family(
        &h.pathvectord_id,
        "2001:db8:aaaa::1/128",
        true,
        Duration::from_secs(2),
    )
    .await;

    h.gobgp_withdraw_v6("2001:db8:ffff::77/128");
    wait_for_kernel_route_absent_family(
        &h.pathvectord_id,
        "2001:db8:ffff::77/128",
        true,
        Duration::from_secs(15),
    )
    .await
    .expect("IPv6 /128 null route was not removed after the peer withdrew it");
}

// ── FIB Prometheus metrics ────────────────────────────────────────────────────

/// `pathvectord_bgp_fib_routes_installed{afi="ipv4"}` must increment after a
/// real netlink install and decrement after a real netlink withdraw — proving
/// `on_fib_write` is wired into `fib::process_batch`'s real success arms, not
/// just correct in isolation (covered by `fib.rs`'s own unit tests against a
/// `MockFibWriter`).
#[tokio::test]
async fn fib_routes_installed_gauge_tracks_real_kernel_install_and_withdraw() {
    let h = FibHarness::new_with_metrics().await;
    let metrics_port = h
        .metrics_host_port
        .expect("metrics enabled for this harness");

    wait_for_metric(
        metrics_port,
        "pathvectord_bgp_fib_routes_installed{afi=\"ipv4\"} 0",
        Duration::from_secs(10),
    )
    .await;

    h.gobgp_announce("10.101.0.0/24", &h.gobgp_ip.to_string());

    // Confirm the real kernel install landed first, so the metric assertion
    // below is checking a state we know already settled.
    wait_for_kernel_route(&h.pathvectord_id, "10.101.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.101.0.0/24 was not installed in kernel FIB within 15 s");

    wait_for_metric(
        metrics_port,
        "pathvectord_bgp_fib_routes_installed{afi=\"ipv4\"} 1",
        Duration::from_secs(10),
    )
    .await;

    h.gobgp_withdraw("10.101.0.0/24");

    wait_for_kernel_route_withdrawn(&h.pathvectord_id, "10.101.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.101.0.0/24 was not removed from kernel FIB within 15 s");

    wait_for_metric(
        metrics_port,
        "pathvectord_bgp_fib_routes_installed{afi=\"ipv4\"} 0",
        Duration::from_secs(10),
    )
    .await;
}

/// A BLACKHOLE route's kernel null-route install must also count toward
/// `pathvectord_bgp_fib_routes_installed{afi="ipv4"}` — it is still a real FIB
/// entry (`RTN_BLACKHOLE`), just not a unicast one.
#[tokio::test]
async fn fib_routes_installed_gauge_counts_real_blackhole_install() {
    let h = FibHarness::new_with_metrics_and_blackhole(&BLACKHOLE_SCOPE).await;
    let metrics_port = h
        .metrics_host_port
        .expect("metrics enabled for this harness");

    h.gobgp_announce_blackhole("10.102.0.0/24");

    wait_for_kernel_blackhole_route(&h.pathvectord_id, "10.102.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.102.0.0/24 (BLACKHOLE) was not installed as a kernel null route within 15 s");

    wait_for_metric(
        metrics_port,
        "pathvectord_bgp_fib_routes_installed{afi=\"ipv4\"} 1",
        Duration::from_secs(10),
    )
    .await;
}

/// No FIB write failures are expected on the happy path — the
/// `pathvectord_bgp_fib_write_failures_total` series must not appear at all
/// when every real netlink write has succeeded, matching `on_fib_write`'s
/// documented "never move both" invariant (gauge moves on success, counter on
/// failure, never both).
#[tokio::test]
async fn fib_write_failures_counter_absent_on_healthy_install() {
    let h = FibHarness::new_with_metrics().await;
    let metrics_port = h
        .metrics_host_port
        .expect("metrics enabled for this harness");

    h.gobgp_announce("10.103.0.0/24", &h.gobgp_ip.to_string());

    wait_for_kernel_route(&h.pathvectord_id, "10.103.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.103.0.0/24 was not installed in kernel FIB within 15 s");

    let body = scrape_metrics_text(metrics_port);
    assert!(
        !body.contains("pathvectord_bgp_fib_write_failures_total"),
        "fib_write_failures_total must not appear when every netlink write succeeded\nfull body:\n{body}"
    );
}

// ── Import-policy-reject counter (real BGP session) ───────────────────────────

/// `pathvectord_bgp_import_policy_rejected_total{peer}` must increment when a
/// real UPDATE hits `handle_update`'s actual `Decision::Reject` arm, but must
/// NOT increment for a real RFC 7999 BLACKHOLE UPDATE received under the same
/// reject-all policy — proving the distinction holds over a real BGP session,
/// not just against hand-built `UpdateMessage` structs in unit tests (where a
/// prior bug conflating the two was originally caught and fixed).
///
/// Ordering determinism: an *authorized* BLACKHOLE route is honored instead of
/// (not through) import policy — RFC 7999 §3.3 — so it reaches the kernel as a
/// null route whatever the import default, and its kernel install is used as a
/// "everything earlier in this ordered BGP session has already been
/// processed" marker — avoiding a fixed sleep. The session therefore agrees to
/// BLACKHOLE for 10.105.1.0/24 only.
#[tokio::test]
async fn import_reject_counter_increments_on_real_reject_but_not_blackhole() {
    let h = FibHarness::new_with_metrics_and_blackhole(&["10.105.1.0/24"]).await;
    let metrics_port = h
        .metrics_host_port
        .expect("metrics enabled for this harness");
    let peer_ip = h.gobgp_ip.to_string();

    let mut client = h.client.clone();
    client
        .set_import_default(&peer_ip, false)
        .await
        .expect("SetImportDefault(Reject) gRPC call succeeded");

    h.gobgp_announce("10.105.0.0/24", &peer_ip);
    h.gobgp_announce_blackhole("10.105.1.0/24");

    wait_for_kernel_blackhole_route(&h.pathvectord_id, "10.105.1.0/24", Duration::from_secs(15))
        .await
        .expect("10.105.1.0/24 (BLACKHOLE) marker route was not installed within 15 s");

    wait_for_metric(
        metrics_port,
        &format!("pathvectord_bgp_import_policy_rejected_total{{peer=\"{peer_ip}\"}} 1"),
        Duration::from_secs(10),
    )
    .await;
}
