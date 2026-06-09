//! End-to-end compliance tests for RFC 8212 default-reject policy and runtime
//! policy reload (soft reconfiguration).
//!
//! # RFC 8212 — Default External BGP Route Propagation Behavior
//!
//! RFC 8212 mandates that an eBGP speaker with **no** explicit import or export
//! policy MUST default to rejecting routes in both directions.  This prevents
//! accidental route leaks on misconfigured routers.
//!
//! Each static-policy test has a **negative** variant (RFC 8212 compliance —
//! routes must be blocked) and a matching **positive control** (explicit accept
//! policy — routes must flow).  The controls confirm the topology works; the
//! negative tests confirm the default-reject is enforced.
//!
//! # Soft reconfiguration (runtime policy reload)
//!
//! The `set_import_default` and `set_export_default` gRPC RPCs allow an
//! operator to change a peer's policy default at runtime without tearing down
//! the BGP session.  The daemon re-evaluates the relevant RIB and propagates
//! any changes as BGP UPDATEs or WITHDRAWs.
//!
//! - **Import reload**: start with RFC 8212 reject default, confirm route is
//!   absent, call `SetImportDefault(Accept)`, confirm route appears in Loc-RIB.
//! - **Export reload**: start with RFC 8212 reject default, confirm route is
//!   not forwarded to sink, call `SetExportDefault(Accept)`, confirm route
//!   propagates to sink.
//!
//! # Import policy tests (single-peer topology)
//!
//! ```text
//! GoBGP (AS 65001) ──UPDATE──► pathvectord (AS 65002)
//! ```
//!
//! - **No import policy**: the UPDATE must be silently dropped; prefix absent
//!   from Loc-RIB.
//! - **`import_default = "accept"`**: the UPDATE must be installed; prefix
//!   present in Loc-RIB.
//!
//! # Export policy tests (two-peer topology)
//!
//! ```text
//! GoBGP-source (AS 65003) ──► pathvectord (AS 65002) ──► GoBGP-sink (AS 65001)
//! ```
//!
//! - **No export policy**: the route reaches Loc-RIB but must NOT be forwarded
//!   to the sink.
//! - **`export_default = "accept"`**: the route must propagate end-to-end to
//!   the sink (covered by `outbound.rs`; not repeated here).

use std::time::Duration;

use pathvector_e2e::{Harness, TwoPeerHarness, wait_for_gobgp_rib_entry, wait_for_route};

// ── Import policy ─────────────────────────────────────────────────────────────

/// RFC 8212 §4: an eBGP session with no explicit import policy MUST NOT
/// install received routes into the Loc-RIB.
///
/// The session itself is fully established — pathvectord and GoBGP exchange
/// OPEN/KEEPALIVE successfully.  Only the UPDATE carrying the prefix is
/// subject to the default-reject.  We wait long enough (5 s) for the UPDATE
/// to have been processed before asserting absence.
#[tokio::test]
async fn no_import_policy_rejects_ebgp_prefix() {
    let mut h = Harness::new_rfc8212().await;

    h.gobgp_announce("192.0.2.0/24", "10.0.0.1");

    // Give pathvectord time to receive and process the UPDATE.  If the
    // default-reject is working the route will never appear; if it is broken
    // the route appears within milliseconds of the UPDATE being sent.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let route = h
        .client
        .get_best_route("192.0.2.0/24")
        .await
        .expect("gRPC call succeeded");

    assert!(
        route.is_none(),
        "RFC 8212 violation: 192.0.2.0/24 appeared in Loc-RIB without an explicit import policy"
    );
}

/// Positive control: with `import_default = "accept"`, an announced prefix
/// MUST be installed in the Loc-RIB.
///
/// This test confirms that the topology itself works and that the RFC 8212
/// test above fails for the right reason (policy default), not because of a
/// broken session or timing issue.
#[tokio::test]
async fn explicit_import_accept_installs_ebgp_prefix() {
    let mut h = Harness::new().await;

    h.gobgp_announce("192.0.2.128/25", "10.0.0.1");

    wait_for_route(&mut h.client, "192.0.2.128/25", Duration::from_secs(10))
        .await
        .expect("192.0.2.128/25 did not appear in Loc-RIB within 10 s with explicit import accept");
}

// ── Export policy ─────────────────────────────────────────────────────────────

/// RFC 8212 §4: an eBGP session with no explicit export policy MUST NOT
/// advertise routes to the peer.
///
/// The two-peer harness is configured with `import_default = "accept"` on
/// both peers (so pathvectord accepts the route from the source into
/// Loc-RIB) but with **no** `export_default` on either peer (so the RFC 8212
/// eBGP export default of `Reject` applies).
///
/// We assert two things:
/// 1. The route IS present in pathvectord's Loc-RIB — the import leg works.
/// 2. The route is NOT present in the sink's global RIB — the export leg is
///    suppressed.
#[tokio::test]
async fn no_export_policy_suppresses_advertisement_to_peer() {
    let mut h = TwoPeerHarness::new_no_export_policy().await;

    h.source_announce("198.51.100.0/24", "10.0.0.1");

    // Step 1: verify the route reaches pathvectord's own Loc-RIB (import
    // policy is accept, so this must succeed).
    wait_for_route(&mut h.client, "198.51.100.0/24", Duration::from_secs(10))
        .await
        .expect("198.51.100.0/24 must appear in pathvectord Loc-RIB with import_default=accept");

    // Step 2: confirm the route was NOT forwarded to the sink.  At this point
    // the route is already in Loc-RIB, so pathvectord had every opportunity to
    // send it — if it was going to, it would have done so by now.  An extra
    // 3 s gives a generous margin before we call the assertion.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let out = std::process::Command::new("docker")
        .args(["exec", &h.sink_id, "gobgp", "global", "rib"])
        .output()
        .expect("docker exec gobgp global rib");
    let rib_text = String::from_utf8_lossy(&out.stdout);

    assert!(
        !rib_text.contains("198.51.100.0/24"),
        "RFC 8212 violation: 198.51.100.0/24 appeared in sink's RIB without an explicit export policy\nSink RIB:\n{rib_text}"
    );
}

/// Negative control for the export direction: with `export_default = "accept"`
/// the route announced by the source MUST reach the sink.
///
/// This is the basic happy-path covered by `outbound.rs`; we include one
/// representative case here so this file is self-contained.
#[tokio::test]
async fn explicit_export_accept_propagates_to_sink() {
    let h = TwoPeerHarness::new().await;

    h.source_announce("198.51.100.128/25", "10.0.0.1");

    wait_for_gobgp_rib_entry(&h.sink_id, "198.51.100.128/25", Duration::from_secs(15))
        .await
        .expect("198.51.100.128/25 did not reach sink within 15 s with explicit export accept");
}

// ── Soft reconfiguration (runtime policy reload) ──────────────────────────────

/// Runtime import-policy reload: start with RFC 8212 reject default, confirm
/// the route is absent, then call `SetImportDefault(Accept)` via gRPC and
/// verify the route now appears in the Loc-RIB without tearing down the session.
///
/// This tests the `set_import_default` → `reapply_import_policy` →
/// `propagate_prefix` chain end-to-end.
#[tokio::test]
async fn soft_reconfig_import_accept_installs_route() {
    let mut h = Harness::new_rfc8212().await;

    h.gobgp_announce("203.0.113.0/24", "10.0.0.1");

    // With RFC 8212 default-reject the route must be absent.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let route = h
        .client
        .get_best_route("203.0.113.0/24")
        .await
        .expect("gRPC call succeeded");
    assert!(
        route.is_none(),
        "pre-condition failed: 203.0.113.0/24 appeared in Loc-RIB before policy reload"
    );

    // Flip the import policy to Accept at runtime.
    let peer_ip = h.peer.to_string();
    h.client
        .set_import_default(&peer_ip, true)
        .await
        .expect("SetImportDefault gRPC call succeeded");

    // The daemon re-evaluates the Adj-RIB-In synchronously in the write-lock
    // handler; the route should be visible almost immediately.
    wait_for_route(&mut h.client, "203.0.113.0/24", Duration::from_secs(10))
        .await
        .expect(
            "203.0.113.0/24 did not appear in Loc-RIB within 10 s after SetImportDefault(Accept)",
        );
}

/// Runtime export-policy reload: start with RFC 8212 reject default (import
/// accept, export reject), confirm the route reaches Loc-RIB but is NOT
/// forwarded to the sink, then call `SetExportDefault(Accept)` via gRPC and
/// verify the route propagates to the sink.
///
/// This tests the `set_export_default` → `propagate_prefix` chain end-to-end.
#[tokio::test]
async fn soft_reconfig_export_accept_propagates_to_sink() {
    let mut h = TwoPeerHarness::new_no_export_policy().await;

    h.source_announce("203.0.113.128/25", "10.0.0.1");

    // Import leg works — route must reach Loc-RIB.
    wait_for_route(&mut h.client, "203.0.113.128/25", Duration::from_secs(10))
        .await
        .expect("203.0.113.128/25 must appear in pathvectord Loc-RIB (import accept)");

    // Export leg blocked by RFC 8212 default-reject — route must NOT reach sink.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let out = std::process::Command::new("docker")
        .args(["exec", &h.sink_id, "gobgp", "global", "rib"])
        .output()
        .expect("docker exec gobgp global rib");
    let rib_text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !rib_text.contains("203.0.113.128/25"),
        "pre-condition failed: 203.0.113.128/25 appeared in sink RIB before export policy reload"
    );

    // Flip the export policy for the sink peer to Accept at runtime.
    let sink_peer_ip = h.sink_peer.to_string();
    h.client
        .set_export_default(&sink_peer_ip, true)
        .await
        .expect("SetExportDefault gRPC call succeeded");

    // The daemon propagates the Loc-RIB to the sink immediately.
    wait_for_gobgp_rib_entry(&h.sink_id, "203.0.113.128/25", Duration::from_secs(15))
        .await
        .expect("203.0.113.128/25 did not reach sink within 15 s after SetExportDefault(Accept)");
}
