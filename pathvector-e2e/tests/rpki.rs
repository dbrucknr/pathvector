//! End-to-end test proving pathvectord actually rejects an RPKI-Invalid
//! route delivered over a real BGP session — not just that `pathvector rpki
//! validate` reports `INVALID` in isolation (already covered by mock-server-
//! free unit tests in `pathvector-policy`/`pathvectord`).
//!
//! RFC 6811 — Route Origin Validation.
//!
//! Uses a small, deterministic mock RTR server (see
//! `src/bin/mock_rtr_server.rs`) rather than a real validator like
//! Routinator: this test needs to be hermetic and fast in CI, and doesn't
//! need to re-prove Routinator's own crypto validation (out of scope for
//! `pathvector-rpki`; already proven against real Routinator data in a
//! separate manual smoke test documented in `pathvectord/README.md`).

use std::time::Duration;

use pathvector_client::DaemonClient;
use pathvector_e2e::RpkiHarness;

/// RFC 6811 §2: a route whose covering ROA authorizes a different origin AS
/// must never be accepted into the Loc-RIB, while a route whose covering ROA
/// matches must be accepted — over a real BGP session, with a real RTR
/// client synced against a real (if minimal) RTR server.
#[tokio::test]
async fn invalid_roa_route_is_rejected_valid_is_accepted() {
    let mut h = RpkiHarness::new().await;

    // 203.0.113.0/24: the mock RTR server's ROA authorizes AS 65099 for this
    // prefix, but GoBGP (configured as AS 65001 in this harness) announces
    // it — a covering ROA exists but names a different origin AS, so this is
    // Invalid and must be rejected.
    h.gobgp_announce("203.0.113.0/24", "10.0.0.1");

    // 198.51.100.0/24: the mock RTR server's ROA authorizes AS 65001 for
    // this prefix — GoBGP's announcement matches, so this is Valid.
    h.gobgp_announce("198.51.100.0/24", "10.0.0.1");

    let valid =
        pathvector_e2e::wait_for_route(&mut h.client, "198.51.100.0/24", Duration::from_secs(10))
            .await
            .expect("Valid route (198.51.100.0/24) should be accepted into the Loc-RIB");
    assert_eq!(valid.prefix, "198.51.100.0/24");

    // Give the Invalid route the same generous window, then confirm it
    // never appeared — mirrors the existing RFC 8212 reject-path test's
    // "assert absence after a wait" pattern in pathvector-e2e/tests/policy.rs.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let invalid = h
        .client
        .get_best_route("203.0.113.0/24")
        .await
        .expect("gRPC call succeeded");
    assert!(
        invalid.is_none(),
        "RFC 6811 violation: 203.0.113.0/24 (Invalid ROA — wrong origin AS) \
         appeared in Loc-RIB"
    );
}
