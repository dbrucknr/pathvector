//! End-to-end test for RFC 4271 §5's unrecognized-transitive-attribute
//! relay, over a complete, real two-hop BGP path.
//!
//! Closes the gap identified in Codex's review of PR #49: the existing
//! coverage for "Paths with unrecognized transitive optional attributes
//! SHOULD be accepted and passed along to other BGP peers with the Partial
//! bit... set to 1" is decode-level and daemon-storage-level only. Nothing
//! previously proved the complete decode → daemon storage → RIB →
//! outbound-reconstruction → encode pipeline through a real relay, nor that
//! the Partial bit specifically ends up set on the re-encoded wire bytes a
//! second peer actually receives.

use std::time::Duration;

use pathvector_e2e::{
    UNKNOWN_TRANSITIVE_ATTR_TEST_PREFIX, UnknownTransitiveAttrHarness, wait_for_docker_log,
    wait_for_route,
};

/// RFC 4271 §5: an unrecognized transitive optional attribute must be
/// accepted, stored, and re-forwarded to other peers with the Partial bit
/// set and its value unchanged. An unrecognized *non-transitive* optional
/// attribute (the negative control) must be quietly dropped, never
/// forwarded. Asserted against the observer's own real-wire decode of
/// pathvectord's re-advertised UPDATE, not GoBGP CLI text (not precise
/// enough to assert an exact flags octet).
#[tokio::test]
async fn unknown_transitive_attribute_relayed_with_partial_bit_set() {
    let mut h = UnknownTransitiveAttrHarness::new().await;

    // Confirms the route reached pathvectord's own Loc-RIB (and therefore
    // that decoding + daemon storage of the unrecognized attributes did not
    // reject the whole UPDATE) before checking what the observer received.
    wait_for_route(
        &mut h.client,
        UNKNOWN_TRANSITIVE_ATTR_TEST_PREFIX,
        Duration::from_secs(15),
    )
    .await
    .expect("route did not appear in pathvectord's own Loc-RIB within 15 s");

    wait_for_docker_log(
        &h.observer_id,
        "SCENARIO_OUTCOME: transitive_present=true partial_bit_set=true value_matches=true \
         nontransitive_present=false",
        Duration::from_secs(15),
    )
    .await
    .expect(
        "RFC 4271 §5: the observer must receive the unrecognized transitive attribute with \
         its value unchanged and the Partial bit now set, and must NOT receive the \
         unrecognized non-transitive attribute at all",
    );
}
