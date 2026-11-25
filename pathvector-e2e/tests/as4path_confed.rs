//! End-to-end test for RFC 6793 §4's AS_TRANS/AS4_PATH downgrade combined
//! with RFC 5065 §5.3's confederation exception, over a complete, real
//! two-hop BGP path.
//!
//! Closes the gap identified in review: `pathvectord/src/outbound.rs`'s
//! `as4.strip_confed_segments()` call (RFC 6793 §§3, 4.2.2 — confed segments
//! "are declared invalid for the AS4_PATH attribute and MUST NOT be
//! included") had unit coverage only. Nothing previously proved the real
//! wire codec on both ends produces the expected shape: a confed segment
//! surviving the AS_PATH value toward a fellow `ConfedMember` peer (RFC 5065
//! §5.3 — the opposite of the `External` case) while AS4_PATH excludes it.
//!
//! The observer is a genuine OLD BGP speaker (no `FourByteAsn`, RFC 6793
//! §4.2): it parses the raw UPDATE bytes at two octets per ASN, so this also
//! proves pathvectord's real two-octet AS_PATH wire encoding (issue #95), not
//! just the logical AS_TRANS/AS4_PATH decision. Interop with a third-party
//! 2-byte-only implementation is still untested (see `TODO.md`).

use std::time::Duration;

use pathvector_e2e::{
    AS4PATH_CONFED_TEST_PREFIX, As4PathConfedHarness, wait_for_docker_log, wait_for_route,
};

/// A four-byte-ASN-capable confed-member source announces a route whose
/// AS_PATH leads with `AS_CONFED_SEQUENCE` followed by a 4-byte ASN.
/// pathvectord relays it to a fellow confed-member observer that hasn't
/// negotiated `FourByteAsn`. The observer's own decode of the real wire
/// bytes must show: the confed segment still present in the AS_PATH value
/// (RFC 5065 §5.3), AS_PATH genuinely two-octet on the wire with AS_TRANS
/// substituted for the 4-byte ASN (RFC 6793 §4), AS4_PATH present and carrying the real 4-byte ASN, and
/// AS4_PATH excluding the confed segment entirely (RFC 6793 §§3, 4.2.2).
#[tokio::test]
async fn as4_path_excludes_confed_segment_while_wire_as_path_keeps_it() {
    let mut h = As4PathConfedHarness::new().await;

    // Confirms the route reached pathvectord's own Loc-RIB (decoding the
    // 4-byte AS_PATH from the confed-source succeeded) before checking what
    // the two-byte observer actually received.
    wait_for_route(
        &mut h.client,
        AS4PATH_CONFED_TEST_PREFIX,
        Duration::from_secs(15),
    )
    .await
    .expect("route did not appear in pathvectord's own Loc-RIB within 15 s");

    wait_for_docker_log(
        &h.observer_id,
        "SCENARIO_OUTCOME: wire_as_path_two_octet=true \
         wire_as_path_keeps_confed_sequence=true \
         wire_as_path_has_as_trans=true \
         as4_path_present=true \
         as4_path_has_real_asn=true \
         as4_path_excludes_confed_segments=true",
        Duration::from_secs(15),
    )
    .await
    .expect(
        "RFC 6793 §4 / RFC 5065 §5.3: wire AS_PATH toward a fellow ConfedMember peer must \
         keep the confed segment and substitute AS_TRANS for the 4-byte ASN, while AS4_PATH \
         must carry the real 4-byte ASN and exclude the confed segment entirely",
    );
}
