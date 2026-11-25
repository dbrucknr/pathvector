//! Which AS numbers a received UPDATE may carry.
//!
//! A pure step of attribute decoding: it looks only at the attributes decoded
//! from one UPDATE and records what the RFCs require for each violation. The
//! RFC 7606 recovery itself is decided and applied by the FSM.
//!
//! RFC 7607 §2 (AS 0): `AS_PATH` and `AGGREGATOR` errors are "handled by the
//! procedures specified in [RFC7606]" — treat-as-withdraw (§7.2) and attribute
//! discard (§7.7) respectively; `AS4_PATH` and `AS4_AGGREGATOR` errors by
//! RFC 6793 §6 — attribute discard for both.
//!
//! It must run on the attributes as received, before
//! `AS4_PATH` / `AS4_AGGREGATOR` are merged away.

use pathvector_types::Asn;

use super::update::{AttributeDecodeError, AttributeErrorPolicy, PathAttribute};

/// Applies the receive rules to `attrs`, appending to `errors`.
///
/// A discarded attribute is removed from `attrs`. An attribute that calls for
/// treat-as-withdraw is left in place, so the UPDATE can still be inspected as
/// it was received.
pub(super) fn apply_receive_rules(
    attrs: &mut Vec<PathAttribute>,
    errors: &mut Vec<AttributeDecodeError>,
) {
    attrs.retain(|attr| {
        let violation = match attr {
            PathAttribute::AsPath(path) if path.contains(Asn::ZERO) => (
                AttributeErrorPolicy::TreatAsWithdraw,
                "AS 0 in AS_PATH (RFC 7607 §2)",
            ),
            PathAttribute::Aggregator(agg) if agg.asn == Asn::ZERO => (
                AttributeErrorPolicy::AttributeDiscard,
                "AS 0 in AGGREGATOR (RFC 7607 §2)",
            ),
            PathAttribute::As4Path(path) if path.contains(Asn::ZERO) => (
                AttributeErrorPolicy::AttributeDiscard,
                "AS 0 in AS4_PATH (RFC 7607 §2)",
            ),
            PathAttribute::As4Aggregator { asn: 0, .. } => (
                AttributeErrorPolicy::AttributeDiscard,
                "AS 0 in AS4_AGGREGATOR (RFC 7607 §2)",
            ),
            _ => return true,
        };
        let (policy, detail) = violation;
        let discard = policy == AttributeErrorPolicy::AttributeDiscard;
        errors.push(AttributeDecodeError {
            type_code: attr.type_code(),
            policy,
            detail,
        });
        !discard
    });
}
