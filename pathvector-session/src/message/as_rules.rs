//! Which AS numbers and segment types a received UPDATE may carry.
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
//! RFC 9774 §3 (`AS_SET` / `AS_CONFED_SET`): "MUST use the
//! "treat-as-withdraw" error handling behavior per [RFC7606] upon reception of
//! BGP UPDATE messages containing `AS_SET`s or `AS_CONFED_SET`s in the `AS_PATH` or
//! `AS4_PATH`". No operator exception is offered. The clause is unconditional
//! about `AS4_PATH`, so a set there withdraws even where RFC 6793 would only
//! discard the attribute (a four-octet session, §4.1) or the segment
//! (`AS_CONFED_SET`, §6): RFC 7606 §3(h), the strongest action applies.
//!
//! It must run on the attributes as received, before
//! `AS4_PATH` / `AS4_AGGREGATOR` are merged away.

use pathvector_types::Asn;

use super::update::{AttributeDecodeError, AttributeErrorPolicy, PathAttribute};

/// Applies the receive rules to `attrs`, appending to `errors`.
///
/// A discarded attribute is removed from `attrs`. An attribute that only calls
/// for treat-as-withdraw is left in place, so the UPDATE can still be inspected
/// as it was received.
pub(super) fn apply_receive_rules(
    attrs: &mut Vec<PathAttribute>,
    errors: &mut Vec<AttributeDecodeError>,
) {
    use AttributeErrorPolicy::{AttributeDiscard, TreatAsWithdraw};

    attrs.retain(|attr| {
        let mut keep = true;
        let mut report = |policy: AttributeErrorPolicy, detail| {
            keep &= policy != AttributeDiscard;
            errors.push(AttributeDecodeError {
                type_code: attr.type_code(),
                policy,
                detail,
            });
        };
        match attr {
            PathAttribute::AsPath(path) => {
                if path.contains_as_set() {
                    report(
                        TreatAsWithdraw,
                        "AS_SET or AS_CONFED_SET in AS_PATH (RFC 9774 §3)",
                    );
                }
                if path.contains(Asn::ZERO) {
                    report(TreatAsWithdraw, "AS 0 in AS_PATH (RFC 7607 §2)");
                }
            }
            PathAttribute::As4Path(path) => {
                if path.contains_as_set() {
                    report(
                        TreatAsWithdraw,
                        "AS_SET or AS_CONFED_SET in AS4_PATH (RFC 9774 §3)",
                    );
                }
                if path.contains(Asn::ZERO) {
                    report(AttributeDiscard, "AS 0 in AS4_PATH (RFC 7607 §2)");
                }
            }
            PathAttribute::Aggregator(agg) if agg.asn == Asn::ZERO => {
                report(AttributeDiscard, "AS 0 in AGGREGATOR (RFC 7607 §2)");
            }
            PathAttribute::As4Aggregator { asn: 0, .. } => {
                report(AttributeDiscard, "AS 0 in AS4_AGGREGATOR (RFC 7607 §2)");
            }
            _ => {}
        }
        keep
    });
}
