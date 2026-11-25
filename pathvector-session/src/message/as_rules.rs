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

use pathvector_types::{AsPath, Asn};

use super::update::{AttributeDecodeError, AttributeErrorPolicy, PathAttribute};

/// What one received path holds that the rules care about.
struct PathContent {
    set_segment: bool,
    as_zero: bool,
}

/// Reads `path` once. This runs for every UPDATE received, so the AS 0 test is
/// a branch-free fold over each segment, which the compiler can vectorise.
fn scan(path: &AsPath) -> PathContent {
    let mut content = PathContent {
        set_segment: false,
        as_zero: false,
    };
    for segment in path.segments() {
        content.set_segment |= segment.is_set();
        // Integer OR rather than `any`: no early exit to defeat vectorisation.
        content.as_zero |= segment
            .asns()
            .iter()
            .fold(0, |found, &asn| found | u8::from(asn == Asn::ZERO))
            != 0;
    }
    content
}

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

    let first_new = errors.len();
    for attr in attrs.iter() {
        let mut report = |policy, detail| {
            errors.push(AttributeDecodeError {
                type_code: attr.type_code(),
                policy,
                detail,
            });
        };
        match attr {
            PathAttribute::AsPath(path) => {
                let content = scan(path);
                if content.set_segment {
                    report(
                        TreatAsWithdraw,
                        "AS_SET or AS_CONFED_SET in AS_PATH (RFC 9774 §3)",
                    );
                }
                if content.as_zero {
                    report(TreatAsWithdraw, "AS 0 in AS_PATH (RFC 7607 §2)");
                }
            }
            PathAttribute::As4Path(path) => {
                let content = scan(path);
                if content.set_segment {
                    report(
                        TreatAsWithdraw,
                        "AS_SET or AS_CONFED_SET in AS4_PATH (RFC 9774 §3)",
                    );
                }
                if content.as_zero {
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
    }

    // Only a violation costs a second pass. `attrs` holds one instance of
    // each type (repeats were dropped while decoding), so a type code
    // identifies the attribute to discard.
    let discarded = &errors[first_new..];
    if !discarded.is_empty() {
        attrs.retain(|attr| {
            !discarded
                .iter()
                .any(|e| e.policy == AttributeDiscard && e.type_code == attr.type_code())
        });
    }
}
