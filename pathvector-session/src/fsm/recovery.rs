//! RFC 7606 recovery policy for a malformed UPDATE, as a pure value.
//!
//! This module decides *what* RFC 7606 §3 requires for a decoded
//! [`MalformedUpdate`] — session reset, treat-as-withdraw, or attribute
//! discard — and nothing else. It performs no I/O and holds no session state.
//! It also cannot *apply* its decision: an [`UpdateRecovery`] is an opaque
//! input to [`Fsm::process`](super::Fsm::process), which first applies
//! RFC 4271 §8.2.2's per-state rules and only in `Established` consumes the
//! outcome. That ordering is a property of the types, not a convention: the
//! transport has no other way to turn a `MalformedUpdate` into a route event
//! or a NOTIFICATION. (Issue #98: recovery used to be applied in the
//! transport directly, so a recovered UPDATE reached the route-event
//! boundary in `OpenSent`.)
//!
//! # RFC clauses implemented
//!
//! * RFC 7606 §3(g): "If the `MP_REACH_NLRI` attribute or the `MP_UNREACH_NLRI`
//!   attribute appears more than once in the UPDATE message, then a
//!   NOTIFICATION message MUST be sent with the Error Subcode "Malformed
//!   Attribute List"."
//! * RFC 4271 §6.3 (not amended by RFC 7606): an unrecognized well-known
//!   attribute is a session reset, Data = the attribute (type, length, value).
//! * RFC 7606 §3(h): "When multiple attribute errors exist ... if the same
//!   approach ... is specified ... then the specified approach MUST be used.
//!   Otherwise, the approach with the strongest action MUST be used." —
//!   session reset beats treat-as-withdraw beats attribute discard.
//! * RFC 7606 §5.2: "if any path attribute errors are encountered in such an
//!   UPDATE message [one with attributes other than `MP_UNREACH_NLRI` and no
//!   reachable NLRI] and if any encountered error specifies an error-handling
//!   approach other than "attribute discard", then the "session reset"
//!   approach MUST be used."
//! * RFC 7606 §2: treat-as-withdraw "MUST be treated as though all contained
//!   routes had been withdrawn just as if they had been listed in the
//!   WITHDRAWN ROUTES field (or in the `MP_UNREACH_NLRI` attribute if
//!   appropriate)"; attribute discard: "the malformed attribute MUST be
//!   discarded and the UPDATE message continues to be processed".

use crate::message::{
    AttributeDecodeError, AttributeErrorPolicy, MalformedUpdate, MpUnreachNlri, NotificationError,
    NotificationMessage, PathAttribute, UpdateMessage, UpdateMsgError,
};

/// The RFC 7606 recovery decision for one malformed UPDATE.
///
/// Obtainable only from [`UpdateRecovery::classify`] and consumable only by
/// the FSM (`into_outcome` is `pub(super)`), so recovery cannot take effect
/// outside the state machine's validation.
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateRecovery {
    outcome: Outcome,
}

/// What recovery requires, once the FSM has decided it is permitted.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Outcome {
    /// RFC 4271 §8.2.2 Event 28: send this NOTIFICATION, reset the session.
    SessionReset(NotificationMessage),
    /// RFC 7606 treat-as-withdraw: process this synthesized withdrawal as an
    /// ordinary Event 27 UPDATE.
    TreatAsWithdraw(UpdateMessage),
    /// RFC 7606 attribute discard: process this cleaned UPDATE as an ordinary
    /// Event 27 UPDATE.
    AttributeDiscard(UpdateMessage),
}

impl UpdateRecovery {
    /// Decide the recovery outcome for `m` (pure; see the module docs for the
    /// clauses applied, in priority order).
    #[must_use]
    pub fn classify(m: MalformedUpdate) -> Self {
        let outcome = if m.session_reset {
            // The specific NotificationError/data the triggering error
            // carries (e.g. Unrecognized Well-known Attribute with the
            // offending attribute in `data`), falling back to Malformed
            // Attribute List with no data only if none is found — which
            // shouldn't happen given `session_reset` is itself derived from
            // the presence of a `SessionReset`-policy error.
            Outcome::SessionReset(
                m.errors
                    .iter()
                    .find_map(|e| match &e.policy {
                        AttributeErrorPolicy::SessionReset { error, data } => {
                            Some(NotificationMessage {
                                error: error.clone(),
                                data: data.clone(),
                            })
                        }
                        _ => None,
                    })
                    .unwrap_or_else(malformed_attribute_list),
            )
        } else if m.treat_as_withdraw && is_nlri_less_with_attributes(&m.update, &m.errors) {
            // RFC 7606 §5.2 "Missing NLRI" — see the module docs. This check
            // MUST run before `make_treat_as_withdraw` strips the surviving
            // attributes it depends on, and MUST also consult `m.errors`: an
            // UPDATE whose only attribute was itself the malformed one (e.g.
            // a lone bad NEXT_HOP, no NLRI at all) has an already-empty
            // `m.update.attributes`, indistinguishable from a legitimate
            // empty End-of-RIB unless the stripped attribute is accounted
            // for too.
            Outcome::SessionReset(malformed_attribute_list())
        } else if m.treat_as_withdraw {
            Outcome::TreatAsWithdraw(make_treat_as_withdraw(m.update))
        } else {
            Outcome::AttributeDiscard(m.update)
        };
        Self { outcome }
    }

    /// `true` when recovery is a session reset (RFC 4271 §8.2.2 Event 28) —
    /// the transport uses this to classify the eventual termination as a
    /// locally detected protocol error rather than an unexplained failure.
    #[must_use]
    pub fn is_session_reset(&self) -> bool {
        matches!(self.outcome, Outcome::SessionReset(_))
    }

    /// The NOTIFICATION a session-reset recovery requires, if it is one.
    #[must_use]
    pub fn notification(&self) -> Option<&NotificationMessage> {
        match &self.outcome {
            Outcome::SessionReset(n) => Some(n),
            _ => None,
        }
    }

    pub(super) fn into_outcome(self) -> Outcome {
        self.outcome
    }
}

/// NOTIFICATION "UPDATE Message Error / Malformed Attribute List", no data.
fn malformed_attribute_list() -> NotificationMessage {
    NotificationMessage {
        error: NotificationError::UpdateMessage(UpdateMsgError::MalformedAttributeList),
        data: vec![],
    }
}

/// RFC 4760 §5: the `MP_UNREACH_NLRI` path attribute type code.
const ATTR_MP_UNREACH_NLRI: u8 = 15;

/// RFC 7606 §5.2 "Missing NLRI": `true` when `update` carries no reachable
/// NLRI at all (no traditional NLRI, no `MP_REACH_NLRI` with any prefixes)
/// but the message — counting both `update.attributes` (attributes that
/// survived decoding) and `errors` (attributes that didn't, because they
/// were themselves malformed) — carries an attribute other than
/// `MP_UNREACH_NLRI`.
///
/// `errors` matters because the decoder removes a malformed attribute from
/// `update.attributes` before `MalformedUpdate` is ever built: an UPDATE
/// whose *only* attribute was a malformed `NEXT_HOP` has an empty
/// `update.attributes` — indistinguishable from a legitimate empty
/// End-of-RIB — unless that stripped attribute is also accounted for here.
///
/// The two legitimate NLRI-less encodings — a fully empty legacy
/// End-of-RIB and an `MP_UNREACH_NLRI`-only End-of-RIB/withdrawal (RFC 4724
/// §2, whether or not `MP_UNREACH_NLRI` itself is also malformed) — have no
/// attribute (survived or errored) other than `MP_UNREACH_NLRI`, so this is
/// `false` for both.
fn is_nlri_less_with_attributes(update: &UpdateMessage, errors: &[AttributeDecodeError]) -> bool {
    let has_reachable_nlri = !update.announced.is_empty()
        || update
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::MpReachNlri(mp) if !mp.prefixes.is_empty()));
    if has_reachable_nlri {
        return false;
    }
    update
        .attributes
        .iter()
        .any(|a| !matches!(a, PathAttribute::MpUnreachNlri(_)))
        || errors.iter().any(|e| e.type_code != ATTR_MP_UNREACH_NLRI)
}

/// Convert an UPDATE with treat-as-withdraw errors into a withdrawal-only UPDATE.
///
/// All announced IPv4 NLRIs are moved into `withdrawn`. Any `MP_REACH_NLRI`
/// attributes are converted to `MP_UNREACH_NLRI` so that non-IPv4 prefixes are
/// also withdrawn. All other attributes are dropped.
pub(crate) fn make_treat_as_withdraw(update: UpdateMessage) -> UpdateMessage {
    let mut withdrawn = update.withdrawn;
    withdrawn.extend(update.announced);

    // Convert any decoded MP_REACH_NLRI → MP_UNREACH_NLRI.
    let mp_unreaches: Vec<PathAttribute> = update
        .attributes
        .into_iter()
        .filter_map(|attr| {
            if let PathAttribute::MpReachNlri(mp) = attr {
                Some(PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: mp.afi_safi,
                    prefixes: mp.prefixes,
                }))
            } else {
                None
            }
        })
        .collect();

    UpdateMessage {
        withdrawn,
        attributes: mp_unreaches,
        announced: vec![],
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr as StdIpv4Addr;

    use pathvector_types::Nlri;

    use super::*;

    #[test]
    fn test_make_treat_as_withdraw_moves_announced_to_withdrawn() {
        use pathvector_types::Nlri;

        let nlri: Nlri<StdIpv4Addr> = "10.0.0.0/8".parse().unwrap();
        let update = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![nlri],
        };
        let result = super::make_treat_as_withdraw(update);
        assert_eq!(result.withdrawn, vec![nlri]);
        assert!(result.announced.is_empty());
        assert!(result.attributes.is_empty());
    }

    #[test]
    fn test_make_treat_as_withdraw_strips_non_mp_reach_attributes() {
        use pathvector_types::Origin;

        let update = UpdateMessage {
            withdrawn: vec![],
            // LOCAL_PREF and ORIGIN are not MpReachNlri — they must be stripped.
            attributes: vec![
                PathAttribute::LocalPref(100),
                PathAttribute::Origin(Origin::Igp),
            ],
            announced: vec![],
        };
        let result = super::make_treat_as_withdraw(update);
        assert!(
            result.attributes.is_empty(),
            "non-MpReach attrs must be stripped"
        );
        assert!(result.withdrawn.is_empty());
        assert!(result.announced.is_empty());
    }

    #[test]
    fn test_make_treat_as_withdraw_mixed_attrs_keeps_only_mp_unreach() {
        use std::net::Ipv6Addr;

        use crate::message::{MpReachNlri, Prefix};
        use pathvector_types::{AfiSafi, NextHop, Nlri, Origin};

        let prefix: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        let update = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::LocalPref(200),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(prefix)],
                }),
                PathAttribute::Origin(Origin::Egp),
            ],
            announced: vec![],
        };
        let result = super::make_treat_as_withdraw(update);
        // Only the converted MpUnreachNlri should remain.
        assert_eq!(result.attributes.len(), 1);
        assert!(
            matches!(&result.attributes[0], PathAttribute::MpUnreachNlri(m) if m.afi_safi == AfiSafi::IPV6_UNICAST),
            "expected MpUnreachNlri after conversion"
        );
        assert!(result.announced.is_empty());
    }

    #[test]
    fn test_make_treat_as_withdraw_empty_update_is_noop() {
        let update = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        };
        let result = super::make_treat_as_withdraw(update);
        assert!(result.withdrawn.is_empty());
        assert!(result.attributes.is_empty());
        assert!(result.announced.is_empty());
    }

    /// Pins down `is_nlri_less_with_attributes`'s cases directly, without
    /// going through a full session. In particular, the `errors` parameter
    /// must count attributes that were malformed and therefore already
    /// stripped from `update.attributes` by the decoder — an UPDATE whose
    /// only attribute was a malformed `NEXT_HOP` (never surviving into
    /// `update.attributes`) must still be `true`, and the same holds even
    /// when a valid `MP_UNREACH_NLRI` also happens to be present.
    #[test]
    fn test_is_nlri_less_with_attributes() {
        use crate::message::MpUnreachNlri;
        use pathvector_types::{AfiSafi, Origin};

        assert!(
            !super::is_nlri_less_with_attributes(
                &UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![],
                },
                &[]
            ),
            "a fully empty legacy EoR must not be NLRI-less-with-attributes"
        );

        assert!(
            !super::is_nlri_less_with_attributes(
                &UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                        afi_safi: AfiSafi::IPV4_UNICAST,
                        prefixes: vec![],
                    })],
                    announced: vec![],
                },
                &[]
            ),
            "an MP_UNREACH_NLRI-only EoR must not be NLRI-less-with-attributes"
        );

        assert!(
            super::is_nlri_less_with_attributes(
                &UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![PathAttribute::Origin(Origin::Igp)],
                    announced: vec![],
                },
                &[]
            ),
            "ORIGIN present with no reachable NLRI at all must be \
             NLRI-less-with-attributes"
        );

        let prefix: Nlri<StdIpv4Addr> = Nlri::new(StdIpv4Addr::new(10, 0, 0, 0), 8).unwrap();
        assert!(
            !super::is_nlri_less_with_attributes(
                &UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![PathAttribute::Origin(Origin::Igp)],
                    announced: vec![prefix],
                },
                &[]
            ),
            "a message with reachable NLRI must not be NLRI-less-with-attributes"
        );

        // [Codex] The decoder strips a malformed attribute before
        // `MalformedUpdate` is built — an UPDATE whose *only* attribute was
        // a malformed NEXT_HOP has empty `update.attributes`, but the
        // stripped attribute must still count via `errors`.
        let next_hop_error = AttributeDecodeError {
            type_code: 3, // NEXT_HOP
            policy: AttributeErrorPolicy::TreatAsWithdraw,
            detail: "invalid NEXT_HOP length",
        };
        assert!(
            super::is_nlri_less_with_attributes(
                &UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![],
                },
                std::slice::from_ref(&next_hop_error)
            ),
            "a malformed NEXT_HOP as the *only* attribute (already stripped \
             from `update.attributes`) must still be NLRI-less-with-attributes"
        );

        // [Codex] The same bypass exists when a valid MP_UNREACH_NLRI is
        // *also* present alongside the malformed NEXT_HOP.
        assert!(
            super::is_nlri_less_with_attributes(
                &UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                        afi_safi: AfiSafi::IPV4_UNICAST,
                        prefixes: vec![],
                    })],
                    announced: vec![],
                },
                std::slice::from_ref(&next_hop_error)
            ),
            "a malformed NEXT_HOP alongside a valid MP_UNREACH_NLRI must \
             still be NLRI-less-with-attributes"
        );

        // A malformed MP_UNREACH_NLRI itself (its own type code, 15) is not
        // "an attribute other than MP_UNREACH_NLRI" — the message never
        // clears §5.2's own gating condition in the first place.
        let mp_unreach_error = AttributeDecodeError {
            type_code: 15, // MP_UNREACH_NLRI
            policy: AttributeErrorPolicy::TreatAsWithdraw,
            detail: "malformed MP_UNREACH_NLRI",
        };
        assert!(
            !super::is_nlri_less_with_attributes(
                &UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![],
                    announced: vec![],
                },
                std::slice::from_ref(&mp_unreach_error)
            ),
            "a malformed MP_UNREACH_NLRI as the only error must not be \
             NLRI-less-with-attributes"
        );
    }

    fn bad(type_code: u8, policy: AttributeErrorPolicy) -> AttributeDecodeError {
        AttributeDecodeError {
            type_code,
            policy,
            detail: "test",
        }
    }

    fn route() -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::Med(1)],
            announced: vec!["10.9.0.0/16".parse::<Nlri<StdIpv4Addr>>().unwrap()],
        }
    }

    /// RFC 7606 §3(h): with several errors the strongest approach wins; a
    /// session reset therefore carries *its own* NOTIFICATION even when a
    /// treat-as-withdraw error is also present.
    #[test]
    fn rfc7606_3_h_strongest_approach_wins() {
        let notif = NotificationMessage {
            error: NotificationError::UpdateMessage(UpdateMsgError::UnrecognizedWellKnownAttribute),
            data: vec![210, 0],
        };
        let r = UpdateRecovery::classify(MalformedUpdate {
            update: route(),
            errors: vec![
                bad(1, AttributeErrorPolicy::TreatAsWithdraw),
                bad(
                    210,
                    AttributeErrorPolicy::SessionReset {
                        error: notif.error.clone(),
                        data: notif.data.clone(),
                    },
                ),
            ],
            treat_as_withdraw: true,
            session_reset: true,
        });
        assert!(r.is_session_reset());
        assert_eq!(r.notification(), Some(&notif));
    }

    /// RFC 7606 §2: treat-as-withdraw yields the withdrawal, attribute
    /// discard yields the cleaned UPDATE untouched; neither has a NOTIFICATION.
    #[test]
    fn rfc7606_2_recovered_outcomes_carry_no_notification() {
        let tw = UpdateRecovery::classify(MalformedUpdate {
            update: route(),
            errors: vec![bad(1, AttributeErrorPolicy::TreatAsWithdraw)],
            treat_as_withdraw: true,
            session_reset: false,
        });
        assert!(!tw.is_session_reset());
        assert_eq!(tw.notification(), None);
        let Outcome::TreatAsWithdraw(w) = tw.into_outcome() else {
            panic!("expected treat-as-withdraw")
        };
        assert_eq!(w.withdrawn, route().announced);
        assert!(w.announced.is_empty() && w.attributes.is_empty());

        let ad = UpdateRecovery::classify(MalformedUpdate {
            update: route(),
            errors: vec![bad(7, AttributeErrorPolicy::AttributeDiscard)],
            treat_as_withdraw: false,
            session_reset: false,
        });
        assert_eq!(ad.notification(), None);
        assert_eq!(ad.into_outcome(), Outcome::AttributeDiscard(route()));
    }

    /// RFC 7606 §5.2: attributes but no reachable NLRI, plus an error
    /// stronger than attribute discard → session reset (Malformed Attribute
    /// List, no Data). The same UPDATE with only an attribute-discard error
    /// is *not* escalated.
    #[test]
    fn rfc7606_5_2_missing_nlri_escalates_only_for_non_discard_errors() {
        let nlri_less = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::Med(1)],
            announced: vec![],
        };
        let escalated = UpdateRecovery::classify(MalformedUpdate {
            update: nlri_less.clone(),
            errors: vec![bad(1, AttributeErrorPolicy::TreatAsWithdraw)],
            treat_as_withdraw: true,
            session_reset: false,
        });
        assert_eq!(escalated.notification(), Some(&malformed_attribute_list()));

        let discard_only = UpdateRecovery::classify(MalformedUpdate {
            update: nlri_less,
            errors: vec![bad(7, AttributeErrorPolicy::AttributeDiscard)],
            treat_as_withdraw: false,
            session_reset: false,
        });
        assert!(!discard_only.is_session_reset());
    }
}
