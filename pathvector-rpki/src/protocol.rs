//! Pure RTR session state machine — no sockets, no clocks, no tables.
//!
//! This module decides *what a received PDU means* given what the router
//! asked for and what it already knows about the cache. The I/O loop in
//! `client.rs` feeds it decoded PDUs and acts on the verdicts (write a query,
//! stage a record, publish, flush, sleep). Keeping the decisions here means
//! every RFC 8210 clause the client enforces can be tested with plain values.
//!
//! The types are deliberately small new-types so the arguments that were
//! previously bare `(u16, u32)` pairs cannot be swapped or half-remembered:
//!
//! * [`SessionId`] and [`Serial`] are distinct types.
//! * [`Resume`] bundles protocol version, session ID and serial. RFC 8210 §5.1:
//!   "The full test for whether Serial Numbers are commensurate requires
//!   comparing Protocol Version, Session ID, and Serial Number." A router
//!   either has all three or has nothing to resume from — the type has no
//!   "serial without a session" state.
//! * [`Negotiation`] distinguishes the initial negotiation period (RFC 8210
//!   §7: downgrade allowed, Serial Notify ignored) from an agreed version
//!   ("stable for the life of the session"). The only way from one to the
//!   other is [`Exchange::on_pdu`] accepting a Cache Response.
//!
//! Every way a cache can break the contract is a [`Violation`], which says in
//! one value what to tell the cache (Error Report), what to do to the data
//! ([`Consequence`]) and what error to surface — so the I/O loop cannot
//! forget a part of the RFC-mandated reaction.

use crate::{
    error::RtrError,
    pdu::{EndOfDataIntervals, Pdu, RtrVersion},
};

/// RFC 8210 §12 error code 0 ("Corrupt Data").
pub(crate) const ERROR_CODE_CORRUPT_DATA: u16 = 0;
/// RFC 8210 §12 error code 2 ("No Data Available") — the *only* error code
/// not marked "(fatal)".
pub(crate) const ERROR_CODE_NO_DATA_AVAILABLE: u16 = 2;
/// RFC 8210 §12 error code 4 ("Unsupported Protocol Version").
pub(crate) const ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION: u16 = 4;
/// RFC 8210 §12 error code 8 ("Unexpected Protocol Version").
pub(crate) const ERROR_CODE_UNEXPECTED_PROTOCOL_VERSION: u16 = 8;

/// RTR Session ID (RFC 8210 §5.1): identifies one instance of a cache and
/// binds it to the sequence of serial numbers that instance generates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionId(u16);

impl SessionId {
    pub(crate) fn new(raw: u16) -> Self {
        Self(raw)
    }

    pub(crate) fn get(self) -> u16 {
        self.0
    }
}

/// RTR Serial Number (RFC 8210 §5.1). The client only remembers and echoes
/// it; ordering is the cache's business (RFC 1982 arithmetic applies there).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Serial(u32);

impl Serial {
    pub(crate) fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) fn get(self) -> u32 {
        self.0
    }
}

/// Everything a router must know to ask a cache for an *incremental* update.
///
/// Created only by a completed transfer (End of Data) and destroyed whenever
/// the cache says the serial is unusable (Cache Reset), a session error
/// occurs, or the cache's data expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Resume {
    pub(crate) version: RtrVersion,
    pub(crate) session: SessionId,
    pub(crate) serial: Serial,
}

/// Where a connection stands in RFC 8210 §7 protocol version negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Negotiation {
    /// No Cache Response seen yet on this connection. Queries go out at this
    /// version; the cache may downgrade us (§7), and any Serial Notify must
    /// be ignored ("regardless of the Protocol Version field").
    Proposed(RtrVersion),
    /// §7: "Once the cache and router have agreed upon a Protocol Version ...
    /// that version is stable for the life of the session."
    Agreed(RtrVersion),
}

impl Negotiation {
    /// The version queries are written at.
    pub(crate) fn version(self) -> RtrVersion {
        match self {
            Self::Proposed(v) | Self::Agreed(v) => v,
        }
    }
}

/// The query a router sends to start an exchange (RFC 8210 §§5.3, 5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Query {
    /// Ask for the complete current data set.
    Reset,
    /// Ask for the changes since a remembered `(version, session, serial)`.
    Serial(Resume),
}

impl Query {
    /// §8.1: a Serial Query is only appropriate when the router remembers the
    /// session; "in all other cases ... MUST fall back to a Reset Query".
    pub(crate) fn choose(resume: Option<Resume>, force_reset: bool) -> Self {
        match resume {
            Some(r) if !force_reset => Self::Serial(r),
            _ => Self::Reset,
        }
    }

    pub(crate) fn pdu(self) -> Pdu {
        match self {
            Self::Reset => Pdu::ResetQuery,
            Self::Serial(r) => Pdu::SerialQuery {
                session_id: r.session.get(),
                serial: r.serial.get(),
            },
        }
    }
}

/// What to do to the cached data when a [`Violation`] ends the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Consequence {
    /// Leave data and resume state alone (they are not implicated).
    Drop,
    /// The remembered `(version, session, serial)` can no longer be used for
    /// an incremental update, but the VRPs themselves are not known to be
    /// wrong: keep serving them, resynchronise from scratch.
    ForgetResume,
    /// RFC 8210 §5.1: "the router MUST flush all data learned from that
    /// cache."
    Flush,
}

/// The Error Report to send before dropping the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ErrorReportSpec {
    pub(crate) code: u16,
    pub(crate) text: &'static str,
}

/// A cache broke the protocol. Carries the complete RFC-mandated reaction.
#[derive(Debug)]
pub(crate) struct Violation {
    /// What to surface to the operator / session loop.
    pub(crate) error: RtrError,
    /// Error Report to send (best effort) before closing, if the RFC calls
    /// for one.
    pub(crate) report: Option<ErrorReportSpec>,
    pub(crate) consequence: Consequence,
}

impl Violation {
    /// RFC 8210 §5.1: Session ID mismatch ⇒ "MUST immediately terminate the
    /// session with an Error Report PDU with code 0 ("Corrupt Data"), and the
    /// router MUST flush all data learned from that cache."
    fn session_mismatch(expected: SessionId, got: u16) -> Self {
        Self {
            error: RtrError::SessionIdMismatch {
                expected: expected.get(),
                got,
            },
            report: Some(ErrorReportSpec {
                code: ERROR_CODE_CORRUPT_DATA,
                text: "session ID mismatch",
            }),
            consequence: Consequence::Flush,
        }
    }

    /// RFC 8210 §7: a PDU at another version after negotiation ⇒ "MUST drop
    /// the session; ... SHOULD send an Error Report with an error code of 8".
    fn unexpected_version(expected: RtrVersion, got: RtrVersion) -> Self {
        Self {
            error: RtrError::UnexpectedVersion { expected, got },
            report: Some(ErrorReportSpec {
                code: ERROR_CODE_UNEXPECTED_PROTOCOL_VERSION,
                text: "unexpected protocol version",
            }),
            consequence: Consequence::Drop,
        }
    }

    /// RFC 8210 §5.1/§7: the cache answered a resume at a lower version — a
    /// separate session. Terminate without a report (the cache did what §7
    /// explicitly permits) and start over from scratch.
    fn version_changed(resumed: RtrVersion, answered: RtrVersion) -> Self {
        Self {
            error: RtrError::VersionChanged { resumed, answered },
            report: None,
            consequence: Consequence::ForgetResume,
        }
    }

    fn plain(error: RtrError) -> Self {
        Self {
            error,
            report: None,
            consequence: Consequence::Drop,
        }
    }

    fn unexpected_pdu(expected: &'static str, got: &Pdu) -> Self {
        Self::plain(RtrError::UnexpectedPdu {
            expected,
            got: format!("{got:?}"),
        })
    }

    fn error_reported(error_code: u16, text: &str) -> Self {
        Self::plain(RtrError::ErrorReported {
            code: error_code,
            text: text.to_string(),
        })
    }
}

/// What a PDU received during an exchange means for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    /// Cache Response accepted: payload PDUs and an End of Data follow.
    Accepted {
        session: SessionId,
        /// `Some(proposed)` if the cache answered at a lower version than we
        /// proposed and we downgraded (RFC 8210 §7).
        downgraded_from: Option<RtrVersion>,
    },
    /// An IPv4/IPv6 Prefix PDU belonging to this transfer.
    Prefix,
    /// A PDU that is valid here but needs no action (Router Key, a
    /// consistent Serial Notify).
    Ignore,
    /// End of Data for this transfer, validated against its Cache Response.
    Complete {
        session: SessionId,
        serial: Serial,
        intervals: Option<EndOfDataIntervals>,
    },
    /// §8.3 Cache Reset in reply to a Serial Query: the incremental update
    /// cannot be served. The resume state is unusable; issue a Reset Query.
    ResetRequired,
    /// §8.4 / §12 Error Code 2: nothing to serve yet. Non-fatal; retry with a
    /// Reset Query after the retry interval.
    NoDataAvailable { text: String },
    /// §7: the cache rejected our version. Retry once at v0.
    DowngradeToV0 { text: String },
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    AwaitingResponse,
    Transfer { session: SessionId },
}

/// Decision logic for one query/response/transfer exchange.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Exchange {
    query: Query,
    negotiation: Negotiation,
    phase: Phase,
}

impl Exchange {
    pub(crate) fn new(query: Query, negotiation: Negotiation) -> Self {
        Self {
            query,
            negotiation,
            phase: Phase::AwaitingResponse,
        }
    }

    /// The negotiation state after the PDUs processed so far. The caller
    /// carries it into the next exchange on the same connection.
    pub(crate) fn negotiation(&self) -> Negotiation {
        self.negotiation
    }

    /// Interprets one PDU received after the query was sent. `wire_version`
    /// is the Protocol Version byte the PDU actually carried.
    pub(crate) fn on_pdu(
        &mut self,
        wire_version: RtrVersion,
        pdu: &Pdu,
    ) -> Result<Step, Violation> {
        match self.phase {
            Phase::AwaitingResponse => self.on_response(wire_version, pdu),
            Phase::Transfer { session } => self.on_transfer(session, wire_version, pdu),
        }
    }

    fn on_response(&mut self, wire: RtrVersion, pdu: &Pdu) -> Result<Step, Violation> {
        match pdu {
            // RFC 8210 §5.2/§7: a Serial Notify is the one PDU a cache may
            // send unprompted. During the initial negotiation it is ignored
            // outright; afterwards it is an ordinary PDU of the session and
            // must match its version and session.
            Pdu::SerialNotify { session_id, .. } => {
                if let Negotiation::Agreed(v) = self.negotiation {
                    if wire != v {
                        return Err(Violation::unexpected_version(v, wire));
                    }
                    if let Query::Serial(r) = self.query
                        && *session_id != r.session.get()
                    {
                        return Err(Violation::session_mismatch(r.session, *session_id));
                    }
                }
                Ok(Step::Ignore)
            }
            Pdu::CacheResponse { session_id } => {
                let downgraded_from = self.settle_version(wire)?;
                let session = SessionId::new(*session_id);
                if let Query::Serial(r) = self.query {
                    // §5.1: "routers MUST treat sessions with different
                    // Protocol Version fields as separate sessions".
                    if r.version != self.negotiation.version() {
                        return Err(Violation::version_changed(
                            r.version,
                            self.negotiation.version(),
                        ));
                    }
                    // §5.5: "In response to a Serial Query, the Session ID
                    // being the same reassures the router that the Serial
                    // Numbers are commensurate"; otherwise §5.1.
                    if r.session != session {
                        return Err(Violation::session_mismatch(r.session, *session_id));
                    }
                }
                self.phase = Phase::Transfer { session };
                Ok(Step::Accepted {
                    session,
                    downgraded_from,
                })
            }
            // RFC 8210 §5.3/§5.9/§8.3: "The cache may respond to a Serial
            // Query with a Cache Reset". Only a Serial Query can legitimately
            // draw one — a Reset Query already asks for everything, so a
            // Cache Reset in reply to it is a protocol violation (and
            // accepting it would let a broken cache spin the client in a
            // Reset Query loop).
            Pdu::CacheReset if matches!(self.query, Query::Serial(_)) => {
                self.settle_version(wire)?;
                Ok(Step::ResetRequired)
            }
            // The explicit-rejection path. Deliberately not gated on the
            // ErrorReport's own wire version: some servers echo the
            // rejection at the version they support (v0), others at the
            // version they received (v1). Only valid while negotiating — once
            // a version is agreed it is stable (§7), so a later "unsupported
            // version" is just a fatal error.
            Pdu::ErrorReport {
                error_code, text, ..
            } if *error_code == ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION
                && self.negotiation == Negotiation::Proposed(RtrVersion::V1) =>
            {
                Ok(Step::DowngradeToV0 { text: text.clone() })
            }
            // §12 Error Code 2 is the only non-fatal error code.
            Pdu::ErrorReport {
                error_code, text, ..
            } if *error_code == ERROR_CODE_NO_DATA_AVAILABLE => {
                Ok(Step::NoDataAvailable { text: text.clone() })
            }
            Pdu::ErrorReport {
                error_code, text, ..
            } => Err(Violation::error_reported(*error_code, text)),
            other => Err(Violation::unexpected_pdu("Cache Response", other)),
        }
    }

    fn on_transfer(
        &mut self,
        session: SessionId,
        wire: RtrVersion,
        pdu: &Pdu,
    ) -> Result<Step, Violation> {
        // An Error Report is reported as such whatever version it carries
        // (§7: no Error Report is sent in reply to an Error Report).
        if let Pdu::ErrorReport {
            error_code, text, ..
        } = pdu
        {
            return Err(Violation::error_reported(*error_code, text));
        }
        // §5.8: End of Data "Session ID and Protocol Version MUST be the same
        // as that of the corresponding Cache Response"; §7 for every other
        // PDU of the transfer.
        let agreed = self.negotiation.version();
        if wire != agreed {
            return Err(Violation::unexpected_version(agreed, wire));
        }
        match pdu {
            Pdu::Ipv4Prefix { .. } | Pdu::Ipv6Prefix { .. } => Ok(Step::Prefix),
            // Decoded-and-discarded — Phase 1 doesn't act on BGPsec keys.
            Pdu::RouterKey => Ok(Step::Ignore),
            Pdu::SerialNotify { session_id, .. } => {
                if *session_id == session.get() {
                    Ok(Step::Ignore)
                } else {
                    Err(Violation::session_mismatch(session, *session_id))
                }
            }
            Pdu::EndOfData {
                session_id,
                serial,
                intervals,
            } => {
                if *session_id != session.get() {
                    return Err(Violation::session_mismatch(session, *session_id));
                }
                Ok(Step::Complete {
                    session,
                    serial: Serial::new(*serial),
                    intervals: *intervals,
                })
            }
            // RFC 8210 §5.9 defines Cache Reset only as the reply to a Serial
            // Query, i.e. *instead of* a Cache Response; after one has been
            // accepted it is as unexpected as any other query-direction PDU.
            other => Err(Violation::unexpected_pdu(
                "Prefix, Router Key, Serial Notify, or End of Data",
                other,
            )),
        }
    }

    /// Applies RFC 8210 §7 to the Protocol Version of the first substantive
    /// PDU of an exchange. Returns `Some(proposed)` if it caused a downgrade.
    fn settle_version(&mut self, wire: RtrVersion) -> Result<Option<RtrVersion>, Violation> {
        match self.negotiation {
            Negotiation::Agreed(v) if wire == v => Ok(None),
            Negotiation::Agreed(v) => Err(Violation::unexpected_version(v, wire)),
            Negotiation::Proposed(p) if wire == p => {
                self.negotiation = Negotiation::Agreed(p);
                Ok(None)
            }
            // §7: "The cache may reply with a version 0 response. In this
            // case, the router MUST either downgrade to version 0 or
            // terminate the connection."
            Negotiation::Proposed(p) if wire < p => {
                self.negotiation = Negotiation::Agreed(wire);
                Ok(Some(p))
            }
            // A cache answering *above* the version we spoke is not a
            // downgrade; it is not something §7 permits.
            Negotiation::Proposed(p) => Err(Violation::unexpected_version(p, wire)),
        }
    }
}

/// What an unsolicited PDU received while idle (between exchanges) means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Idle {
    /// A consistent Serial Notify: poll now instead of waiting for the
    /// refresh timer (§5.2).
    Notify,
}

/// Validates a PDU received while idle against the agreed version and the
/// remembered session.
pub(crate) fn on_idle(
    agreed: RtrVersion,
    resume: Option<Resume>,
    wire: RtrVersion,
    pdu: &Pdu,
) -> Result<Idle, Violation> {
    if let Pdu::ErrorReport {
        error_code, text, ..
    } = pdu
    {
        return Err(Violation::error_reported(*error_code, text));
    }
    if wire != agreed {
        return Err(Violation::unexpected_version(agreed, wire));
    }
    match pdu {
        Pdu::SerialNotify { session_id, .. } => match resume {
            Some(r) if r.session.get() != *session_id => {
                Err(Violation::session_mismatch(r.session, *session_id))
            }
            _ => Ok(Idle::Notify),
        },
        other => Err(Violation::unexpected_pdu("Serial Notify", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::PrefixFlags;

    const V0: RtrVersion = RtrVersion::V0;
    const V1: RtrVersion = RtrVersion::V1;

    fn resume() -> Resume {
        Resume {
            version: V1,
            session: SessionId::new(1),
            serial: Serial::new(7),
        }
    }

    fn prefix() -> Pdu {
        Pdu::Ipv4Prefix {
            flags: PrefixFlags { announce: true },
            prefix_len: 24,
            max_len: 24,
            prefix: "192.0.2.0".parse().unwrap(),
            asn: 65001,
        }
    }

    fn eod(session_id: u16, version: RtrVersion) -> Pdu {
        Pdu::EndOfData {
            session_id,
            serial: 8,
            intervals: (version == V1).then_some(EndOfDataIntervals {
                refresh: 3600,
                retry: 600,
                expire: 7200,
            }),
        }
    }

    fn notify(session_id: u16) -> Pdu {
        Pdu::SerialNotify {
            session_id,
            serial: 9,
        }
    }

    fn reset_exchange(v: RtrVersion) -> Exchange {
        Exchange::new(Query::Reset, Negotiation::Proposed(v))
    }

    fn serial_exchange() -> Exchange {
        Exchange::new(Query::Serial(resume()), Negotiation::Proposed(V1))
    }

    /// An exchange already inside a transfer for session 1 at `v`.
    fn in_transfer(v: RtrVersion) -> Exchange {
        let mut ex = Exchange::new(Query::Reset, Negotiation::Proposed(v));
        ex.on_pdu(v, &Pdu::CacheResponse { session_id: 1 }).unwrap();
        ex
    }

    fn violation(r: Result<Step, Violation>) -> Violation {
        r.expect_err("expected a protocol violation")
    }

    // ── queries ──────────────────────────────────────────────────────────

    /// A serial of 0 is a legitimate value and must resume like any other —
    /// "no serial yet" is expressed by `Option<Resume>::None`, not a sentinel.
    #[test]
    fn serial_zero_is_a_valid_resume_point() {
        let r = Resume {
            serial: Serial::new(0),
            ..resume()
        };
        assert_eq!(
            Query::choose(Some(r), false).pdu(),
            Pdu::SerialQuery {
                session_id: 1,
                serial: 0
            }
        );
    }

    #[test]
    fn query_choice_follows_section_8_1() {
        assert_eq!(Query::choose(None, false), Query::Reset);
        assert_eq!(
            Query::choose(Some(resume()), false),
            Query::Serial(resume())
        );
        // Error Code 2 handling forces a Reset Query even with resume state.
        assert_eq!(Query::choose(Some(resume()), true), Query::Reset);
    }

    #[test]
    fn serial_query_pdu_carries_remembered_session_and_serial() {
        assert_eq!(
            Query::Serial(resume()).pdu(),
            Pdu::SerialQuery {
                session_id: 1,
                serial: 7
            }
        );
        assert_eq!(Query::Reset.pdu(), Pdu::ResetQuery);
    }

    // ── #87: Cache Reset ─────────────────────────────────────────────────

    /// RFC 8210 §8.3: Cache Reset is the cache's normal answer to a Serial
    /// Query.
    #[test]
    fn cache_reset_answers_serial_query() {
        assert_eq!(
            serial_exchange().on_pdu(V1, &Pdu::CacheReset).unwrap(),
            Step::ResetRequired
        );
    }

    /// §5.9: Cache Reset replies to a *Serial* Query. In reply to a Reset
    /// Query there is nothing to fall back to — reject it rather than loop.
    #[test]
    fn cache_reset_in_reply_to_reset_query_is_a_violation() {
        let v = violation(reset_exchange(V1).on_pdu(V1, &Pdu::CacheReset));
        assert!(matches!(v.error, RtrError::UnexpectedPdu { .. }));
        assert_eq!(v.consequence, Consequence::Drop);
    }

    // ── #90: version negotiation (RFC 8210 §7) ───────────────────────────

    #[test]
    fn cache_response_at_proposed_version_agrees_it() {
        let mut ex = reset_exchange(V1);
        let step = ex
            .on_pdu(V1, &Pdu::CacheResponse { session_id: 5 })
            .unwrap();
        assert_eq!(
            step,
            Step::Accepted {
                session: SessionId::new(5),
                downgraded_from: None
            }
        );
        assert_eq!(ex.negotiation(), Negotiation::Agreed(V1));
    }

    /// §7 case 2: "The cache may reply with a version 0 response. In this
    /// case, the router MUST either downgrade to version 0 or terminate."
    #[test]
    fn v0_reply_to_v1_reset_query_downgrades() {
        let mut ex = reset_exchange(V1);
        let step = ex
            .on_pdu(V0, &Pdu::CacheResponse { session_id: 5 })
            .unwrap();
        assert!(matches!(
            step,
            Step::Accepted {
                downgraded_from: Some(V1),
                ..
            }
        ));
        assert_eq!(ex.negotiation(), Negotiation::Agreed(V0));
    }

    /// A reply *above* the version spoken is not a downgrade.
    #[test]
    fn v1_reply_to_v0_query_is_rejected() {
        let v = violation(reset_exchange(V0).on_pdu(V1, &Pdu::CacheResponse { session_id: 5 }));
        assert!(matches!(v.error, RtrError::UnexpectedVersion { .. }));
        assert_eq!(
            v.report.unwrap().code,
            ERROR_CODE_UNEXPECTED_PROTOCOL_VERSION
        );
    }

    /// §7: "Once ... agreed ... that version is stable for the life of the
    /// session" — a later Cache Response at another version is rejected, with
    /// Error Report 8, and does not implicate the data.
    #[test]
    fn cache_response_at_other_version_after_agreement_is_rejected() {
        let mut ex = Exchange::new(Query::Reset, Negotiation::Agreed(V1));
        let v = violation(ex.on_pdu(V0, &Pdu::CacheResponse { session_id: 1 }));
        assert_eq!(
            v.report,
            Some(ErrorReportSpec {
                code: ERROR_CODE_UNEXPECTED_PROTOCOL_VERSION,
                text: "unexpected protocol version"
            })
        );
        assert_eq!(v.consequence, Consequence::Drop);
        assert!(matches!(
            v.error,
            RtrError::UnexpectedVersion {
                expected: V1,
                got: V0
            }
        ));
    }

    /// Cache Reset is a PDU of the session too.
    #[test]
    fn cache_reset_at_other_version_after_agreement_is_rejected() {
        let mut ex = Exchange::new(Query::Serial(resume()), Negotiation::Agreed(V1));
        let v = violation(ex.on_pdu(V0, &Pdu::CacheReset));
        assert!(matches!(v.error, RtrError::UnexpectedVersion { .. }));
    }

    /// Initial negotiation (valid): v1 rejected with Error Code 4 ⇒ fall back
    /// to v0.
    #[test]
    fn error_code_4_while_negotiating_v1_falls_back() {
        let step = reset_exchange(V1)
            .on_pdu(
                V0,
                &Pdu::ErrorReport {
                    error_code: ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION,
                    pdu_copy: vec![],
                    text: "v0 only".into(),
                },
            )
            .unwrap();
        assert_eq!(
            step,
            Step::DowngradeToV0 {
                text: "v0 only".into()
            }
        );
    }

    /// ...but only once: a v0 proposal rejected with code 4 is fatal, and so
    /// is code 4 after the version was agreed.
    #[test]
    fn error_code_4_is_fatal_unless_negotiating_v1() {
        let report = Pdu::ErrorReport {
            error_code: ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION,
            pdu_copy: vec![],
            text: String::new(),
        };
        for neg in [
            Negotiation::Proposed(V0),
            Negotiation::Agreed(V0),
            Negotiation::Agreed(V1),
        ] {
            let v = violation(Exchange::new(Query::Reset, neg).on_pdu(V1, &report));
            assert!(matches!(v.error, RtrError::ErrorReported { code: 4, .. }));
        }
    }

    /// §7: "The router MUST ignore any Serial Notify PDUs it might receive
    /// from the cache during this initial startup period, regardless of the
    /// Protocol Version field".
    #[test]
    fn serial_notify_is_ignored_during_negotiation_whatever_its_version_or_session() {
        for wire in [V0, V1] {
            for session in [1, 77] {
                for mut ex in [reset_exchange(V1), serial_exchange()] {
                    assert_eq!(ex.on_pdu(wire, &notify(session)).unwrap(), Step::Ignore);
                    assert_eq!(ex.negotiation(), Negotiation::Proposed(V1));
                }
            }
        }
    }

    /// After agreement a Serial Notify is an ordinary PDU of the session.
    #[test]
    fn serial_notify_after_agreement_is_checked() {
        let mut ex = Exchange::new(Query::Serial(resume()), Negotiation::Agreed(V1));
        assert_eq!(ex.on_pdu(V1, &notify(1)).unwrap(), Step::Ignore);
        let v = violation(ex.on_pdu(V0, &notify(1)));
        assert!(matches!(v.error, RtrError::UnexpectedVersion { .. }));
        let v = violation(ex.on_pdu(V1, &notify(2)));
        assert!(matches!(v.error, RtrError::SessionIdMismatch { .. }));
        assert_eq!(v.consequence, Consequence::Flush);
    }

    // ── #90: session identity (RFC 8210 §5.1) ────────────────────────────

    /// §5.1 + §5.5: Cache Response to a Serial Query for another session ⇒
    /// Error Report 0 and flush.
    #[test]
    fn cache_response_with_other_session_to_serial_query_is_corrupt_data() {
        let v = violation(serial_exchange().on_pdu(V1, &Pdu::CacheResponse { session_id: 99 }));
        assert_eq!(
            v.report,
            Some(ErrorReportSpec {
                code: ERROR_CODE_CORRUPT_DATA,
                text: "session ID mismatch"
            })
        );
        assert_eq!(v.consequence, Consequence::Flush);
        assert!(matches!(
            v.error,
            RtrError::SessionIdMismatch {
                expected: 1,
                got: 99
            }
        ));
    }

    /// §5.5: "In response to a Reset Query, the new value of the Session ID
    /// tells the router the instance of the cache session" — a new ID there
    /// is normal.
    #[test]
    fn cache_response_to_reset_query_may_carry_any_session() {
        assert!(matches!(
            reset_exchange(V1).on_pdu(V1, &Pdu::CacheResponse { session_id: 99 }),
            Ok(Step::Accepted { .. })
        ));
    }

    /// §5.1: sessions "with different Protocol Version fields" are separate
    /// sessions even with the same Session ID, so a v0 answer to a v1 resume
    /// can't be applied as a continuation — start over, keep the data.
    #[test]
    fn v0_answer_to_v1_resume_is_a_different_session() {
        let mut ex = serial_exchange();
        let v = violation(ex.on_pdu(V0, &Pdu::CacheResponse { session_id: 1 }));
        assert!(matches!(
            v.error,
            RtrError::VersionChanged {
                resumed: V1,
                answered: V0
            }
        ));
        assert_eq!(v.consequence, Consequence::ForgetResume);
        assert_eq!(v.report, None);
        // The version the cache actually speaks is remembered for the retry.
        assert_eq!(ex.negotiation().version(), V0);
    }

    /// §5.8: End of Data "Session ID and Protocol Version MUST be the same as
    /// that of the corresponding Cache Response".
    #[test]
    fn end_of_data_must_match_the_cache_response_session() {
        let mut ex = in_transfer(V1);
        let v = violation(ex.on_pdu(V1, &eod(2, V1)));
        assert_eq!(v.consequence, Consequence::Flush);
        assert_eq!(v.report.unwrap().code, ERROR_CODE_CORRUPT_DATA);
    }

    #[test]
    fn end_of_data_must_match_the_cache_response_version() {
        let mut ex = in_transfer(V1);
        let v = violation(ex.on_pdu(V0, &eod(1, V0)));
        assert!(matches!(v.error, RtrError::UnexpectedVersion { .. }));
        assert_eq!(
            v.report.unwrap().code,
            ERROR_CODE_UNEXPECTED_PROTOCOL_VERSION
        );
        assert_eq!(v.consequence, Consequence::Drop);
    }

    #[test]
    fn prefix_pdu_must_match_the_transfer_version() {
        let mut ex = in_transfer(V1);
        assert_eq!(ex.on_pdu(V1, &prefix()).unwrap(), Step::Prefix);
        let v = violation(ex.on_pdu(V0, &prefix()));
        assert!(matches!(v.error, RtrError::UnexpectedVersion { .. }));
    }

    #[test]
    fn matching_end_of_data_completes_with_its_serial_and_intervals() {
        let mut ex = in_transfer(V1);
        assert_eq!(
            ex.on_pdu(V1, &eod(1, V1)).unwrap(),
            Step::Complete {
                session: SessionId::new(1),
                serial: Serial::new(8),
                intervals: Some(EndOfDataIntervals {
                    refresh: 3600,
                    retry: 600,
                    expire: 7200
                })
            }
        );
    }

    #[test]
    fn v0_transfer_completes_without_intervals() {
        let mut ex = in_transfer(V0);
        assert!(matches!(
            ex.on_pdu(V0, &eod(1, V0)).unwrap(),
            Step::Complete {
                intervals: None,
                ..
            }
        ));
    }

    #[test]
    fn router_key_is_ignored_and_notifies_are_checked_mid_transfer() {
        let mut ex = in_transfer(V1);
        assert_eq!(ex.on_pdu(V1, &Pdu::RouterKey).unwrap(), Step::Ignore);
        assert_eq!(ex.on_pdu(V1, &notify(1)).unwrap(), Step::Ignore);
        let v = violation(ex.on_pdu(V1, &notify(3)));
        assert_eq!(v.consequence, Consequence::Flush);
    }

    /// RFC 8210 §5.9: Cache Reset answers a Serial Query; it is not a valid
    /// way to abort a transfer already begun with a Cache Response.
    #[test]
    fn cache_reset_mid_transfer_is_a_violation() {
        let mut ex = in_transfer(V1);
        let v = violation(ex.on_pdu(V1, &Pdu::CacheReset));
        assert!(matches!(v.error, RtrError::UnexpectedPdu { .. }));
        assert_eq!(v.consequence, Consequence::Drop);
    }

    #[test]
    fn error_report_mid_transfer_is_fatal_whatever_its_version() {
        let mut ex = in_transfer(V1);
        let v = violation(ex.on_pdu(
            V0,
            &Pdu::ErrorReport {
                error_code: 1,
                pdu_copy: vec![],
                text: "oops".into(),
            },
        ));
        assert!(matches!(v.error, RtrError::ErrorReported { code: 1, .. }));
        assert_eq!(v.report, None, "never answer an Error Report with one");
    }

    // ── idle phase ───────────────────────────────────────────────────────

    #[test]
    fn idle_serial_notify_for_the_remembered_session_triggers_a_poll() {
        assert_eq!(
            on_idle(V1, Some(resume()), V1, &notify(1)).unwrap(),
            Idle::Notify
        );
    }

    #[test]
    fn idle_serial_notify_at_other_version_is_error_8() {
        let v = on_idle(V1, Some(resume()), V0, &notify(1)).unwrap_err();
        assert_eq!(
            v.report.unwrap().code,
            ERROR_CODE_UNEXPECTED_PROTOCOL_VERSION
        );
        assert_eq!(v.consequence, Consequence::Drop);
    }

    #[test]
    fn idle_serial_notify_for_other_session_is_error_0_and_flush() {
        let v = on_idle(V1, Some(resume()), V1, &notify(2)).unwrap_err();
        assert_eq!(v.report.unwrap().code, ERROR_CODE_CORRUPT_DATA);
        assert_eq!(v.consequence, Consequence::Flush);
    }

    /// With no resume state (e.g. already invalidated) there is no session to
    /// contradict; the notify just prompts a (Reset) query.
    #[test]
    fn idle_serial_notify_without_resume_state_only_prompts_a_poll() {
        assert_eq!(on_idle(V1, None, V1, &notify(9)).unwrap(), Idle::Notify);
    }

    #[test]
    fn idle_non_notify_pdu_is_unexpected() {
        let v = on_idle(V1, Some(resume()), V1, &Pdu::CacheReset).unwrap_err();
        assert!(matches!(v.error, RtrError::UnexpectedPdu { .. }));
    }
}
