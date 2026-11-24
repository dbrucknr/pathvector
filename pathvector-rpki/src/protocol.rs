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

use crate::{
    error::RtrError,
    pdu::{Pdu, RtrVersion},
};

/// RFC 8210 §12 error code 2 ("No Data Available") — the *only* error code
/// not marked "(fatal)".
pub(crate) const ERROR_CODE_NO_DATA_AVAILABLE: u16 = 2;
/// RFC 8210 §12 error code 4 ("Unsupported Protocol Version").
pub(crate) const ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION: u16 = 4;

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

/// What the first PDU received after a query means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Response {
    /// Cache Response: payload PDUs and an End of Data follow.
    Accepted {
        session: SessionId,
        /// Version the server actually used on the wire.
        version: RtrVersion,
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

/// Decision logic for one query/response exchange.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Exchange {
    query: Query,
    /// §7: a v1 attempt may fall back to v0 exactly once.
    may_fall_back: bool,
}

impl Exchange {
    pub(crate) fn new(query: Query, may_fall_back: bool) -> Self {
        Self {
            query,
            may_fall_back,
        }
    }

    /// Interprets the first PDU received after the query.
    pub(crate) fn on_response(
        &self,
        wire_version: RtrVersion,
        pdu: &Pdu,
    ) -> Result<Response, RtrError> {
        match pdu {
            Pdu::CacheResponse { session_id } => Ok(Response::Accepted {
                session: SessionId::new(*session_id),
                version: wire_version,
            }),
            // RFC 8210 §5.3/§5.9/§8.3: "The cache may respond to a Serial
            // Query with a Cache Reset". Only a Serial Query can legitimately
            // draw one — a Reset Query already asks for everything, so a
            // Cache Reset in reply to it is a protocol violation (and
            // accepting it would let a broken cache spin the client in a
            // Reset Query loop).
            Pdu::CacheReset if matches!(self.query, Query::Serial(_)) => {
                Ok(Response::ResetRequired)
            }
            // The explicit-rejection path. Deliberately not gated on the
            // ErrorReport's own wire version: some servers echo the
            // rejection at the version they support (v0), others at the
            // version they received (v1).
            Pdu::ErrorReport {
                error_code, text, ..
            } if *error_code == ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION && self.may_fall_back => {
                Ok(Response::DowngradeToV0 { text: text.clone() })
            }
            // §12 Error Code 2 is the only non-fatal error code.
            Pdu::ErrorReport {
                error_code, text, ..
            } if *error_code == ERROR_CODE_NO_DATA_AVAILABLE => {
                Ok(Response::NoDataAvailable { text: text.clone() })
            }
            Pdu::ErrorReport {
                error_code, text, ..
            } => Err(RtrError::ErrorReported {
                code: *error_code,
                text: text.clone(),
            }),
            other => Err(RtrError::UnexpectedPdu {
                expected: "Cache Response",
                got: format!("{other:?}"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resume() -> Resume {
        Resume {
            version: RtrVersion::V1,
            session: SessionId::new(1),
            serial: Serial::new(7),
        }
    }

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

    /// RFC 8210 §8.3: Cache Reset is the cache's normal answer to a Serial
    /// Query.
    #[test]
    fn cache_reset_answers_serial_query() {
        let ex = Exchange::new(Query::Serial(resume()), true);
        assert_eq!(
            ex.on_response(RtrVersion::V1, &Pdu::CacheReset).unwrap(),
            Response::ResetRequired
        );
    }

    /// §5.9: Cache Reset replies to a *Serial* Query. In reply to a Reset
    /// Query there is nothing to fall back to — reject it rather than loop.
    #[test]
    fn cache_reset_in_reply_to_reset_query_is_a_violation() {
        let ex = Exchange::new(Query::Reset, true);
        assert!(matches!(
            ex.on_response(RtrVersion::V1, &Pdu::CacheReset),
            Err(RtrError::UnexpectedPdu { .. })
        ));
    }
}
