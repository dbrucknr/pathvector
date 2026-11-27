//! RPKI-to-Router (RTR) protocol client — RFC 8210 (v1) with RFC 6810 (v0) fallback.
//!
//! Connects to an external RPKI validator (Routinator, rpki-client, `OctoRPKI`, Cloudflare
//! gortr, etc.) over TCP, maintains a live Route Origin Authorization (ROA) validity
//! cache, and answers `(prefix, origin AS) -> Valid | Invalid | NotFound` queries per
//! RFC 6811 §2.
//!
//! This crate does not perform RPKI repository sync or certificate validation itself —
//! that is the external validator's job. It only speaks the RTR protocol to consume the
//! validator's output.
//!
//! Consistency guarantees (RFC 8210 §§4, 5.1, 6, 7): VRPs, serial, status and change
//! notifications are published together at End of Data; a failed transfer leaves the
//! previous generation intact; the negotiated protocol version and Session ID are
//! enforced on every PDU; and the data is discarded when the cache's Expire Interval
//! elapses without a completed sync (after which every validation is `NotFound`). See
//! the crate README for the details and the cost of staging.
//!
//! Input handling: PDUs are delimited by their Length field however the bytes arrive, and
//! a partly received PDU survives the refresh timer. A PDU that cannot be accepted — an
//! unknown type or protocol version, a wrong Length, or prefix lengths outside RFC 8210
//! §§5.1, 5.6 and 5.7 — is answered with the matching §12 Error Report (never when it is
//! itself an Error Report, §5.11) and ends the session without publishing any of that
//! transfer. The one exception: a Serial Notify of an unknown version during version
//! negotiation is ignored (§7).

mod cache;
mod client;
mod error;
mod frame;
mod pdu;
mod protocol;
mod table;
mod timers;
mod transport;
mod vrp;

#[cfg(test)]
mod regression_tests;

pub use cache::RtrStatus;
pub use client::{RtrClient, RtrConfig, RtrHandle};
pub use error::{PduError, RtrConfigError, RtrError, VrpError};
pub use pdu::RtrVersion;
pub use table::{RoaTable, RoaValidity};

#[cfg(any(test, feature = "test-util"))]
pub use client::for_testing;
#[cfg(any(test, feature = "test-util"))]
pub use frame::decode_for_fuzzing;
