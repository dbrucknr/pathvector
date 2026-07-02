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

mod client;
mod error;
mod pdu;
mod table;

pub use client::{RtrClient, RtrConfig, RtrHandle, RtrStatus};
pub use error::{PduError, RtrError};
pub use pdu::RtrVersion;
pub use table::{RoaTable, RoaValidity};

#[cfg(any(test, feature = "test-util"))]
pub use client::for_testing;
#[cfg(any(test, feature = "test-util"))]
pub use pdu::decode_for_fuzzing;
