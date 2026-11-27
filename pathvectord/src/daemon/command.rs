//! The driving port: what a management adapter may ask the daemon to do.

use std::net::IpAddr;

use crate::config;

/// Commands sent from the gRPC layer to the event loop for dynamic peer management.
///
/// The event loop owns all session handles and routing state; gRPC handlers send
/// commands rather than mutating state directly, which keeps the generics out of
/// the gRPC layer and avoids locking concerns.
pub(crate) enum DaemonCommand {
    /// Add a new peer at runtime.  The event loop spawns a session, registers
    /// all per-peer RIB/policy state, and updates the BGP listener map.
    AddPeer(config::PeerConfig),
    /// Remove an existing peer at runtime.  The event loop sends a Cease
    /// NOTIFICATION, withdraws all received routes, and cleans up all state.
    RemovePeer(IpAddr),
}
