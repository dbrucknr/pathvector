//! Clap CLI struct definitions.
//!
//! All subcommand argument types live here so that `main.rs` stays focused on
//! dispatch logic and `output.rs` stays focused on formatting.

use clap::{Parser, Subcommand, ValueEnum};

/// CLI management tool for the pathvector BGP daemon.
///
/// Connects to a running `pathvectord` over its gRPC management API and
/// provides subcommands to inspect peers, query the Loc-RIB, adjust routing
/// policy at runtime, and display a live-updating dashboard.
#[derive(Debug, Parser)]
#[command(name = "pathvector", version, about, long_about = None)]
pub struct Cli {
    /// Daemon gRPC endpoint URI.
    ///
    /// Overrides the `PATHVECTOR_ADDRESS` environment variable.
    /// Defaults to `http://127.0.0.1:50051`.
    #[arg(
        long,
        global = true,
        env = "PATHVECTOR_ADDRESS",
        default_value = "http://127.0.0.1:50051",
        value_name = "URL"
    )]
    pub address: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Inspect BGP peer sessions.
    Peer {
        #[command(subcommand)]
        command: PeerCommands,
    },

    /// Query the Loc-RIB.
    Route {
        #[command(subcommand)]
        command: RouteCommands,
    },

    /// Manage routing policies at runtime (soft reconfiguration).
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// Live-updating TUI dashboard showing peers and routes (press q to quit).
    Dashboard,
}

// ── peer subcommands ──────────────────────────────────────────────────────────

#[derive(Debug, Subcommand)]
pub enum PeerCommands {
    /// List all configured BGP peers.
    List,

    /// Show detailed state for a single peer.
    Get {
        /// Peer IP address in dotted-decimal notation.
        address: String,
    },
}

// ── route subcommands ─────────────────────────────────────────────────────────

#[derive(Debug, Subcommand)]
pub enum RouteCommands {
    /// List all best routes in the Loc-RIB.
    List {
        /// Only show routes whose best-path winner is this peer.
        #[arg(long, value_name = "ADDRESS")]
        peer: Option<String>,
    },

    /// Show the best route for a CIDR prefix.
    Best {
        /// Prefix in CIDR notation, e.g. 10.0.0.0/8.
        prefix: String,
    },

    /// List all candidate routes for a CIDR prefix.
    Candidates {
        /// Prefix in CIDR notation, e.g. 10.0.0.0/8.
        prefix: String,
    },
}

// ── policy subcommands ────────────────────────────────────────────────────────

#[derive(Debug, Subcommand)]
pub enum PolicyCommands {
    /// Replace the import-policy default for a peer (soft reconfiguration).
    ///
    /// Re-evaluates the peer's Adj-RIB-In against the new policy and propagates
    /// any Loc-RIB changes to all established peers — no session reset required.
    SetImport {
        /// Peer IP address in dotted-decimal notation.
        address: String,
        /// New default action.
        decision: Decision,
    },

    /// Replace the export-policy default for a peer (soft reconfiguration).
    ///
    /// Re-evaluates the Loc-RIB for this peer against the new policy; the peer
    /// receives UPDATEs for newly accepted prefixes and WITHDRAWs for rejected
    /// ones — no session reset required.
    SetExport {
        /// Peer IP address in dotted-decimal notation.
        address: String,
        /// New default action.
        decision: Decision,
    },
}

/// Policy default action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Decision {
    /// Accept routes by default.
    Accept,
    /// Reject routes by default (RFC 8212 behaviour for eBGP).
    Reject,
}

impl Decision {
    /// Returns `true` for [`Decision::Accept`], `false` for [`Decision::Reject`].
    pub fn as_bool(self) -> bool {
        self == Self::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_debug_assert() {
        Cli::command().debug_assert();
    }

    #[test]
    fn decision_as_bool() {
        assert!(Decision::Accept.as_bool());
        assert!(!Decision::Reject.as_bool());
    }

    #[test]
    fn default_address() {
        let cli = Cli::parse_from(["pathvector", "peer", "list"]);
        assert_eq!(cli.address, "http://127.0.0.1:50051");
    }

    #[test]
    fn address_flag_override() {
        let cli = Cli::parse_from([
            "pathvector",
            "--address",
            "http://10.0.0.1:9090",
            "peer",
            "list",
        ]);
        assert_eq!(cli.address, "http://10.0.0.1:9090");
    }
}
