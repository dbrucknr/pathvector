//! Clap CLI struct definitions.
//!
//! All subcommand argument types live here so that `main.rs` stays focused on
//! dispatch logic and `output.rs` stays focused on formatting.

use clap::{Parser, Subcommand, ValueEnum};

/// BGP origin attribute for an originated route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum OriginArg {
    /// Interior Gateway Protocol (most common; use for static/originated routes).
    #[default]
    Igp,
    /// Exterior Gateway Protocol.
    Egp,
    /// Origin cannot be determined.
    Incomplete,
}

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

    /// Subscribe to live BGP events (streams to stdout; press Ctrl-C to stop).
    Watch {
        #[command(subcommand)]
        command: WatchCommands,
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

    /// Inject a locally originated route into the Loc-RIB.
    ///
    /// Idempotent: re-originating the same prefix replaces the existing route.
    /// Export policy still applies; the route is advertised to all eligible peers.
    Originate {
        /// Prefix in CIDR notation, e.g. 192.0.2.0/24 or 198.51.100.1/32.
        prefix: String,

        /// Next-hop IP address.
        #[arg(long, value_name = "IP")]
        next_hop: String,

        /// BGP origin attribute (default: igp).
        #[arg(long, value_enum, default_value_t = OriginArg::Igp)]
        origin: OriginArg,

        /// Standard community values in AS:value notation, e.g. 65000:666.
        /// May be repeated.
        #[arg(long = "community", value_name = "AS:VALUE")]
        communities: Vec<String>,

        /// Local preference (iBGP only).
        #[arg(long, value_name = "N")]
        local_pref: Option<u32>,

        /// Multi-exit discriminator.
        #[arg(long, value_name = "N")]
        med: Option<u32>,
    },

    /// Withdraw a locally originated route from the Loc-RIB.
    ///
    /// No-op if the prefix was not previously originated.
    Withdraw {
        /// Prefix in CIDR notation, e.g. 192.0.2.0/24.
        prefix: String,
    },

    /// List all locally originated routes.
    ListOriginated,
}

// ── watch subcommands ─────────────────────────────────────────────────────────

#[derive(Debug, Subcommand)]
pub enum WatchCommands {
    /// Stream live Loc-RIB changes to stdout.
    ///
    /// Delivers a snapshot of current best routes (CURRENT events), an
    /// `END_INITIAL` sentinel, then live ANNOUNCED/WITHDRAWN deltas until
    /// Ctrl-C or the daemon closes the stream.
    Routes {
        /// Filter the initial snapshot to routes from this peer address.
        /// Use "local" to see only locally originated routes.
        #[arg(long, value_name = "ADDRESS")]
        peer: Option<String>,
    },

    /// Stream live peer session changes to stdout.
    ///
    /// Delivers a snapshot of current peer states (CURRENT events), an
    /// `END_INITIAL` sentinel, then live CHANGED events until Ctrl-C or the
    /// daemon closes the stream.
    Peers,
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

    #[test]
    fn route_originate_defaults() {
        let cli = Cli::parse_from([
            "pathvector",
            "route",
            "originate",
            "192.0.2.0/24",
            "--next-hop",
            "10.0.0.1",
        ]);
        if let Commands::Route {
            command:
                RouteCommands::Originate {
                    origin,
                    communities,
                    local_pref,
                    med,
                    ..
                },
        } = cli.command
        {
            assert_eq!(origin, OriginArg::Igp);
            assert!(communities.is_empty());
            assert!(local_pref.is_none());
            assert!(med.is_none());
        } else {
            panic!("expected Originate");
        }
    }

    #[test]
    fn route_originate_all_flags() {
        let cli = Cli::parse_from([
            "pathvector",
            "route",
            "originate",
            "198.51.100.1/32",
            "--next-hop",
            "10.0.0.1",
            "--origin",
            "incomplete",
            "--community",
            "65000:666",
            "--local-pref",
            "200",
            "--med",
            "50",
        ]);
        if let Commands::Route {
            command:
                RouteCommands::Originate {
                    prefix,
                    next_hop,
                    origin,
                    communities,
                    local_pref,
                    med,
                },
        } = cli.command
        {
            assert_eq!(prefix, "198.51.100.1/32");
            assert_eq!(next_hop, "10.0.0.1");
            assert_eq!(origin, OriginArg::Incomplete);
            assert_eq!(communities, vec!["65000:666"]);
            assert_eq!(local_pref, Some(200));
            assert_eq!(med, Some(50));
        } else {
            panic!("expected Originate");
        }
    }

    #[test]
    fn route_withdraw_parses() {
        let cli = Cli::parse_from(["pathvector", "route", "withdraw", "192.0.2.0/24"]);
        assert!(matches!(
            cli.command,
            Commands::Route {
                command: RouteCommands::Withdraw { .. }
            }
        ));
    }

    #[test]
    fn route_list_originated_parses() {
        let cli = Cli::parse_from(["pathvector", "route", "list-originated"]);
        assert!(matches!(
            cli.command,
            Commands::Route {
                command: RouteCommands::ListOriginated
            }
        ));
    }

    #[test]
    fn watch_routes_no_filter() {
        let cli = Cli::parse_from(["pathvector", "watch", "routes"]);
        if let Commands::Watch {
            command: WatchCommands::Routes { peer },
        } = cli.command
        {
            assert!(peer.is_none());
        } else {
            panic!("expected Watch Routes");
        }
    }

    #[test]
    fn watch_routes_with_peer_filter() {
        let cli = Cli::parse_from(["pathvector", "watch", "routes", "--peer", "10.0.0.1"]);
        if let Commands::Watch {
            command: WatchCommands::Routes { peer },
        } = cli.command
        {
            assert_eq!(peer.as_deref(), Some("10.0.0.1"));
        } else {
            panic!("expected Watch Routes --peer");
        }
    }

    #[test]
    fn watch_peers_parses() {
        let cli = Cli::parse_from(["pathvector", "watch", "peers"]);
        assert!(matches!(
            cli.command,
            Commands::Watch {
                command: WatchCommands::Peers
            }
        ));
    }
}
