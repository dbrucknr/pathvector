//! `pathvector` — CLI management tool for the pathvector BGP daemon.
//!
//! Connects to a running `pathvectord` over its gRPC management API.
//!
//! # Usage
//!
//! ```text
//! pathvector [--address <url>] <COMMAND>
//!
//! Commands:
//!   peer list                            List all configured peers
//!   peer get <ADDRESS>                   Show detailed state for one peer
//!   route list [--peer <ADDRESS>]        List all best routes (optional peer filter)
//!   route best <PREFIX>                  Best route for a CIDR prefix
//!   route candidates <PREFIX>            All candidate routes for a prefix
//!   policy set-import <ADDR> <DECISION>  Change import-policy default (no session reset)
//!   policy set-export <ADDR> <DECISION>  Change export-policy default (no session reset)
//!   dashboard                            Live-updating TUI (press q to quit)
//! ```
//!
//! The `--address` flag and `PATHVECTOR_ADDRESS` environment variable both
//! accept a URI such as `http://127.0.0.1:50051` (the default).

mod cli;
mod client_trait;
mod dashboard;
mod error;
mod output;

use std::net::IpAddr;

use clap::Parser;
use pathvector_client::PathvectorClient;

use cli::{Cli, Commands, PeerCommands, PolicyCommands, RouteCommands};
use client_trait::DaemonClient;
use error::CliError;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Entry point: parse the CLI then hand off to the testable core.
async fn run() -> Result<(), CliError> {
    let args = Cli::parse();
    run_with(args, |addr| {
        PathvectorClient::connect(addr).map_err(CliError::from)
    })
    .await
}

/// Testable dispatch core.
///
/// Accepts a `connect` closure so that tests can inject a `MockDaemonClient`
/// without any network I/O.  Production code passes a closure that wraps
/// [`PathvectorClient::connect`].
///
/// The `Dashboard` command does not go through `connect` — it creates its own
/// client inside [`dashboard::run_dashboard`] because the dashboard event loop
/// needs to reconnect on error and needs to own the client for the full
/// duration of the TUI session.
async fn run_with<C, F>(args: Cli, connect: F) -> Result<(), CliError>
where
    C: DaemonClient,
    F: FnOnce(&str) -> Result<C, CliError>,
{
    let addr = args.address.as_str();

    match args.command {
        // Dashboard spins up its own client internally.
        Commands::Dashboard => {
            dashboard::run_dashboard(args.address).await?;
        }

        Commands::Peer { command } => {
            let mut client = connect(addr)?;
            match command {
                PeerCommands::List => {
                    let peers = client.list_peers().await?;
                    output::print_peer_table(&peers);
                }
                PeerCommands::Get { address } => {
                    let ip: IpAddr = address.parse().map_err(|_| {
                        pathvector_client::error::ClientError::Rpc(tonic::Status::invalid_argument(
                            format!("'{address}' is not a valid IP address"),
                        ))
                    })?;
                    let peer = client.get_peer(ip).await?;
                    output::print_peer_detail(&peer);
                }
            }
        }

        Commands::Route { command } => {
            let mut client = connect(addr)?;
            match command {
                RouteCommands::List { peer } => {
                    let peer_filter = peer
                        .as_deref()
                        .map(|s| {
                            s.parse::<IpAddr>().map_err(|_| {
                                pathvector_client::error::ClientError::Rpc(
                                    tonic::Status::invalid_argument(format!(
                                        "'{s}' is not a valid IP address"
                                    )),
                                )
                            })
                        })
                        .transpose()?;
                    let routes = client.list_routes(peer_filter).await?;
                    output::print_route_table(&routes);
                }
                RouteCommands::Best { prefix } => match client.get_best_route(&prefix).await? {
                    Some(route) => output::print_route_detail(&route),
                    None => println!("No route for {prefix}."),
                },
                RouteCommands::Candidates { prefix } => {
                    let routes = client.list_candidates(&prefix).await?;
                    output::print_route_table(&routes);
                }
            }
        }

        Commands::Policy { command } => {
            let mut client = connect(addr)?;
            match command {
                PolicyCommands::SetImport { address, decision } => {
                    client
                        .set_import_default(&address, decision.as_bool())
                        .await?;
                }
                PolicyCommands::SetExport { address, decision } => {
                    client
                        .set_export_default(&address, decision.as_bool())
                        .await?;
                }
            }
        }
    }

    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use client_trait::MockDaemonClient;
    use pathvector_client::types::{
        AsSegment, AsSegmentType, Origin, PeerState, PeerType, Route, SessionState,
    };

    // ── Fixtures ──────────────────────────────────────────────────────────────

    fn make_peer() -> PeerState {
        PeerState {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            remote_as: 65001,
            local_as: 65002,
            session_state: SessionState::Established,
            peer_type: Some(PeerType::External),
            hold_time: 90,
            uptime_seconds: 3661,
            prefixes_received: 5,
            prefixes_accepted: 4,
            prefixes_advertised: 3,
        }
    }

    fn make_route() -> Route {
        Route {
            prefix: "192.0.2.0/24".to_owned(),
            peer_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            peer_type: PeerType::External,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            as_path: vec![AsSegment {
                kind: AsSegmentType::Sequence,
                asns: vec![65001],
            }],
            origin: Origin::Igp,
            local_pref: None,
            med: None,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            atomic_aggregate: false,
            aggregator: None,
        }
    }

    /// Helper: build `Cli` from a string slice and call `run_with` with a mock.
    async fn run_cmd(args: &[&str], mock: MockDaemonClient) -> Result<(), CliError> {
        let cli = Cli::parse_from(args);
        run_with(cli, |_addr| Ok(mock)).await
    }

    // ── peer list ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn peer_list_empty() {
        run_cmd(&["pv", "peer", "list"], MockDaemonClient::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn peer_list_with_peers() {
        let mut mock = MockDaemonClient::new();
        mock.peers = vec![make_peer()];
        run_cmd(&["pv", "peer", "list"], mock).await.unwrap();
    }

    #[tokio::test]
    async fn peer_list_propagates_error() {
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::unavailable("no daemon"),
        ));
        assert!(run_cmd(&["pv", "peer", "list"], mock).await.is_err());
    }

    // ── peer get ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn peer_get_found() {
        let mut mock = MockDaemonClient::new();
        mock.peers = vec![make_peer()];
        run_cmd(&["pv", "peer", "get", "10.0.0.1"], mock)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn peer_get_not_found() {
        // Empty mock: get_peer returns NOT_FOUND.
        let err = run_cmd(&["pv", "peer", "get", "10.0.0.1"], MockDaemonClient::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("peer not found"));
    }

    #[tokio::test]
    async fn peer_get_invalid_address() {
        // IP parsing error is caught before the gRPC call.
        let err = run_cmd(&["pv", "peer", "get", "not-an-ip"], MockDaemonClient::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not a valid IP address"));
    }

    // ── route list ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn route_list_empty() {
        run_cmd(&["pv", "route", "list"], MockDaemonClient::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn route_list_with_routes() {
        let mut mock = MockDaemonClient::new();
        mock.routes = vec![make_route()];
        run_cmd(&["pv", "route", "list"], mock).await.unwrap();
    }

    #[tokio::test]
    async fn route_list_peer_filter() {
        let mut mock = MockDaemonClient::new();
        mock.routes = vec![make_route()];
        run_cmd(&["pv", "route", "list", "--peer", "10.0.0.1"], mock)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn route_list_invalid_peer_filter() {
        let err = run_cmd(
            &["pv", "route", "list", "--peer", "bad"],
            MockDaemonClient::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("not a valid IP address"));
    }

    // ── route best ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn route_best_found() {
        let mut mock = MockDaemonClient::new();
        mock.best_route = Some(make_route());
        run_cmd(&["pv", "route", "best", "192.0.2.0/24"], mock)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn route_best_not_found() {
        // `best_route` is None — should print "No route for …" and exit Ok.
        run_cmd(
            &["pv", "route", "best", "192.0.2.0/24"],
            MockDaemonClient::new(),
        )
        .await
        .unwrap();
    }

    // ── route candidates ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn route_candidates_empty() {
        run_cmd(
            &["pv", "route", "candidates", "192.0.2.0/24"],
            MockDaemonClient::new(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn route_candidates_with_results() {
        let mut mock = MockDaemonClient::new();
        mock.candidates = vec![make_route()];
        run_cmd(&["pv", "route", "candidates", "192.0.2.0/24"], mock)
            .await
            .unwrap();
    }

    // ── policy set-import ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn policy_set_import_accept() {
        let mock = MockDaemonClient::new();
        run_cmd(&["pv", "policy", "set-import", "10.0.0.1", "accept"], mock)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn policy_set_import_reject() {
        run_cmd(
            &["pv", "policy", "set-import", "10.0.0.1", "reject"],
            MockDaemonClient::new(),
        )
        .await
        .unwrap();
    }

    // ── policy set-export ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn policy_set_export_accept() {
        run_cmd(
            &["pv", "policy", "set-export", "10.0.0.1", "accept"],
            MockDaemonClient::new(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn policy_set_export_reject() {
        run_cmd(
            &["pv", "policy", "set-export", "10.0.0.1", "reject"],
            MockDaemonClient::new(),
        )
        .await
        .unwrap();
    }
}
