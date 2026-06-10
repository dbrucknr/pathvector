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
//!   peer list                                         List all configured peers
//!   peer get <ADDRESS>                                Show detailed state for one peer
//!   route list [--peer <ADDRESS>]                     List all best routes (optional peer filter)
//!   route best <PREFIX>                               Best route for a CIDR prefix
//!   route candidates <PREFIX>                         All candidate routes for a prefix
//!   route originate <PREFIX> --next-hop <IP> [opts]   Inject a locally originated route
//!   route withdraw <PREFIX>                           Withdraw a locally originated route
//!   route list-originated                             List all locally originated routes
//!   policy set-import <ADDR> <DECISION>               Change import-policy default (no session reset)
//!   policy set-export <ADDR> <DECISION>               Change export-policy default (no session reset)
//!   watch routes [--peer <ADDRESS>]                   Stream live Loc-RIB changes to stdout
//!   watch peers                                       Stream live peer session changes to stdout
//!   dashboard                                         Live-updating TUI (press q to quit)
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
use futures::StreamExt as _;
use pathvector_client::{PathvectorClient, types::OriginateRouteParams};

use cli::{Cli, Commands, OriginArg, PeerCommands, PolicyCommands, RouteCommands, WatchCommands};
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

    // Watch commands require PathvectorClient directly (streaming RPCs are not
    // on the DaemonClient trait), so they bypass run_with.
    if let Commands::Watch { command } = args.command {
        let mut client = PathvectorClient::connect(&args.address).map_err(CliError::from)?;
        return run_watch(&mut client, command).await;
    }

    run_with(
        args,
        |addr| PathvectorClient::connect(addr).map_err(CliError::from),
        dashboard::run_dashboard,
    )
    .await
}

/// Drive watch commands against a live `PathvectorClient`.
///
/// Streams events to stdout until the daemon closes the stream or the user
/// presses Ctrl-C.
async fn run_watch(client: &mut PathvectorClient, command: WatchCommands) -> Result<(), CliError> {
    match command {
        WatchCommands::Routes { peer } => {
            let mut stream = client.watch_routes(peer.as_deref()).await?;
            loop {
                tokio::select! {
                    item = stream.next() => {
                        match item {
                            Some(Ok(event)) => output::print_route_event(&event),
                            Some(Err(e)) => return Err(CliError::from(e)),
                            None => break,
                        }
                    }
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
        }
        WatchCommands::Peers => {
            let mut stream = client.watch_peers().await?;
            loop {
                tokio::select! {
                    item = stream.next() => {
                        match item {
                            Some(Ok(event)) => output::print_peer_event(&event),
                            Some(Err(e)) => return Err(CliError::from(e)),
                            None => break,
                        }
                    }
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
        }
    }
    Ok(())
}

/// Testable dispatch core.
///
/// Accepts a `connect` closure so that tests can inject a `MockDaemonClient`
/// without any network I/O, and a `run_dashboard_fn` so that tests can stub
/// the TUI dashboard without opening a real terminal.
///
/// Production code passes `dashboard::run_dashboard` directly.
#[allow(clippy::too_many_lines)]
async fn run_with<C, F, D, Fut>(args: Cli, connect: F, run_dashboard_fn: D) -> Result<(), CliError>
where
    C: DaemonClient,
    F: FnOnce(&str) -> Result<C, CliError>,
    D: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<(), CliError>>,
{
    let addr = args.address.as_str();

    match args.command {
        Commands::Dashboard => {
            run_dashboard_fn(args.address).await?;
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
                RouteCommands::Originate {
                    prefix,
                    next_hop,
                    origin,
                    communities,
                    local_pref,
                    med,
                } => {
                    let communities = communities
                        .iter()
                        .map(|s| parse_community(s))
                        .collect::<Result<Vec<u32>, _>>()?;
                    let params = OriginateRouteParams {
                        prefix,
                        next_hop,
                        origin: match origin {
                            OriginArg::Igp => pathvector_client::types::Origin::Igp,
                            OriginArg::Egp => pathvector_client::types::Origin::Egp,
                            OriginArg::Incomplete => pathvector_client::types::Origin::Incomplete,
                        },
                        communities,
                        large_communities: vec![],
                        extended_communities: vec![],
                        local_pref,
                        med,
                    };
                    client.originate_route(params).await?;
                }
                RouteCommands::Withdraw { prefix } => {
                    client.withdraw_originated_route(&prefix).await?;
                }
                RouteCommands::ListOriginated => {
                    let routes = client.list_originated_routes().await?;
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

        // Handled in `run()` before `run_with` is called; unreachable here.
        Commands::Watch { .. } => {}
    }

    Ok(())
}

/// Parse a community string in `AS:value` notation into a packed `u32`.
fn parse_community(s: &str) -> Result<u32, CliError> {
    let (as_part, val_part) = s.split_once(':').ok_or_else(|| {
        CliError::from(pathvector_client::error::ClientError::Rpc(
            tonic::Status::invalid_argument(format!(
                "'{s}' is not a valid community — expected AS:value notation"
            )),
        ))
    })?;
    let asn: u32 = as_part.parse().map_err(|_| {
        CliError::from(pathvector_client::error::ClientError::Rpc(
            tonic::Status::invalid_argument(format!("'{as_part}' is not a valid AS number")),
        ))
    })?;
    let val: u32 = val_part.parse().map_err(|_| {
        CliError::from(pathvector_client::error::ClientError::Rpc(
            tonic::Status::invalid_argument(format!("'{val_part}' is not a valid community value")),
        ))
    })?;
    if asn > 0xFFFF || val > 0xFFFF {
        return Err(CliError::from(pathvector_client::error::ClientError::Rpc(
            tonic::Status::invalid_argument(format!(
                "'{s}' — AS and value must both fit in 16 bits (0–65535)"
            )),
        )));
    }
    Ok((asn << 16) | val)
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

    // ── parse_community ───────────────────────────────────────────────────────

    #[test]
    fn parse_community_valid() {
        assert_eq!(parse_community("65000:666").unwrap(), (65000_u32 << 16) | 0x29A);
    }

    #[test]
    fn parse_community_zero_values() {
        assert_eq!(parse_community("0:0").unwrap(), 0);
    }

    #[test]
    fn parse_community_max_values() {
        assert_eq!(parse_community("65535:65535").unwrap(), 0xFFFF_FFFF);
    }

    #[test]
    fn parse_community_missing_colon() {
        assert!(parse_community("65000").is_err());
    }

    #[test]
    fn parse_community_non_numeric() {
        assert!(parse_community("abc:def").is_err());
    }

    #[test]
    fn parse_community_overflow() {
        assert!(parse_community("65536:0").is_err());
        assert!(parse_community("0:65536").is_err());
    }

    #[test]
    fn parse_community_bad_value() {
        assert!(parse_community("65000:abc").is_err());
    }

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
            peer_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
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
    ///
    /// The dashboard is stubbed as a no-op so that `Commands::Dashboard` can be
    /// tested without opening a real terminal.
    async fn run_cmd(args: &[&str], mock: MockDaemonClient) -> Result<(), CliError> {
        let cli = Cli::parse_from(args);
        run_with(cli, |_addr| Ok(mock), |_addr| async { Ok(()) }).await
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

    // ── route originate ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn route_originate_basic() {
        run_cmd(
            &[
                "pv",
                "route",
                "originate",
                "192.0.2.0/24",
                "--next-hop",
                "10.0.0.1",
            ],
            MockDaemonClient::new(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn route_originate_egp_origin() {
        run_cmd(
            &[
                "pv",
                "route",
                "originate",
                "192.0.2.0/24",
                "--next-hop",
                "10.0.0.1",
                "--origin",
                "egp",
            ],
            MockDaemonClient::new(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn route_originate_incomplete_origin() {
        run_cmd(
            &[
                "pv",
                "route",
                "originate",
                "192.0.2.0/24",
                "--next-hop",
                "10.0.0.1",
                "--origin",
                "incomplete",
            ],
            MockDaemonClient::new(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn watch_command_no_ops_in_run_with() {
        // Commands::Watch is handled before run_with in run(); passing it directly
        // to run_with hits the no-op arm and returns Ok.
        let cli = Cli::parse_from(["pv", "watch", "peers"]);
        run_with(
            cli,
            |_addr| Ok(MockDaemonClient::new()),
            |_addr| async { Ok(()) },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn route_originate_with_community() {
        run_cmd(
            &[
                "pv",
                "route",
                "originate",
                "192.0.2.0/24",
                "--next-hop",
                "10.0.0.1",
                "--community",
                "65000:666",
            ],
            MockDaemonClient::new(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn route_originate_invalid_community() {
        let err = run_cmd(
            &[
                "pv",
                "route",
                "originate",
                "192.0.2.0/24",
                "--next-hop",
                "10.0.0.1",
                "--community",
                "notvalid",
            ],
            MockDaemonClient::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("not a valid community"));
    }

    #[tokio::test]
    async fn route_originate_propagates_error() {
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::invalid_argument("bad prefix"),
        ));
        assert!(
            run_cmd(
                &[
                    "pv",
                    "route",
                    "originate",
                    "bad/prefix",
                    "--next-hop",
                    "10.0.0.1"
                ],
                mock,
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn route_originate_batch_propagates_error() {
        // originate_routes (batch) is not exposed as a CLI command but its mock
        // method must be reachable; exercise it via the trait directly.
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::unavailable("no daemon"),
        ));
        let err = mock.originate_routes(vec![]).await.unwrap_err();
        assert!(matches!(err, pathvector_client::error::ClientError::Rpc(_)));
    }

    // ── route withdraw ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn route_withdraw_basic() {
        run_cmd(
            &["pv", "route", "withdraw", "192.0.2.0/24"],
            MockDaemonClient::new(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn route_withdraw_propagates_error() {
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::unavailable("no daemon"),
        ));
        assert!(
            run_cmd(&["pv", "route", "withdraw", "192.0.2.0/24"], mock)
                .await
                .is_err()
        );
    }

    // ── route list-originated ─────────────────────────────────────────────────

    #[tokio::test]
    async fn route_list_originated_empty() {
        run_cmd(&["pv", "route", "list-originated"], MockDaemonClient::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn route_originate_batch_success() {
        let count = MockDaemonClient::new()
            .originate_routes(vec![])
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn route_withdraw_batch_success() {
        let count = MockDaemonClient::new()
            .withdraw_originated_routes(vec!["192.0.2.0/24".to_owned()])
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn route_withdraw_batch_propagates_error() {
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::unavailable("no daemon"),
        ));
        let err = mock.withdraw_originated_routes(vec![]).await.unwrap_err();
        assert!(matches!(err, pathvector_client::error::ClientError::Rpc(_)));
    }

    #[tokio::test]
    async fn route_list_originated_propagates_error() {
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::unavailable("no daemon"),
        ));
        assert!(
            run_cmd(&["pv", "route", "list-originated"], mock)
                .await
                .is_err()
        );
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

    // ── dashboard dispatch ────────────────────────────────────────────────────

    /// Verify that `Commands::Dashboard` is routed to `run_dashboard_fn`.
    /// The `connect` closure is never invoked for the dashboard command.
    /// The stub `run_dashboard_fn` returns `Ok(())` — no real terminal is opened.
    #[tokio::test]
    async fn dashboard_command_dispatches() {
        run_cmd(&["pv", "dashboard"], MockDaemonClient::new())
            .await
            .unwrap();
    }

    // ── MockDaemonClient error paths ──────────────────────────────────────────
    //
    // Each test covers the `return Err(e)` path inside the relevant mock method
    // when `force_error` is set.  Together with `peer_list_propagates_error` and
    // `refresh_sets_last_error_on_peer_failure` (which cover `list_peers` and
    // `list_routes`), these tests exhaust all six error branches in the mock.

    #[tokio::test]
    async fn peer_get_propagates_error() {
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::unavailable("no daemon"),
        ));
        assert!(
            run_cmd(&["pv", "peer", "get", "10.0.0.1"], mock)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn route_best_propagates_error() {
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::unavailable("no daemon"),
        ));
        assert!(
            run_cmd(&["pv", "route", "best", "192.0.2.0/24"], mock)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn route_candidates_propagates_error() {
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::unavailable("no daemon"),
        ));
        assert!(
            run_cmd(&["pv", "route", "candidates", "192.0.2.0/24"], mock)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn policy_set_import_propagates_error() {
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::unavailable("no daemon"),
        ));
        assert!(
            run_cmd(&["pv", "policy", "set-import", "10.0.0.1", "accept"], mock)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn policy_set_export_propagates_error() {
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::unavailable("no daemon"),
        ));
        assert!(
            run_cmd(&["pv", "policy", "set-export", "10.0.0.1", "reject"], mock)
                .await
                .is_err()
        );
    }

    /// Exercises the `ClientError::Convert` arm of `MockDaemonClient::check_error`.
    /// This path maps `Convert(c)` → `Rpc(internal(c.to_string()))` before returning
    /// the error to the caller.
    #[tokio::test]
    async fn convert_error_variant_propagates() {
        use pathvector_client::error::ConvertError;
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Convert(
            ConvertError::InvalidAddress("not-an-ip".to_owned()),
        ));
        let err = run_cmd(&["pv", "peer", "list"], mock).await.unwrap_err();
        // Convert is re-wrapped as an Rpc(internal) by check_error, so the
        // original message should appear in the Display output.
        assert!(
            err.to_string().contains("not-an-ip"),
            "convert error message must propagate: {err}"
        );
    }
}
