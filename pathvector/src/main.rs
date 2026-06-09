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
mod dashboard;
mod error;
mod output;

use std::net::IpAddr;

use clap::Parser;
use pathvector_client::PathvectorClient;

use cli::{Cli, Commands, PeerCommands, PolicyCommands, RouteCommands};
use error::CliError;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), CliError> {
    let args = Cli::parse();
    let addr = args.address.clone();

    match args.command {
        // Dashboard spins up its own client internally.
        Commands::Dashboard => {
            dashboard::run_dashboard(addr).await?;
        }

        // All other subcommands share a single client connection.
        Commands::Peer { command } => {
            let mut client = PathvectorClient::connect(&addr)?;
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
            let mut client = PathvectorClient::connect(&addr)?;
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
            let mut client = PathvectorClient::connect(&addr)?;
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
