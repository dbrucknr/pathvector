# pathvector-client

Typed async Rust client for the `pathvectord` gRPC management API.

Use this crate to embed BGP operational data into your own Rust application — query
peers and routes, stream live changes, originate routes, or change policy at runtime,
all without shelling out to the `pathvector` CLI.

---

## What does this crate do?

`pathvectord` exposes three gRPC services (Peer, RIB, Policy, Origination, Watch). This
crate wraps those services in a typed, async Rust API so you never have to write Protobuf
or gRPC boilerplate. It also provides:

- **`DaemonClient` trait** — the abstract interface. Write code against the trait; inject
  a real client in production and a `MockDaemonClient` in tests.
- **`PathvectorClient`** — the concrete gRPC implementation.
- **`types` module** — decoded response types (`PeerState`, `Route`, `RouteEvent`, etc.)
  that are plain Rust structs with no Protobuf imports.

---

## Quick start

```rust,no_run
use pathvector_client::{DaemonClient, PathvectorClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = PathvectorClient::connect("http://127.0.0.1:50051")?;

    // List all BGP peers
    for peer in client.list_peers().await? {
        println!("{} — {:?}", peer.address, peer.session_state);
    }

    // Get all best routes
    for route in client.list_routes(None).await? {
        println!("{} via {}", route.prefix, route.next_hop);
    }

    Ok(())
}
```

---

## `DaemonClient` trait

All methods are `async`. The trait is `Send + 'static` so implementations work across
thread and task boundaries.

```rust,no_run
use std::net::IpAddr;
use pathvector_client::{DaemonClient, types::{PeerState, Route, RouteEvent, PeerEvent}};
use pathvector_client::error::ClientError;

// The trait provides:
async fn list_peers(client: &mut impl DaemonClient) -> Result<Vec<PeerState>, ClientError> {
    client.list_peers().await
}
```

### Available methods

| Method | Description |
|---|---|
| `list_peers()` | All configured peers and their session state |
| `get_peer(addr)` | One peer by IP address; `NOT_FOUND` if not configured |
| `list_routes(peer)` | Best routes in Loc-RIB, optionally filtered by peer IP |
| `list_all_routes(peer)` | Like `list_routes` but follows pagination transparently |
| `get_best_route(prefix)` | Best route for a CIDR prefix, or `None` if absent |
| `list_candidates(prefix)` | All candidate routes for a prefix (all peers, not just best) |
| `set_import_default(peer, accept)` | Change import policy default at runtime |
| `set_export_default(peer, accept)` | Change export policy default at runtime |
| `originate_route(params)` | Inject a route from the daemon into the Loc-RIB |
| `originate_routes(vec)` | Batch origination |
| `withdraw_originated_route(prefix)` | Withdraw a previously originated route |
| `withdraw_originated_routes(vec)` | Batch withdrawal |
| `list_originated_routes()` | All currently originated routes |
| `watch_routes(peer)` | Stream live RIB changes (snapshot + deltas) |
| `watch_peers()` | Stream live peer state changes |
| `add_peer(params)` | Add a peer at runtime without restarting the daemon |
| `remove_peer(addr)` | Remove a peer and withdraw all its routes from the Loc-RIB |

---

## Streaming with `watch_routes`

`watch_routes` returns a `BoxStream` of `RouteEvent` values. The stream opens with a
snapshot of the current RIB (`Current` events), then signals `EndInitial`, then streams
`Announced` and `Withdrawn` events as the RIB changes.

```rust,no_run
use futures::StreamExt;
use pathvector_client::{DaemonClient, PathvectorClient, types::RouteEventType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = PathvectorClient::connect("http://127.0.0.1:50051")?;
    let mut stream = client.watch_routes(None).await?;

    while let Some(event) = stream.next().await {
        let event = event?;
        match event.event_type {
            RouteEventType::Current | RouteEventType::Announced => {
                if let Some(route) = event.route {
                    println!("+ {} via {}", route.prefix, route.next_hop);
                }
            }
            RouteEventType::Withdrawn => {
                println!("- {}", event.withdrawn_prefix.unwrap_or_default());
            }
            RouteEventType::EndInitial => {
                println!("--- initial snapshot complete ---");
            }
            _ => {}
        }
    }
    Ok(())
}
```

---

## Originating routes

```rust,no_run
use std::net::Ipv4Addr;
use pathvector_client::{DaemonClient, PathvectorClient, types::OriginateRouteParams};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = PathvectorClient::connect("http://127.0.0.1:50051")?;

    client.originate_route(OriginateRouteParams {
        prefix:   "203.0.113.0/24".to_owned(),
        next_hop: "10.0.0.2".to_owned(),
        med:      None,
    }).await?;

    println!("Route originated.");
    Ok(())
}
```

---

## Dynamic peer management

Add or remove peers at runtime without restarting the daemon. All other sessions
remain unaffected.

```rust,no_run
use std::net::{IpAddr, Ipv4Addr};
use pathvector_client::{DaemonClient, PathvectorClient, types::AddPeerParams};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = PathvectorClient::connect("http://127.0.0.1:50051")?;

    // Add an eBGP peer — sessions starts immediately
    client.add_peer(AddPeerParams {
        address:        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        remote_as:      65003,
        port:           None,           // defaults to 179
        import_default: Some(true),     // accept all routes from this peer
        export_default: Some(true),     // advertise all best routes to this peer
        md5_password:   None,           // no TCP MD5
    }).await?;

    println!("Peer added.");

    // Later: remove the peer — routes are withdrawn from the Loc-RIB first
    client.remove_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))).await?;

    println!("Peer removed.");
    Ok(())
}
```

`add_peer` is idempotent — calling it for an existing peer is a no-op. `remove_peer`
returns an error with `NOT_FOUND` if the address is not a configured peer.

`import_default` / `export_default`:
- `None` — RFC 8212 default (reject for eBGP, accept for iBGP)
- `Some(true)` — accept all routes / advertise all best routes by default
- `Some(false)` — reject all routes / advertise nothing by default

---

## Testing with `DaemonClient`

Write your application code against `impl DaemonClient`. In tests, inject a
`MockDaemonClient` from `pathvector/src/client_trait.rs` (or write your own) instead of
connecting to a live daemon.

```rust,ignore
// Application code
async fn show_established_peers(client: &mut impl DaemonClient) -> Vec<String> {
    client.list_peers().await
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.session_state == SessionState::Established)
        .map(|p| p.address.to_string())
        .collect()
}

// Test — no daemon, no network
#[tokio::test]
async fn only_established_peers_are_shown() {
    let mut mock = MockDaemonClient::new();
    mock.peers = vec![
        PeerState { address: "10.0.0.1".to_owned(), session_state: SessionState::Established, .. },
        PeerState { address: "10.0.0.2".to_owned(), session_state: SessionState::Idle, .. },
    ];
    let result = show_established_peers(&mut mock).await;
    assert_eq!(result, ["10.0.0.1"]);
}
```

---

## Error types

All methods return `Result<_, ClientError>`.

| Variant | When |
|---|---|
| `ClientError::Rpc(tonic::Status)` | The daemon returned a gRPC error (NOT_FOUND, INVALID_ARGUMENT, etc.) |
| `ClientError::Convert(ConvertError)` | A proto response could not be decoded into the Rust type |

`ConnectError` is returned only by `PathvectorClient::connect` and indicates an invalid
endpoint URI — not a connection failure (the gRPC channel is lazy).

---

## Running tests

```bash
cargo test -p pathvector-client
```

---

## License

MIT
