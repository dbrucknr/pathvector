# TOML Reference

> **Note:** This reference is a stub. Full field documentation with types,
> defaults, and examples is coming. The authoritative source until then is
> `pathvectord/src/config.rs`, which has inline doc comments on every field.

## `[daemon]`

| Field | Type | Default | Description |
|---|---|---|---|
| `local_as` | `u32` | required | Local AS number |
| `bgp_id` | `Ipv4Addr` | required | BGP router ID — must be a non-loopback address on the host |
| `bgp_port` | `u16` | `179` | TCP port to listen on for inbound BGP connections |
| `grpc_port` | `u16` | `50051` | TCP port for the gRPC management API |

## `[[peers]]`

| Field | Type | Default | Description |
|---|---|---|---|
| `address` | `Ipv4Addr` | required | Neighbor IP address |
| `remote_as` | `u32` | required | Neighbor AS number |
| `port` | `u16` | `179` | TCP port to dial |
| `import_default` | `"accept"` \| `"reject"` | eBGP: `"reject"`, iBGP: `"accept"` | Default import action when no policy term matches (RFC 8212) |
| `import_default_v6` | `"accept"` \| `"reject"` | falls back to `import_default` | Per-AFI override for IPv6 import default |
| `export_default` | `"accept"` \| `"reject"` | eBGP: `"reject"`, iBGP: `"accept"` | Default export action when no policy term matches (RFC 8212) |
| `md5_password` | `String` | none | TCP MD5 authentication key (RFC 2385); Linux only |
