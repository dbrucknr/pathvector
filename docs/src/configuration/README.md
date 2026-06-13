# Configuration

pathvectord is configured via a TOML file passed as the sole command-line argument:

```sh
pathvectord /etc/pathvectord.toml
```

The file has two top-level sections: `[daemon]` for global settings and one or
more `[[peers]]` tables for BGP neighbor configuration.

## Minimal example

```toml
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
bgp_port  = 179
grpc_port = 50051

[[peers]]
address        = "10.0.0.1"
remote_as      = 65001
import_default = "accept"
export_default = "accept"
```

See [TOML Reference](toml-reference.md) for every available field, and
[Policy Engine](policy.md) for how `import_default` and `export_default`
interact with RFC 8212.
