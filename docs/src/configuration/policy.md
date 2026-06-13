# Policy Engine

> **Note:** This chapter is a stub. Full policy documentation — term conditions,
> actions, community matching, per-AFI overrides — is coming.

## RFC 8212 default behaviour

pathvector enforces RFC 8212 out of the box. For eBGP peers (peers in a
different AS), routes are **rejected by default** unless an explicit import or
export policy accepts them. iBGP peers (same AS) default to accept.

```toml
[[peers]]
address   = "10.0.0.1"
remote_as = 65001
# No import_default — eBGP peer, so routes are rejected by default (RFC 8212)
```

```toml
[[peers]]
address        = "10.0.0.1"
remote_as      = 65001
import_default = "accept"   # Explicit accept overrides the RFC 8212 default
export_default = "accept"
```

## Runtime policy changes

Import and export policy can be changed without restarting the session:

```sh
pathvector policy set-import 10.0.0.1 reject
pathvector policy set-import 10.0.0.1 accept
pathvector policy set-export 10.0.0.1 reject
```

When import policy changes, pathvector re-evaluates all routes stored in
Adj-RIB-In (soft reconfiguration) and installs or withdraws routes from
Loc-RIB without tearing down the BGP session.

## Per-AFI import policy

`import_default_v6` lets you accept IPv4 routes while applying different
semantics to IPv6 from the same peer:

```toml
[[peers]]
address           = "10.0.0.1"
remote_as         = 65001
import_default    = "accept"   # IPv4 routes accepted
import_default_v6 = "reject"   # IPv6 routes rejected
```
