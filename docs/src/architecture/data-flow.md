# Data Flow

> This chapter summarises the two primary data paths through the system.
> For the full annotated walkthrough with code references, see
> [Architecture](README.md).

## Inbound: peer UPDATE → Loc-RIB

```
Peer TCP socket
  │  raw bytes
  ▼
BgpCodec::decode         pathvector-session
  │  BgpMessage::Update
  ▼
Fsm::on_update           pathvector-session
  │  SessionEvent::RouteAnnounced / RouteWithdrawn
  ▼
DaemonState::handle_update              pathvectord
  ├── BLACKHOLE check (RFC 7999)
  ├── AdjRibIn::insert  (pre-policy store for soft reconfig)
  ├── Policy::evaluate  (import policy — RFC 8212 default-reject for eBGP)
  │     Accept → LocRib::insert → best-path recompute
  │     Reject → route stored in AdjRibIn only
  └── propagate_prefix  (if best path changed)
        │
        ▼  [for each established peer]
      export Policy::evaluate
        Accept → AdjRibOut::insert → flush_updates → UPDATE sent
        Reject → route suppressed for that peer
```

## Outbound: origination → peer UPDATE

```
pathvector route originate <prefix>
  │  gRPC OriginateRequest
  ▼
RibService::originate_route             pathvectord/src/grpc.rs
  │
  ▼
DaemonState::originate_route
  ├── Build Route<Ipv4Addr> with ORIGIN=IGP, local AS_PATH
  ├── LocRib::insert  (originated routes win best-path over peers by RFC 4271)
  └── propagate_prefix → AdjRibOut → flush_updates → UPDATE sent to all peers
```

## What's not wired yet

The inbound path terminates at `LocRib`. Routes are queryable via the gRPC API
and reflected in the CLI and dashboard, but are not installed into the kernel's
forwarding table. **FIB integration (Netlink) is the next major milestone** and
will add a `FibManager` step after `LocRib::insert`.
