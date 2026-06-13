# Roadmap

pathvector is being built toward GoBGP feature parity for single-AS and eBGP
peering deployments. This page tracks the key milestones. The full detail behind
each item lives in `TODO.md` at the workspace root.

## Immediate (ready to implement now)

- **`on_terminated` RouteEvents** — when a peer session drops, `RouteEvent::Withdrawn`
  events are not emitted; the dashboard shows stale routes
- **Best-path step 8** — tie-break by lowest peer IP address (RFC 4271 §9.1);
  unblocked, two lines of code
- **Advertise `MultiProtocol(IPv4_UNICAST)` capability** — one-line RFC 4760
  compliance fix; causes GoBGP to exercise the MP_REACH_NLRI code path end-to-end

## Short-term

- **BIRD 2 interoperability** — run the existing 41 e2e scenarios against BIRD
  (stricter RFC compliance than GoBGP); likely to surface bugs GoBGP accepts silently
- **Criterion benchmark suite** — `select_best`, `LocRib::insert`, outbound pipeline;
  establishes performance baseline before optimisation

## Medium-term (biggest impact)

- **FIB integration (Netlink)** — install routes into the kernel's forwarding table;
  this is the gap between "BGP process" and "BGP router"; unlocks best-path step 1
- **Graceful Restart FSM (RFC 4724)** — hold stale routes during restart window;
  critical for production operational correctness
- **Route Reflector (RFC 4456)** — `ORIGINATOR_ID` and `CLUSTER_LIST`; required
  for iBGP deployments without full-mesh

## Longer horizon

- IPv6 BGP transport (TCP sessions over IPv6)
- Dynamic neighbors (accept by source prefix range)
- RPKI / Route Origin Validation (RFC 6811)
- BGP Monitoring Protocol (RFC 7854)
- ADD-PATH (RFC 7911)
- FRR and Arista cEOS interoperability

## RFC coverage

See [RFC Compliance](rfc-compliance.md) for the full status of every RFC
the workspace tracks.
