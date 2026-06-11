# pathvector-rib

BGP Routing Information Base for the [pathvector](https://github.com/dbrucknr/pathvector) ecosystem.

---

## The three routing tables

BGP maintains three distinct routing tables per address family. Understanding
their roles is essential to understanding how BGP routers make decisions.

### Adj-RIB-In — the raw inbox

One table per peer. Routes are stored exactly as received from that peer,
before any import policy is applied. The session layer writes here when an
UPDATE arrives. Storing unfiltered routes matters: if you later change your
import policy you can re-process this table without asking the peer to
re-send anything.

### Loc-RIB — the decision table

The central routing table. For each prefix, Loc-RIB holds every candidate
route that passed import policy — one per peer that announced it. **Best-path
selection** runs across these candidates whenever the candidate set changes,
and the winning route is recorded as the current best. The best routes are
what the router uses for forwarding decisions and what it makes available to
export policy for redistribution to other peers.

### Adj-RIB-Out — the outbound view

One table per peer. Contains the routes that will be (or have been) advertised
to that peer, after export policy has been applied to the Loc-RIB's best
routes. What you advertise to peer A may differ from what you advertise to
peer B — communities may be stripped, next-hops rewritten, local-pref removed.
Adj-RIB-Out represents that per-peer view.

### Data flow

```text
Peer A --UPDATE--> AdjRibIn[A]
                        |
                   import policy        (applied by the caller, not by the RIB)
                        |
                        v
                      LocRib  --best-path selection--> best route per prefix
                        |
                   export policy        (applied by the caller, not by the RIB)
                        |
                        v
                   AdjRibOut[B] --UPDATE--> Peer B
```

Policy is applied **externally** — the RIB stores and selects; the caller
decides what to accept and what to send. This keeps `pathvector-rib`
independent of any specific policy configuration.

---

## Best-path selection

When Loc-RIB has multiple candidates for the same prefix (one from each peer
that announced it), it must choose one best route. The algorithm follows
RFC 4271 §9.1. The steps implemented in this crate:

| Step | Criterion | Winner |
|---|---|---|
| 2 | `LOCAL_PREF` | higher (missing → treated as 100) |
| 3/7 | Route source | locally originated > eBGP > iBGP |
| 4 | AS path length | shorter (confederation segments count as 0) |
| 5 | `ORIGIN` | lower (IGP=0 best, then EGP=1, then INCOMPLETE=2) |
| 6 | `MED` | lower (missing → treated as 0) |
| 9 | Route age | oldest eBGP route (only when both candidates are eBGP) |
| 10 | Peer IP address | lower (final tie-breaker) |

Steps 1 (next-hop reachability) and 8 (IGP metric to next-hop) require IGP/FIB
integration and are deferred. See `TODO.md` for details.

---

## Types

| Type | Description |
|---|---|
| [`Route<A>`] | A concrete BGP route stored in the RIB; implements [`BgpRoute`](pathvector_policy::BgpRoute) |
| [`RouteBuilder<A>`] | Builder for constructing [`Route<A>`] values |
| [`PeerId`] | A BGP peer identified by its IP address |
| [`AdjRibIn<A>`] | Per-peer inbound routing table (pre-policy) |
| [`LocRib<A>`] | Local routing table with best-path selection |
| [`AdjRibOut<A>`] | Per-peer outbound routing table (post-policy) |

---

## Benchmarks

Three Criterion benchmark groups measure the control-plane hot paths. Run them with:

```bash
cargo bench -p pathvector-rib
```

To run a single group:

```bash
cargo bench -p pathvector-rib -- select_best
cargo bench -p pathvector-rib -- loc_rib_insert
cargo bench -p pathvector-rib -- outbound_pipeline
```

HTML reports are written to `target/criterion/` when gnuplot or the plotters backend
is available. To compare two runs (e.g. before and after a change):

```bash
cargo bench -p pathvector-rib -- --save-baseline before
# make your change
cargo bench -p pathvector-rib -- --baseline before
```

### Groups

| Group | Sizes | What it measures |
|---|---|---|
| `select_best` | 2 / 10 / 100 candidates | RFC 4271 §9.1 10-step comparison loop across competing routes for one prefix |
| `loc_rib_insert` | 10k / 100k / 500k prefixes | `LocRib::insert` + best-path recompute; simulates a RIB of increasing size up to ~½ a full internet table |
| `outbound_pipeline` | 1 / 10 / 50 peers | `prepare_outbound` + `AdjRibOut::insert` per peer; simulates the Update-Send Process for one prefix change |

All benchmarks are deterministic (no random input) and sized for M2 Max hardware.

---

## License

MIT
