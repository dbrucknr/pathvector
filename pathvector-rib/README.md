# pathvector-rib

BGP Routing Information Base for the [pathvector](https://github.com/dbrucknr/pathvector) ecosystem.

---

## The three routing tables

BGP maintains three distinct routing tables per address family. Understanding
their roles is essential to understanding how BGP routers make decisions.

All three identify a destination by its **prefix**: address bits beyond the
prefix length are irrelevant (RFC 4271 §4.3, RFC 4760 §5), so `10.1.2.3/8` and
`10.0.0.0/8` insert, find and withdraw the same entry. `Nlri` itself keeps
whatever bits it was built with; the RIBs convert it to a crate-private
`CanonicalNlri` (the only constructor masks) before it becomes a key, and every
internal map is declared in terms of that type. Whatever comes back out —
`Route::nlri`, iterator keys, `BestPathChange` — is canonical.

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

Candidates whose `NEXT_HOP` the `NextHopOracle` reports unresolvable stay in the
candidate set (so they can be re-selected when they become resolvable) but are
excluded from selection, per RFC 4271 §9.1.2.

Every mutation (`insert`, `withdraw`, `withdraw_peer`, `recompute_all`)
returns a `BestPathChange` per affected prefix. The stream is a complete,
minimal delta of the best-path table: replaying it onto an empty map always
reproduces `best_routes()`. In particular, a prefix that had a best route and
is left with no feasible candidate — whether by an explicit withdrawal or by a
replacement route with an unresolvable `NEXT_HOP` — always yields `Withdrawn`,
and a prefix that never had a best route never does.

`LocRib::best_win_count(peer)` answers "how many prefixes does this peer
currently win?" in O(1). The winner map and the per-peer counts live in one
private type whose single mutator updates both, so the counts cannot drift from
the table; a property test checks them against a full recount after every step
of arbitrary insert / withdraw / peer-down / reachability sequences. Management
reads use it instead of scanning the table once per peer.

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
| 10 | BGP Identifier, or `ORIGINATOR_ID` if the route carries one (RFC 4456 §9) | lower (unknown ranks after every known identifier) |
| 10a | `CLUSTER_LIST` length (RFC 4456 §9; absent counts as 0) | shorter |
| 11 | Peer IP address | lower (final tie-breaker) |

Steps 1 (next-hop reachability) and 8 (IGP metric to next-hop) require IGP/FIB
integration and are deferred. See `TODO.md` for details.

**Route reflection.** RFC 4456 §9 amends the tie-breakers. If a route carries
`ORIGINATOR_ID`, that identifier "SHOULD be treated as the BGP Identifier of the
BGP speaker that has advertised the route". A route reflector's own identifier
therefore never decides between two reflected routes. A shorter `CLUSTER_LIST`
is then preferred before the peer address. The selector reads both from the
route (`Route::effective_router_id`, `Route::cluster_list_len`), so the caller
only has to store the attributes as received. `pathvectord` keeps them only
from iBGP peers (RFC 7606 §7.9/§7.10). A route with neither an
`ORIGINATOR_ID` nor a known peer BGP Identifier ranks after every route that
has one. Skipping the step instead would not be transitive across three
routes.

**Graceful Restart.** A route retained while a peer restarts is marked
`Staleness::GrStale`, but staleness is not a decision step: RFC 4724 §4.2
forbids differentiating stale routes "during forwarding", and RFC 9494 §1
states that "in conventional GR, route preference is not affected". A stale
route keeps winning on its `LOCAL_PREF` (and every later step) until the peer
replaces it, its End-of-RIB sweeps it, or the Restart Time expires. Staleness
is never advertised. Long-Lived GR (RFC 9494), which *does* make retained
routes least preferred, is not implemented.

---

## Types

| Type | Description |
|---|---|
| [`Route<A>`] | A concrete BGP route stored in the RIB; implements [`BgpRoute`](pathvector_policy::BgpRoute) |
| [`RouteBuilder<A>`] | Builder for constructing [`Route<A>`] values |
| [`Staleness`] | `Fresh` or `GrStale` (RFC 4724 §4.2); documents why staleness does not affect selection |
| [`EffectiveRouterId`] | The identifier best-path step (f) compares: `ORIGINATOR_ID` if carried, else the peer's BGP Identifier (RFC 4456 §9); ordered for preference |
| [`PeerId`] | A BGP peer identified by its IP address |
| [`AdjRibIn<A>`] | Per-peer inbound routing table (pre-policy) |
| [`LocRib<A>`] | Local routing table with best-path selection |
| [`AdjRibOut<A>`] | Per-peer outbound routing table (post-policy) |

---

## Benchmarks

Criterion benchmark groups measure the control-plane hot paths. Run them with:

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
| `select_best_reflected_tie` | 2 / 10 / 100 candidates | Candidates tied through step (e), so every comparison reaches the RFC 4456 §9 tie-breakers and (g) |
| `loc_rib_insert` | 10k / 100k / 500k prefixes | `LocRib::insert` + best-path recompute; simulates a RIB of increasing size up to ~½ a full internet table |
| `loc_rib_insert_steady` | 10k / 100k / 500k prefixes | Steady-state `LocRib::insert` on a RIB built once: `hot` (one prefix, winner flips) and `scattered` (stride over the whole table, cache-cold). Use this, not `loc_rib_insert`, to compare insert cost at 500k |
| `peer_win_count` | 100 / 1k / 10k / 100k / 1M prefixes | Per-peer win count: the old `best_routes()` scan vs `best_win_count`, plus the `LocRib::clone` that copy-on-write performs |
| `prefix_keyed_ops` | 100 / 1k / 10k prefixes, IPv4 and IPv6 | One pass of `insert` / `best` / `longest_match` / `withdraw` over every prefix, plus `AdjRibIn` and `AdjRibOut` insert + get + withdraw: the operations that build a storage key |
| `outbound_pipeline` | 1 / 10 / 50 peers | `prepare_outbound` + `AdjRibOut::insert` per peer; simulates the Update-Send Process for one prefix change |

All benchmarks are deterministic (no random input) and sized for M2 Max hardware.

---

## License

MIT
