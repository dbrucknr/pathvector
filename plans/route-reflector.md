# Plan: Route Reflector Correctness

## Motivation

Route reflection (RFC 4456) is implemented but has several known correctness gaps
that affect real deployments. These are not theoretical — any topology with a route
reflector and non-client iBGP peers will hit the initial-dump split-horizon bug
immediately on session establishment.

## Known gaps (priority order)

### Gap 1 — Split-horizon not applied during initial dump (HIGH)

**File:** `pathvectord/src/daemon.rs`, `on_established`  
**RFC:** 4456 §8

When a new peer reaches Established, `on_established` sends the full Loc-RIB
without applying RR non-client split-horizon. The check exists in
`propagate_to_all_peers` for incremental updates but is absent from the initial
dump. A non-client iBGP peer therefore receives routes learned from other
non-client iBGP peers in its initial dump — a routing loop risk.

Fix: extract the split-horizon predicate into a shared helper and call it in
`on_established` before sending each route from the dump.

### Gap 2 — eBGP routes not getting reflection attributes (HIGH)

**RFC:** 4456 §8

When an eBGP-learned route is reflected to iBGP clients, it does not receive
`ORIGINATOR_ID` or `CLUSTER_LIST`. RFC 4456 §8 requires these on *all* reflected
routes, including those learned from eBGP peers.

Fix: add `ORIGINATOR_ID` / `CLUSTER_LIST` stamping in `propagate_prefix` for the
RR reflecting path, not just for iBGP-learned routes.

### Gap 3 — IPv6 AdjRibOut not RR-aware (MEDIUM)

**File:** `pathvectord/src/daemon.rs`

`on_established` and `on_terminated` reset IPv6 `AdjRibOut` without calling
`new_reflecting`. `propagate_to_all_peers_v6` has no RR split-horizon logic.
IPv6 route reflection requires the same changes applied to IPv4.

Fix: mirror the IPv4 RR logic into the IPv6 path (same pattern, different
address type).

### Gap 4 — ORIGINATOR_ID loop detection (LOW)

**RFC:** 4456 §8 SHOULD

If a received `ORIGINATOR_ID` equals our own `bgp_id`, discard the UPDATE.
Currently only `CLUSTER_LIST` loop detection is implemented.

Fix: add the `ORIGINATOR_ID` check in `validate_update` alongside the existing
`CLUSTER_LIST` check.

### Gap 5 — CLUSTER_LIST loop detection scope (LOW)

The inbound loop check fires only for routes from RR clients. Routes from
non-client iBGP peers that carry a `CLUSTER_LIST` (already reflected by another
RR) should also be loop-checked before entering the Loc-RIB.

Fix: apply the `CLUSTER_LIST` loop check unconditionally for all iBGP peers, not
just clients.

## Tests needed

- `test_on_established_applies_rr_split_horizon` — seed Loc-RIB with a route
  learned from non-client iBGP peer A; call `on_established` for non-client iBGP
  peer B; assert peer B does NOT receive that route in the initial dump
- `test_ebgp_route_gets_reflection_attributes` — eBGP route reflected to iBGP
  client should carry `ORIGINATOR_ID` and `CLUSTER_LIST` in `AdjRibOut`
- `test_originator_id_loop_detection` — route with `ORIGINATOR_ID == bgp_id`
  should be discarded

## Order of execution

1. Fix Gap 1 (highest operational impact, has a test path)
2. Fix Gap 2 (correctness violation, affects all RR deployments)
3. Fix Gap 3 (mirrors Gap 1/2 for IPv6)
4. Fix Gap 4 and 5 (SHOULD-level, low risk of real-world impact)

## Related TODO entries

- TODO.md §Route reflector: items 1, 3, 4, 5, 6
