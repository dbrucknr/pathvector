# Plan: IPv6 Interop E2E Tests

## Motivation

IPv6 NLRI exchange over IPv4 sessions (MP_REACH_NLRI / MP_UNREACH_NLRI) is
implemented and unit-tested, but there are no end-to-end tests that verify
pathvectord actually receives, processes, and withdraws IPv6 routes from a real
peer. BIRD and FRR e2e tests exist for IPv4; the IPv6 variants are missing.

## Scope

Add IPv6-session e2e tests for both BIRD and FRR peers. These tests exercise the
full stack: Docker containers, real BGP TCP sessions, MP_REACH_NLRI exchange, and
gRPC assertions via `PathvectorClient`.

Note: "IPv6 NLRI" here means IPv6 prefixes advertised over an IPv4 BGP session
(MP_BGP, RFC 4760). IPv6 BGP transport (TCP sessions over IPv6 addresses) is a
separate item tracked in TODO.md under `pathvectord → IPv6 BGP transport`.

## Files to create / modify

### Test harnesses

- **`e2e/src/bird.rs`** — add `BirdHarness::new_v6()` constructor that writes a
  config with `address-family ipv6` and announces an IPv6 prefix (e.g.
  `2001:db8::/32`)
- **`e2e/src/frr.rs`** — add `FrrHarness::new_v6()` constructor with equivalent
  FRR `address-family ipv6 unicast` config

### Test cases

- **`e2e/tests/bird_v6.rs`** (or add to `bird.rs`):
  - `test_bird_v6_route_received` — BIRD announces `2001:db8::/32`; assert
    `pathvector route list` shows it via gRPC
  - `test_bird_v6_route_withdrawn` — BIRD withdraws the prefix; assert it
    disappears from the Loc-RIB

- **`e2e/tests/frr_v6.rs`** (or add to `frr.rs`):
  - Same two tests driven by FRR

### Docker

The BIRD and FRR Dockerfiles (`e2e/Dockerfile.bird`, `e2e/Dockerfile.frr`) should
already support IPv6 config — verify that the containers have IPv6 addresses on
the bridge network and that Docker Buildx is configured for IPv6.

## Config snippets

**BIRD IPv6 peer config:**
```
protocol bgp gobgp_v6 {
    local as 65001;
    neighbor 10.0.0.2 as 65002;
    ipv6 {
        import all;
        export all;
    };
}
```

**FRR IPv6 peer config:**
```
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
 address-family ipv6 unicast
  network 2001:db8::/32
  neighbor 10.0.0.2 activate
 exit-address-family
```

**pathvectord config** — no changes needed; IPv6 NLRI is already accepted on
IPv4 sessions.

## Success criteria

- BIRD v6 test: `2001:db8::/32` appears in `PathvectorClient::list_routes_v6()`
  after session establishment
- FRR v6 test: same assertion
- Withdrawal tests: prefix disappears from gRPC list after peer withdraws it

## Order of execution

1. Add `BirdHarness::new_v6()` and smoke-test config locally
2. Write `test_bird_v6_route_received` + `test_bird_v6_route_withdrawn`
3. Add `FrrHarness::new_v6()` and mirror the tests
4. Confirm CI passes

## Related TODO entries

- TODO.md §Known coverage gaps: "No IPv6 route receive/withdraw tests for BIRD and FRR peers"
