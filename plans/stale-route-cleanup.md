# Plan: Stale BGP Route Cleanup on Restart

## Motivation

When `pathvectord` crashes or restarts, routes it previously installed with
`RTPROT_BGP` linger in the Linux kernel routing table. During the BGP
reconvergence window those routes are stale — they may point to withdrawn
prefixes or dead next-hops. The fix is to delete all `RTPROT_BGP` routes from
the kernel at daemon startup, before any sessions connect.

This matches BIRD's default `krt` protocol behavior (flush kernel routes on
startup unless `learn` is configured). RFC 4724 graceful-restart (keep stale
routes intentionally during the restart window then diff-and-prune) is
explicitly deferred — that is a separate, larger feature.

## Approach

At startup the Loc-RIB is empty (no sessions have run yet), so every
`RTPROT_BGP` route in the kernel is by definition stale. No convergence
signaling is needed — dump and delete before the event loop starts.

Linux-only; the macOS stub returns empty lists and the cleanup loop is a no-op.

## Files to modify

### 1. `pathvector-sys/src/fib/linux.rs`

Add two `pub(super)` async functions that walk the kernel route table and
return NLRI lists for all routes with `RTPROT_BGP`, reusing the existing
`handle.route().get(IpVersion::V4/V6).execute()` pattern from `run()` but
filtering *for* `RTPROT_BGP` (inverse of the `is_bgp_route` exclusion in
`parse_v4/v6`):

```rust
pub(super) async fn dump_stale_bgp_v4(
    handle: &rtnetlink::Handle,
    table: RouteTable,
) -> Vec<Nlri<Ipv4Addr>>

pub(super) async fn dump_stale_bgp_v6(
    handle: &rtnetlink::Handle,
    table: RouteTable,
) -> Vec<Nlri<Ipv6Addr>>
```

### 2. `pathvector-sys/src/fib/mod.rs`

Add a public async method on `KernelFib` that opens a fresh rtnetlink
connection and returns the stale NLRI lists. The non-Linux stub returns
`(vec![], vec![])`.

```rust
pub async fn stale_bgp_nlris(&self) -> (Vec<Nlri<Ipv4Addr>>, Vec<Nlri<Ipv6Addr>>)
```

`pathvector-sys` remains read-only (reports what's stale; does not delete).
The daemon layer owns deletions via the existing `FibWriter`.

### 3. `pathvectord/src/daemon.rs` — `run_with()`

After `KernelFib::new()`, before `run_event_loop()`:

```rust
let (stale_v4, stale_v6) = kernel_fib.stale_bgp_nlris().await;
if !stale_v4.is_empty() || !stale_v6.is_empty() {
    tracing::info!(v4 = stale_v4.len(), v6 = stale_v6.len(), "removing stale BGP routes");
    let mut writer = FibWriter::new(fib_table, fib_metric)?;
    for nlri in stale_v4 {
        writer.withdraw_v4(nlri.addr(), nlri.prefix_len()).await?;
    }
    for nlri in stale_v6 {
        writer.withdraw_v6(nlri.addr(), nlri.prefix_len()).await?;
    }
}
```

`FibWriter::new`, `withdraw_v4`, and `withdraw_v6` all already exist in
`pathvectord/src/fib.rs` — no new write-path code needed.

## Tests

Unit tests in `pathvector-sys/src/fib/linux.rs` using the existing
mock-netlink-message style (see `bgp_route_identified_correctly` etc.):

- `dump_stale_bgp_v4_returns_bgp_route_nlri` — RTM_NEWROUTE with RTPROT_BGP → NLRI returned
- `dump_stale_bgp_v4_excludes_igp_routes` — RTPROT_OSPF route → empty result
- Same two tests for v6

E2e test (can be added after the implementation lands):
- After a GoBGP-to-pathvectord session establishes and a prefix is learned,
  assert `ip route show table 254` inside the pathvectord container contains
  the prefix; restart pathvectord; assert the stale route is removed before
  the session reconnects.

## Order of execution

1. `dump_stale_bgp_v4/v6` in `linux.rs` + unit tests
2. `KernelFib::stale_bgp_nlris()` in `mod.rs`
3. Cleanup call in `daemon.rs::run_with()`
4. `cargo fmt && cargo test -p pathvector-sys -p pathvectord`
5. Commit

## Related TODO entries

- TODO.md §FIB integration: "E2e test (Gap 8): after session ... assert ip route show"
