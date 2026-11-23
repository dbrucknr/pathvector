# pathvector-sys

Linux kernel integration for the pathvector BGP stack: kernel FIB (routing table) access
via rtnetlink, and TCP MD5SIG socket option for RFC 2385 BGP session authentication.

This is the **only crate in the workspace that contains `unsafe` code**. All other crates
inherit `unsafe_code = "forbid"` from the workspace `Cargo.toml`. `pathvector-sys`
overrides this to `"allow"` and is the designated home for all syscall-level code.

---

## What does this crate do?

### Kernel FIB (Forwarding Information Base)

BGP does not just exchange routing information — it is supposed to install the best routes
into the kernel's routing table so the OS can actually forward packets. On Linux, this is
done via the **rtnetlink** interface.

`pathvector-sys` provides:

- **`KernelFib`** — watches for kernel route events and reads the current routing table
- **`FibWriter`** — installs (`RTPROT_BGP`) and removes BGP routes via rtnetlink

Routes installed by `pathvectord` use the `RTPROT_BGP` protocol identifier so they can
be distinguished from kernel-native (`KERNEL`), static (`STATIC`), or IGP routes (`OSPF`,
`ISIS`, etc.).

### TCP MD5SIG (RFC 2385)

BGP speakers can authenticate sessions by adding an HMAC-MD5 signature to every TCP
segment. This requires the `setsockopt(TCP_MD5SIG)` syscall on the listening and
connecting sockets. `pathvector-sys` provides `apply_tcp_md5sig` which wraps this call
and handles all validation.

---

## Platform scope

This crate is **Linux-only in production**. On non-Linux platforms:

- All FIB operations compile to no-ops
- `apply_tcp_md5sig` is a no-op (sessions establish without MD5 enforcement)
- All tests still compile and pass (the validation guards fire before any syscall)

This design lets `pathvectord` compile and run on macOS for development without needing
a Linux kernel.

The FIB and TCP MD5 paths are gated with `#[cfg(target_os = "linux")]`. On macOS, if you
configure `md5_password` on a peer, the socket option call is skipped and the session
establishes without authentication — which is the correct behaviour for a development host
that cannot enforce it.

---

## TCP MD5 (`apply_tcp_md5sig`)

```rust,ignore
// Called by pathvectord when configuring a peer with md5_password
apply_tcp_md5sig(&listener, &peer_addr, b"shared-bgp-secret")
```

### Validation

| Check | Condition | Result |
|---|---|---|
| Key length | > 80 bytes | `Err(InvalidInput)` — RFC 2385 §3 limit |
| Address family | IPv6 | `Err(Unsupported)` — not yet implemented |
| Syscall | `ENOPROTOOPT` / `EOPNOTSUPP` | `Ok(())` with a warning — kernel lacks `CONFIG_TCP_MD5SIG` |
| Syscall | Other OS error | `Err(Os(errno))` |
| Syscall | Success | `Ok(())` |

The graceful-degrade on `ENOPROTOOPT` is why the positive e2e test passes on macOS:
both sides have MD5 configured consistently, the no-op call succeeds, and the session
establishes without kernel-level authentication.

### Why a local `TcpMd5Sig` struct instead of `libc::tcp_md5sig`

`libc::tcp_md5sig` is not exposed on all Linux target architectures in all `libc`
versions (notably absent on `aarch64` in `libc 0.2.x`). The local definition in
`tcp.rs` matches `<linux/tcp.h>` exactly with documented field offsets and sizes, making
it both portable and auditable.

### Linux permissions

`setsockopt(TCP_MD5SIG)` requires `CAP_NET_ADMIN`. In production, run `pathvectord` as
root or grant the capability with `setcap cap_net_admin+ep ./target/release/pathvectord`.

---

## FIB

The FIB layer uses the [`rtnetlink`](https://docs.rs/rtnetlink) crate for async
netlink communication. Routes are installed with:

- Protocol: `RTPROT_BGP`
- Table: `RT_TABLE_MAIN` (or a configured alternate table)
- Metric: `0` (pathvectord does not set a kernel metric by default)

`RTPROT_BGP` is the IANA-assigned protocol ID for BGP routes. It lets operators
distinguish pathvectord-installed routes from other BGP implementations and from static
or IGP routes when running tools like `ip route show proto bgp`.

### Reading the kernel FIB: route identity

`KernelFib` keeps a `FibSnapshot` of the kernel routing table and answers next-hop
reachability and IGP-metric queries from its *tracked* routes: unicast, blackhole,
unreachable, prohibit and throw routes not installed by BGP (`RTPROT_BGP`).

A prefix does not identify a kernel route. Linux keeps several routes for one prefix,
and the snapshot stores each under the identity the kernel itself uses:

| Family | Slot (the kernel's grouping) | Route within the slot |
|---|---|---|
| IPv4 | table, prefix, TOS, priority (`fib_table_insert`: "[prefix,dscp,priority]") | type, protocol, scope, preferred source, next hop(s) |
| IPv6 | table, prefix, source prefix, metric (`fib6_add_rt2node`) | next hop (each ECMP sibling is its own route); type, protocol and preference are recorded but, as in `rt6_duplicate_nexthop`, not compared |

Prefixes are validated newtypes (`Ipv4Prefix`, `Ipv6Prefix`: length within range, no
host bits) and table IDs cannot be zero (`TableId`), so a route identity can only hold
values the kernel can report. `RTM_DELROUTE` removes exactly the route it names.
`RTM_NEWROUTE` with `NLM_F_REPLACE` displaces the route the kernel replaced, which never
gets an `RTM_DELROUTE` of its own.

Every route is mirrored, tracked or not, because the kernel's replace rules act on a
slot's real order: if a BGP alias sits ahead of a static alias, replacing the BGP alias
must leave the static one in place. Untracked routes are kept only as a 64-bit identity
hash. They never count for reachability and never signal a change, so BGP route churn
does not wake the decision process. The cost is memory proportional to the kernel
table: about 86 MB for 1M BGP routes in the tracked table (≈170 MB peak while the hash
table grows; release build, M2 Max). Inserts and deletes are hashed, about 0.26 µs each.

An IPv6 multipath message describes only its first leg; the other legs carry no protocol
of their own, and Linux lets one ECMP set mix static and BGP routes. Dumps do not help:
`fib6_dump_node` dumps a sibling set once and skips the other siblings. The dump of a
BGP-first static+BGP set is byte-for-byte the dump of an all-BGP set (a live test checks
this), so a policy has to decide what an unreported sibling is.

**Policy:** an unreported sibling takes the protocol of the sibling the message describes,
marked `protocol_inferred: true`, and a message that later reports its protocol replaces
the inference. ECMP sets are almost always installed by one daemon, so this is exact for
every single-protocol set, BGP or IGP. Those sets give the same answer after a restart's
dump as from live events, and the BGP exclusion holds for all-BGP ECMP sets. The
alternatives are worse in the common case: counting every unreported sibling as IGP makes
each all-BGP ECMP set count as IGP reachability after a restart, and counting none loses
the second path of every all-static set.

A lookup takes the longest matching prefix and, among its routes, the lowest priority,
as the kernel does. For IPv6, routes of that priority are then ranked by router
preference (`RTA_PREF`; `rt6_score_route` adds `IPV6_DECODE_PREF(pref) << 2`, and
`find_match` keeps only a strictly better score), and only then by list order. Negative
IPv6 routes are always medium preference: `ip6_route_info_create` overwrites a reject
route's flags with `RTF_REJECT | RTF_NONEXTHOP`, dropping `RTF_PREF`. IPv4 routes with a
non-zero TOS and IPv6 source-specific routes are kept but not selected, because a
best-effort lookup from an unspecified source cannot use them.
`FibSnapshot::routes_v4` / `routes_v6` list the tracked routes.

### Reading the kernel FIB: negative routes

The route is selected **before** its type is looked at, so a negative route beneath a
covering unicast route makes the destinations it covers unreachable. `ip-route(8)`:
blackhole, unreachable and prohibit destinations "are unreachable"; a selected throw
route ends the lookup in the table "pretending that no route was found". In the kernel,
`fib_table_lookup` returns the selected alias's `fib_props` error without backtracking to
a shorter prefix, and `fib6_table_lookup` only backtracks when a node yields no route.

`FibSnapshot::lookup_v4` / `lookup_v6` return a `FibLookup`:

| Selected route | `FibLookup` | Reachable | Kernel error for local senders |
|---|---|---|---|
| unicast | `Forward(route)` | yes | none |
| blackhole | `Reject { kind: Blackhole, .. }` | no | `EINVAL` |
| unreachable | `Reject { kind: Unreachable, .. }` | no | `EHOSTUNREACH` |
| prohibit | `Reject { kind: Prohibit, .. }` | no | `EACCES` |
| throw | `Throw(route)` | no (see below) | `ENETUNREACH` with the default rules |
| none | `NoRoute` | no | `ENETUNREACH` |

`is_v4_reachable` / `is_v6_reachable`, `igp_metric_v4` / `igp_metric_v6` and
`route_to_v4` / `route_to_v6` only ever use a `Forward` result, so a negative route can
never supply an IGP metric.

`is_v6_reachable` treats a link-local address (`fe80::/10`) as on-link **only when no
route covers it**, because the oracle has no output interface to find the per-interface
`fe80::/64` route with. A negative route over link-local space is honoured, as the
kernel honours it (`RTM_GETROUTE` for an address beneath a `prohibit` route answers
`EACCES`).

**Throw.** A throw route ends the lookup in its table with `-EAGAIN`, which is also what
a table returns when nothing matches; the kernel then tries the next policy rule. With
the default rules (local, main, default for IPv4; local, main for IPv6) a throw in `main`
leaves only the normally empty `default` table, so the lookup fails. The snapshot mirrors
one table and does not model rules, so it reports a throw as "no route in the mirrored
table": not reachable. If you use policy rules that send thrown traffic to another
table, the oracle does not follow them.

`FibWriter`'s own RFC 7999 blackholes carry `RTPROT_BGP` and stay untracked, like every
BGP route (see "BGP route exclusion" in the `fib` module docs).

Known limits:

- **Mixed-protocol IPv6 ECMP sets learned from a dump (or a multipath `NLM_F_APPEND`)**
  are the one case the inference gets wrong, in either direction, because netlink never
  reports the unreported siblings' protocols:
  - static first, BGP second: the BGP sibling counts as a path until it is deleted;
  - BGP first, static second: the static sibling is not used until a message reports it,
    even after the BGP sibling is deleted.

  Such sets need two daemons (or an operator) appending into one ECMP set. `FibWriter`
  replaces rather than appends, so it never creates them. Re-reading the set after its
  first sibling is deleted would narrow the second case; that is a possible follow-up.
- Untracked identities are compared by a 64-bit hash within one slot; a collision
  between two routes of the same slot is possible in principle but negligible.
- IPv4 aliases that differ only in `RTA_METRICS` are treated as one route.
- With table `0` (all tables) the tables are compared as one; policy routing rules are
  not modelled.
- IPv6 ECMP eligibility uses `RTPROT_RA` as a stand-in for the kernel's `RTF_ADDRCONF`
  flag, which netlink does not expose.
- A route through a nexthop object (`RTA_NH_ID`) is classified by the type the kernel
  reports. The kernel reports a route through a blackhole nexthop as `blackhole`, but
  changing the nexthop object later sends no route notification.
- An IPv6 unicast route via the loopback device is turned into a reject route by the
  kernel (`fib6_is_reject`) but still reported as unicast, so the oracle treats it as
  reachable.
- IPv6 selection within a metric group follows preference and list order, but not the
  kernel's round-robin pointer (`fn->rr_ptr`, moved only when a gateway's neighbour
  fails), neighbour reachability, or the early return `__find_rr_leaf` takes for a route
  through a blackhole nexthop object.

---

## Unsafe code audit

All `unsafe` in the workspace lives in `pathvector-sys/src/tcp.rs`, in the
`apply_linux` function (approximately 60 lines). The unsafe surface is:

1. Constructing a `TcpMd5Sig` struct by zero-initialising and filling fields — safe
   because `MaybeUninit::zeroed()` is valid for `#[repr(C)]` structs with no padding
   invariants, and every field is set before use.
2. Calling `setsockopt` via `libc::setsockopt` with a pointer to that struct — safe
   because the pointer is valid for the struct's lifetime and the size is correct.

The FIB code uses `rtnetlink`, which handles its own kernel communication; no `unsafe`
blocks are needed there.

---

## Running tests

```bash
# All tests (runs on macOS and Linux)
cargo test -p pathvector-sys

# Linux-only tests require native Linux (not macOS Docker Desktop)
# They run in CI on ubuntu-latest automatically
```

See [TESTING.md](../TESTING.md#tcp-md5-authentication-safety-pathvector-sys) for the
full validation layer description.

---

## License

MIT
