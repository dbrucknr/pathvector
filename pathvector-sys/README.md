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

`KernelFib` keeps a `FibSnapshot` of the kernel's IGP routes (unicast, blackhole,
unreachable, prohibit and throw routes not tagged `RTPROT_BGP`) and answers next-hop
reachability and IGP-metric queries from it.

A prefix does not identify a kernel route. Linux keeps several routes for one prefix,
and the snapshot stores each under the identity the kernel itself uses:

| Family | Slot (the kernel's grouping) | Route within the slot |
|---|---|---|
| IPv4 | table, prefix, TOS, priority (`fib_table_insert`: "[prefix,dscp,priority]") | type, protocol, scope, preferred source, next hop(s) |
| IPv6 | table, prefix, source prefix, metric (`fib6_add_rt2node`) | next hop (each ECMP sibling is its own route); the type is recorded but, as in `rt6_duplicate_nexthop`, not compared |

Prefixes are validated newtypes (`Ipv4Prefix`, `Ipv6Prefix`: length within range, no
host bits) and table IDs cannot be zero (`TableId`), so a route identity can only hold
values the kernel can report. `RTM_DELROUTE` removes exactly the route it names.
`RTM_NEWROUTE` with `NLM_F_REPLACE` displaces the route the kernel replaced, which never
gets an `RTM_DELROUTE` of its own.

A lookup takes the longest matching prefix and, among its routes, the lowest priority,
as the kernel does. For IPv6, routes of that priority are then ranked by router
preference (`RTA_PREF`; `rt6_score_route` adds `IPV6_DECODE_PREF(pref) << 2`, and
`find_match` keeps only a strictly better score), and only then by list order. Negative
IPv6 routes are always medium preference: `ip6_route_info_create` overwrites a reject
route's flags with `RTF_REJECT | RTF_NONEXTHOP`, dropping `RTF_PREF`. IPv4 routes with a non-zero TOS and IPv6 source-specific routes are
kept but not selected, because a best-effort lookup from an unspecified source cannot
use them. `FibSnapshot::routes_v4` / `routes_v6` list the stored routes.

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

`FibWriter`'s own RFC 7999 blackholes carry `RTPROT_BGP` and stay excluded, like every
BGP route (see "BGP route exclusion" in the `fib` module docs).

Known limits:

- Routes the snapshot does not track (BGP-installed routes and the `local`,
  `broadcast`, `anycast`, `multicast` types) are not mirrored, so if one sits ahead of a
  tracked route in the same IPv4 slot, an `NLM_F_REPLACE` may displace the wrong one in
  the mirror.
- A route through a nexthop object (`RTA_NH_ID`) is classified by the type the kernel
  reports. The kernel reports a route through a blackhole nexthop as `blackhole`, but
  changing the nexthop object later sends no route notification, and the object's own
  state (dead, link down) is not checked.
- An IPv6 unicast route via the loopback device is turned into a reject route by the
  kernel (`fib6_is_reject`) but still reported as unicast, so the oracle treats it as
  reachable.
- IPv6 selection within a metric group follows preference and list order, but not the
  kernel's round-robin pointer (`fn->rr_ptr`, moved only when a gateway's neighbour
  fails), neighbour reachability, or the early return `__find_rr_leaf` takes for a route
  through a blackhole nexthop object.
- IPv4 aliases that differ only in `RTA_METRICS` are treated as one route.
- With table `0` (all tables) the tables are compared as one; policy routing rules are
  not modelled.
- IPv6 ECMP eligibility uses `RTPROT_RA` as a stand-in for the kernel's `RTF_ADDRCONF`
  flag, which netlink does not expose.

### Reading the kernel FIB: lost notifications and recovery

netlink(7): "Netlink is not a reliable protocol." When a listener's receive buffer is
full "the message will be dropped and the kernel and the user-space process will no
longer have the same view of kernel state. It is up to the application to detect when
this happens (via the `ENOBUFS` error returned by recvmsg(2)) and resynchronize."
Subscribing before the first dump only closes the startup race; it does nothing about
later losses.

`KernelFib::spawn` therefore runs a supervisor over one `NETLINK_ROUTE` socket that is
subscribed to IPv4 and IPv6 route notifications and also carries the dumps:

| Detected | How it surfaces | Cause reported |
|---|---|---|
| Notifications dropped | `recvmsg` fails with `ENOBUFS`; `netlink-proto` 0.12 turns it into an `NLMSG_OVERRUN` message | `NotificationsLost` |
| Connection ended | any other socket error or an undecodable datagram ends `netlink-proto`'s connection task and the notification stream | `ConnectionLost` |
| Dump cut short | the reply stream ends without `NLMSG_DONE` (`NLMSG_DONE` forwarding is switched on for this) | `ConnectionLost` |
| Dump failed | `NLMSG_ERROR`, or a negative error in `NLMSG_DONE` | `DumpFailed(errno)` |
| Dump may have missed routes | `NLM_F_DUMP_INTR`, or a notification for the same family arriving during that family's dump | `DumpInconsistent` |
| Dump stopped | an overrun while the dump runs, or no `NLMSG_DONE` within `DumpTimeout` (60 s by default) | `NotificationsLost` / `DumpStalled` |
| New socket refused | `socket` / `bind` / `setsockopt` failed | `ConnectFailed(errno)` |

The last detection rule matters because the kernel's route dumpers never set
`NLM_F_DUMP_INTR` (only dumpers that call `nl_dump_check_consistent` do), yet
`fib6_dump_table` restarts from the root after a tree change and skips as many routes as
it had already sent, which can drop an unchanged route. Every such change is also
notified on the subscribed socket, so it is visible.

A dump can also stop without ending: when `netlink_dump` cannot allocate or charge its
next chunk it returns `-ENOBUFS`, leaves the dump running, and `netlink_recvmsg` retries
it only after it has received another queued message. The supervisor therefore reads
notifications while a dump runs, gives each dump a deadline, and replaces the socket when
it abandons a running dump (a new dump on that socket would get `EBUSY` from
`__netlink_dump_start`). A busy notification channel cannot hold either back: the dump
and the deadline are checked before every notification, and the supervisor yields to the
runtime as it works through a long queue.

After a detection the snapshot becomes `Degraded`, the supervisor waits (`ResyncBackoff`:
100 ms doubling to 10 s by default, applying the notifications it still receives), dumps
IPv4 then IPv6 into a fresh snapshot, and swaps it in with one move under the write lock.
An overrun during an attempt abandons it: the kernel drops every notification while the
socket is congested but reports `ENOBUFS` only once (`netlink_overrun`,
`netlink_broadcast_deliver`, `netlink_rcv_wake`). A lost connection is reopened with the
same delays; an overrun keeps the socket.

`KernelFib::status()` / `KernelOracle::status()` publish a `FibStatus`: the
`SnapshotHealth` (`Starting`, `Ready { since }`, `Degraded { since, cause, attempts }`)
plus counters of losses and completed resyncs. **Lookups never refuse:** while degraded
they answer from the last snapshot (stale but flagged), because declaring every next hop
unreachable would make BGP withdraw everything on a transient overrun. `spawn` returns
only if the very first socket cannot be opened. `KernelFib::builder` sets the backoff,
the per-dump deadline (`dump_timeout`) and the socket's `SO_RCVBUF` (`receive_buffer`).
`pathvectord` logs the status it finds when its logger starts, every change of cause,
recovery, and a reminder when a single-cause outage reaches 4, 8, 16, … retries.

Known limits:

- Changes the kernel never notifies are not detected. In particular, when a link goes
  down `fib_table_flush` removes the IPv4 routes through it and sends `RTM_DELROUTE` only
  if their preferred source address was removed.
- There is no periodic verification dump, so a divergence that is never signalled lasts
  until the next detected loss.
- `KernelFib::stale_bgp_routes` still uses `rtnetlink`'s dump, which cannot tell a
  complete dump from one cut short by a closed connection.

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
