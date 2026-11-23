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
reachability and IGP-metric queries from its *tracked* routes: unicast routes not
installed by BGP (`RTPROT_BGP`).

A prefix does not identify a kernel route. Linux keeps several routes for one prefix,
and the snapshot stores each under the identity the kernel itself uses:

| Family | Slot (the kernel's grouping) | Route within the slot |
|---|---|---|
| IPv4 | table, prefix, TOS, priority (`fib_table_insert`: "[prefix,dscp,priority]") | type, protocol, scope, preferred source, next hop(s) |
| IPv6 | table, prefix, source prefix, metric (`fib6_add_rt2node`) | next hop (each ECMP sibling is its own route) |

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
`fib6_dump_node` dumps a sibling set once and skips the other siblings. A leg whose
protocol no message has given is recorded with `protocol: None` and **counts as a path**,
because the kernel forwards over every sibling and all-IGP ECMP sets are the common case.
A later message that describes the leg settles its protocol.

A lookup takes the longest matching prefix and, among its routes, the lowest priority,
as the kernel does. IPv4 routes with a non-zero TOS and IPv6 source-specific routes are
kept but not selected, because a best-effort lookup from an unspecified source cannot
use them. `FibSnapshot::routes_v4` / `routes_v6` list the stored routes and
`route_to_v4` / `route_to_v6` return the route a lookup selects.

Known limits:

- An IPv6 ECMP sibling of unknown protocol (learned from the initial dump, or added by a
  multipath `NLM_F_APPEND`) counts as a path even if it is in fact a BGP route. This
  only matters for an ECMP set that mixes BGP and IGP routes: after the IGP siblings are
  deleted, such a BGP leg keeps the prefix reachable until it is deleted too. The kernel
  does not report the protocol, so this cannot be resolved from netlink.
  `FibWriter` replaces rather than appends, so it never creates mixed sets.
- Untracked identities are compared by a 64-bit hash within one slot; a collision
  between two routes of the same slot is possible in principle but negligible.
- IPv4 aliases that differ only in `RTA_METRICS` are treated as one route.
- With table `0` (all tables) the tables are compared as one; policy routing rules are
  not modelled.
- IPv6 ECMP eligibility uses `RTPROT_RA` as a stand-in for the kernel's `RTF_ADDRCONF`
  flag, which netlink does not expose.

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
