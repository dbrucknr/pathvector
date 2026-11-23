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

BGP speakers can authenticate sessions by adding an MD5 signature to every TCP
segment. This requires the `setsockopt(TCP_MD5SIG)` syscall on the listening and
connecting sockets. `pathvector-sys` provides `install_tcp_md5_key` and
`remove_tcp_md5_key`, which wrap this call and report exactly what happened.

---

## Platform scope

This crate is **Linux-only in production**. On non-Linux platforms:

- All FIB operations compile to no-ops
- `install_tcp_md5_key` / `remove_tcp_md5_key` return
  `Err(TcpMd5Error::Unsupported(TcpMd5Unsupported::Platform))`: no key is installed,
  and the crate says so instead of returning success
- All tests still compile and pass

This design lets `pathvectord` compile and run on macOS for development without needing
a Linux kernel.

The FIB and TCP MD5 paths are gated with `#[cfg(target_os = "linux")]`. What a peer
with `md5_password` does on a host that cannot enforce it is decided by the caller, not
this crate: pathvectord refuses to connect unless `[daemon] tcp_md5_enforcement =
"best-effort"` is set (see `pathvectord/README.md`).

---

## TCP MD5 (`install_tcp_md5_key` / `remove_tcp_md5_key`)

```rust,ignore
use std::os::fd::AsFd;
use pathvector_sys::{TcpMd5Key, install_tcp_md5_key, remove_tcp_md5_key};

let key: TcpMd5Key = "shared-bgp-secret".parse()?;   // 1–80 bytes, Debug-redacted
install_tcp_md5_key(socket.as_fd(), peer_ip, &key)?; // before connect() / before SYNs arrive
remove_tcp_md5_key(socket.as_fd(), peer_ip)?;        // explicit, separately named delete
```

`TcpMd5Port` is the port (trait) over these two calls and `KernelTcpMd5` is the real
adapter, so callers can test their policy with a fake.

### Outcomes

| Input / kernel answer | Result | Source |
|---|---|---|
| Empty key | `TcpMd5Key` construction fails (`TcpMd5KeyError::Empty`) | Linux `tcp_v4_parse_md5_keys`: zero `tcpm_keylen` → `tcp_md5_do_del` (delete) |
| Key over 80 bytes | `TcpMd5KeyError::TooLong` | `TCP_MD5SIG_MAXKEYLEN 80`; kernel returns `EINVAL` |
| Non-Linux build | `Err(Unsupported(Platform))` | no adapter |
| IPv6 peer | `Err(Unsupported(Ipv6Peer))` | not implemented yet |
| `ENOPROTOOPT` / `EOPNOTSUPP` | `Err(Unsupported(Kernel { errno }))` | `do_tcp_setsockopt`: `TCP_MD5SIG` only handled under `CONFIG_TCP_MD5SIG`, else `-ENOPROTOOPT` |
| `remove` with no key installed | `Err(Os(e))`, `e.kind() == NotFound` | `tcp_md5_do_del` returns `-ENOENT` |
| Other OS error | `Err(Os(e))` | |
| Success | `Ok(())`: the kernel now signs and verifies every segment for that peer | RFC 2385 §2.0 |

`Ok(())` never means "not enforced". RFC 5925 §8: an endpoint configured to require
TCP MD5 must add it "to all outgoing segments and validate[] [it] on all incoming
segments".

Docker Desktop's `LinuxKit` kernel is built with `# CONFIG_TCP_MD5SIG is not set`, so
there every install reports `Unsupported(Kernel { errno: ENOPROTOOPT })`.

### Why a local `TcpMd5Sig` struct instead of `libc::tcp_md5sig`

`libc::tcp_md5sig` is not exposed on all Linux target architectures in all `libc`
versions (notably absent on `aarch64` in `libc 0.2.x`), so `src/tcp/linux.rs` defines
it locally. Its middle bytes use an older padding layout that only encodes the same
`tcpm_keylen` as `<linux/tcp.h>` on little-endian targets; issue #60 tracks mirroring the
UAPI exactly.

### Linux permissions

`setsockopt(TCP_MD5SIG)` needs no capability: `tcp_v4_parse_md5_keys` performs no
permission check, and the loopback tests below run unprivileged. (Binding port 179 still
needs `CAP_NET_BIND_SERVICE`.)

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
as the kernel does. IPv4 routes with a non-zero TOS and IPv6 source-specific routes are
kept but not selected, because a best-effort lookup from an unspecified source cannot
use them. `FibSnapshot::routes_v4` / `routes_v6` list the stored routes and
`route_to_v4` / `route_to_v6` return the route a lookup selects.

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

---

## Unsafe code audit

All `unsafe` for TCP MD5 lives in `pathvector-sys/src/tcp/linux.rs`, in
`set_md5sig_v4` (approximately 60 lines). The socket is passed as a `BorrowedFd`, so it
is guaranteed open for the duration of the call. The unsafe surface is:

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

# Live TCP MD5 enforcement over loopback (Linux, no privileges needed)
cargo test -p pathvector-sys --test tcp_md5_loopback
```

`tests/tcp_md5_loopback.rs` opens real connections and checks that matching keys connect
while unsigned, wrongly signed and unexpectedly signed SYNs are dropped, that a second
install replaces the key, and that `remove_tcp_md5_key` really stops enforcement. On a
kernel without `CONFIG_TCP_MD5SIG` (Docker Desktop) these tests check that `Unsupported`
was reported and skip the rest; with `CI` set (GitHub Actions) an unsupported kernel fails
them instead.

See [TESTING.md](../TESTING.md#tcp-md5-authentication-safety-pathvector-sys) for the
full validation layer description.

---

## License

MIT
