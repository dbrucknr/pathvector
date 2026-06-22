# RFC Requirements — pathvector-sys

This crate owns the **kernel integration layer**: Linux routing table (FIB) access via
rtnetlink and TCP socket options. It is Linux-specific; non-Linux platforms compile against
no-op stubs so the rest of the workspace builds on macOS for development.

**Status key:** ✅ Implemented and tested | ⚠️ Partial — see notes | ❌ Not started  
**Verified by key:** `test_name` — unit test | `proptest` — property test | `—` — no automated verification

---

## RFC 7999 — BLACKHOLE Community (Kernel Programming)

**Owns:** The kernel half of BLACKHOLE route handling: install and remove
`RTN_BLACKHOLE` routes via rtnetlink. The `FibWrite` trait exposes
`install_blackhole_v4/v6` and `withdraw_blackhole_v4/v6`; `FibWriter` (Linux) and
the stub (non-Linux) implement both.  
**Boundary:** Detection of the BLACKHOLE community and the decision to program a null
route lives in `pathvectord`. The `is_blackhole()` predicate lives in `pathvector-types`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7999

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `RTN_BLACKHOLE` route type used (not `RTN_UNICAST`) | `src/fib/linux.rs` | ✅ | `install_blackhole_v4_message_has_blackhole_type_and_bgp_protocol`, `install_blackhole_v6_message_has_blackhole_type_and_bgp_protocol` |
| No gateway attribute in blackhole route message | `src/fib/linux.rs` | ✅ | `install_blackhole_v4_message_has_blackhole_type_and_bgp_protocol` |
| Blackhole route tagged `RTPROT_BGP` so withdrawal can match it | `src/fib/linux.rs` | ✅ | `install_blackhole_v4_message_has_blackhole_type_and_bgp_protocol` |
| Withdrawal uses same `RTM_DELROUTE` path as unicast routes | `src/fib/linux.rs` | ✅ | shared `withdraw_route_v4/v6` helpers |
| Non-Linux stub returns `Ok(())` for all blackhole methods | `src/fib/stub.rs` | ✅ | `fib_write_trait_install_blackhole_v4_is_noop`, `fib_write_trait_withdraw_blackhole_v4_is_noop`, `fib_write_trait_install_blackhole_v6_is_noop`, `fib_write_trait_withdraw_blackhole_v6_is_noop` |

---

## RFC 2385 — Protection of BGP Sessions via TCP MD5 Signatures

**Owns:** The `TCP_MD5SIG` socket option (`setsockopt`) for authenticating BGP
sessions. `apply_tcp_md5sig(fd, peer_ip, key)` sets the option on an already-open
socket before connect/bind.  
**Boundary:** When to call `apply_tcp_md5sig` (based on config) is `pathvectord`'s
responsibility.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc2385

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Key exceeding 80 bytes rejected with `InvalidInput` before any syscall | `src/tcp.rs` | ✅ | `test_key_too_long_returns_error`, `prop_key_over_limit_always_rejected` |
| Key at exactly 80 bytes accepted (passes length guard) | `src/tcp.rs` | ✅ | `test_key_at_exact_limit_passes_length_guard` |
| IPv6 peers rejected with `Unsupported` (not yet supported) | `src/tcp.rs` | ⚠️ | `test_ipv6_returns_unsupported`, `prop_ipv6_always_unsupported` |
| `setsockopt(TCP_MD5SIG)` called on Linux with valid key and fd | `src/tcp.rs` | ✅ | Linux-only syscall; validated by integration tests on Linux CI |

**Deferred:** IPv6 TCP MD5SIG support. The Linux kernel supports it via
`TCP_MD5SIG_EXT` with `TCP_MD5SIG_FLAG_PREFIX`; not yet implemented.
