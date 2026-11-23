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
sessions: `install_tcp_md5_key(fd, peer_ip, &TcpMd5Key)` and
`remove_tcp_md5_key(fd, peer_ip)`, and an exact report of whether the key is enforced.  
**Boundary:** When to install a key, and what to do when it cannot be enforced, is the
caller's policy (`pathvector-session::transport::tcp_md5`, configured by `pathvectord`).  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc2385

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Keys of 1–80 bytes accepted, any bytes (RFC 2385 §2.0 "nature of the key is deliberately left unspecified"; §4.5 at least 80 printable ASCII bytes) | `src/tcp/key.rs` | ✅ | `keys_of_1_and_80_bytes_are_accepted`, `prop_any_1_to_80_bytes_is_a_key` |
| Key over 80 bytes rejected (`TCP_MD5SIG_MAXKEYLEN`) | `src/tcp/key.rs` | ✅ | `key_longer_than_80_bytes_is_rejected`, `prop_over_80_bytes_is_rejected` |
| Empty key rejected: Linux reads zero `tcpm_keylen` as delete (issue #58) | `src/tcp/key.rs` | ✅ | `empty_key_is_rejected` |
| Key deletion is a separate operation; really stops enforcement; `ENOENT` when absent | `src/tcp/mod.rs` | ✅ | `removing_the_key_stops_enforcement` (live) |
| Unenforceable key never reported as success: `ENOPROTOOPT`/`EOPNOTSUPP`, non-Linux, IPv6 → `Unsupported` (RFC 5925 §8; issue #58) | `src/tcp/mod.rs` | ✅ | `enoprotoopt_and_eopnotsupp_mean_unsupported`, `non_linux_reports_platform_unsupported`, `ipv6_peer_reports_unsupported`, `unsupported_kernel_is_never_reported_as_enforced` (live) |
| Matching keys connect and exchange data | `src/tcp/linux.rs` | ✅ | `matching_keys_connect_and_exchange_data` (live, CI) |
| Unsigned, wrongly signed and unexpectedly signed SYNs dropped without reply (RFC 2385 §2.0, §4.1) | kernel | ✅ | `unsigned_client_cannot_reach_keyed_listener`, `wrong_key_cannot_connect`, `signed_client_cannot_reach_unkeyed_listener` (live, CI) |
| Re-installing replaces the key (rotation) | kernel | ✅ | `reinstalling_replaces_the_key` (live, CI) |
| Key redacted from `Debug` | `src/tcp/key.rs` | ✅ | `debug_output_redacts_the_key` |
| IPv6 peers | — | ⚠️ | reported as `Unsupported(Ipv6Peer)` |

"(live)" tests are in `tests/tcp_md5_loopback.rs`; "(live, CI)" ones need a kernel with
`CONFIG_TCP_MD5SIG` and fail rather than skip when `CI` is set.

**Deferred:** IPv6 TCP MD5SIG support. The Linux kernel supports it via
`TCP_MD5SIG_EXT` with `TCP_MD5SIG_FLAG_PREFIX`; not yet implemented.
