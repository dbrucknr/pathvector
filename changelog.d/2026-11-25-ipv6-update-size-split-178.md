## 2026-11-25 (pathvectord: IPv6 announcements are split at the maximum message size — issue #178)

IPv6 prefixes with equal attributes and next hop were all packed into one `MP_REACH_NLRI`. At
about 570 /48s that passed 4096 octets (RFC 4271 §4.1), and a large enough group also passed
the 65535 of RFC 8654.

- `flush_updates_v6` splits each group into as many UPDATEs as the peer's negotiated limit
  needs, repeating the attributes and next hop in each.
- An IPv6 route that does not fit even on its own is no longer sent (RFC 4271 §9.2). Its prefix
  is withdrawn instead, so the peer does not keep an earlier version (RFC 8654 §4), and a
  warning is logged. Adj-RIB-Out still lists it, and attributes are not discarded to make it
  fit (RFC 8654 §4, SHOULD).
- Tests: `outbound::v6_size_tests`, `coalesced_ipv6_announcements_stay_within_max_len`.
