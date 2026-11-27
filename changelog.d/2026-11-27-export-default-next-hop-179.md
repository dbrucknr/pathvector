## 2026-11-27 (pathvectord: an export-default change keeps the session's `NEXT_HOP` — issue #179)

`SetExportDefault` re-advertised IPv4 routes to eBGP and `next_hop_self` peers with the router ID
as `NEXT_HOP`, even when the default did not change. A peer that cannot reach the router ID on
that link could not use the routes. RFC 4271 §5.1.3: for an external peer, by default "the BGP
speaker SHOULD use the IP address of the interface that the speaker uses to establish the BGP
connection to peer X".

It now uses the session's local address, as the table dump and incremental propagation do, falling
back to the router ID only when the session has no local IPv4 address. A call that leaves the
default unchanged sends nothing for routes already advertised with that address. IPv6 was not
affected.

Tests: `daemon/policy.rs` (eBGP, and iBGP with `next_hop_self`).
