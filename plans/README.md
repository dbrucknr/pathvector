# Plans

Planned initiatives for the pathvector project. Each file covers motivation,
approach, files to modify, and success criteria. Items in TODO.md describe
*what* is deferred; plans here describe *how* to execute on them.

| Plan | Summary |
|---|---|
| [stress-test-full-table.md](stress-test-full-table.md) | Three-stage correctness and performance test at internet scale (~950k prefixes) |
| [criterion-benchmarks.md](criterion-benchmarks.md) | Per-crate criterion benchmark suite across types, policy, RIB, and session codec |
| [stale-route-cleanup.md](stale-route-cleanup.md) | Delete RTPROT_BGP kernel routes at daemon startup to prevent stale routes after restart |
| [route-reflector.md](route-reflector.md) | Fix five known RFC 4456 correctness gaps in the route reflector implementation |
| [ipv6-interop.md](ipv6-interop.md) | End-to-end IPv6 NLRI receive/withdraw tests against BIRD and FRR peers |
| [dynamic-peer-config.md](dynamic-peer-config.md) | ✅ gRPC-driven live peer add/remove/update without daemon restart |
