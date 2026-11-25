## 2026-11-25 (pathvectord: route-reflector non-client split-horizon on every send path)

On a route reflector, a route from a non-client iBGP peer goes to clients only (RFC 4456 §6).
Only incremental propagation and the opening table dump applied that rule (issue #168):

- Session loss, Graceful Restart stale marking, End-of-RIB prune, deadline expiry and
  export-policy changes reflected one non-client's route to another.
- A non-client holding a client's route was sent no withdrawal when a non-client's path took over
  as best, and kept the old route. RFC 4271 §9.1.3: "the previously advertised route in that
  Adj-RIB-Out MUST be withdrawn from service".
- The rule looked up the source's live session, so a peer connecting while a non-client's routes
  were retained for Graceful Restart was sent them.
- The rule was skipped when the source peer was reached over IPv6.

The rule now lives in `propagate_prefix` / `propagate_prefix_v6`, which every send path goes
through, and an excluded route yields a withdrawal if it was advertised before. It reads the
source's peer type from the route itself, so it still holds once the session is gone.

Tests: `daemon/rr_split_horizon_tests.rs`. IPv6 session loss without Graceful Restart still sends
nothing (issue #160), so the IPv6 teardown cases use the flush of a family not covered by the
Graceful Restart capability.
