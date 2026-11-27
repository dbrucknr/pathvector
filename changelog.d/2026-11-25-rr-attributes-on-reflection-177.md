## 2026-11-25 (pathvectord: a route reflector no longer resets the session on an iBGP withdrawal)

A route reflector added `ORIGINATOR_ID` and `CLUSTER_LIST` to each UPDATE it *received* from an
iBGP peer. A withdraw-only UPDATE then looked like one with attributes but no reachable NLRI, so
the RFC 7606 §5.2 check found ORIGIN missing and reset the session (issue #177). Both address
families were affected, so the session dropped the first time an iBGP neighbour withdrew anything.

- Fixed at the cause (issue #135): the two attributes are now added when a route is reflected
  (iBGP-learned, advertised to an iBGP peer), as RFC 4456 §8 describes, and received routes are
  stored as received (RFC 4271 §3.2). Inbound loop detection is unchanged.
- Adj-RIB-In and Loc-RIB no longer show attributes this speaker added. Best-path selection now
  compares the received `CLUSTER_LIST` length (RFC 4456 §9), so a reflector no longer penalizes
  `Internal` routes against `ConfedMember` ones.
- The fallback that used this speaker's own BGP Identifier as `ORIGINATOR_ID` is gone. A route
  whose source's identifier is unknown (not reachable on an Established session) is not reflected.
- API change in `pathvector-rib`: `AdjRibOut::new_reflecting` now takes the reflector's
  `CLUSTER_ID`, and `AdjRibOut::cluster_id` returns it.
- Tests: `daemon/rr_reflection_tests.rs`, including one through `run_event_loop`. The test of the
  removed fallback was deleted.
