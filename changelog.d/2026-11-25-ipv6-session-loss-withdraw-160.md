## 2026-11-25 (Session loss now withdraws and replaces IPv6 routes at other peers — issue #160)

### Fixes

- When a session ended outside Graceful Restart helper mode (TCP failure, hold timer,
  NOTIFICATION, `RemovePeer`), the lost peer's IPv6 routes left the Loc-RIB and FIB but no
  UPDATE was sent: other peers kept the unreachable prefixes and never learned the
  replacement path. RFC 4271 §3.1 / §8.2.2 delete those routes and §9.2 requires
  advertising the result. IPv6-capable peers now get `MP_UNREACH_NLRI` or the new best
  route.
- `WatchRoutes` subscribers were not told about IPv6 changes on any teardown path: session
  loss, the Graceful Restart flush, stale marking, deadline expiry and the End-of-RIB prune.
  They now are.
- Not covered: IPv6 changes from a received UPDATE, a next-hop change or an import-policy
  change still emit no `WatchRoutes` event (issue #169). Local origination and withdrawal do.
