## 2026-11-27 (pathvectord: removing a peer tears it down once)

Removing an Established peer ran the session teardown twice: on its `Terminated` and again on its
`Retired`. The routes were withdrawn correctly, but the second run walked every best route in the
Loc-RIB again under the state write lock, and `WatchRoutes` subscribers received route events for
untouched prefixes both times.

- `Retired` now skips the teardown if `Terminated` already ran it for this removal.
- It still runs the teardown if no `Terminated` was handled while the peer was being removed (not
  Established, between sessions with Graceful Restart routes retained, or a session task that
  died), and if the session became Established again after that `Terminated`.
- `Retired` is still the only event that completes a removal.

The time saved has not been measured.
