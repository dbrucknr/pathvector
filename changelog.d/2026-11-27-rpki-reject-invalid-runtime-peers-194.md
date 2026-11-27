## 2026-11-27 (peers added at runtime get the RPKI reject-Invalid policy, #194)

With `[daemon.rpki]` and `reject_invalid = true` (the default), a peer added with `AddPeer` had
no RFC 6811 reject-Invalid import term, so RPKI-Invalid routes from it were accepted into the
Loc-RIB. Nothing was logged, and a later ROA change did not repair it, because re-evaluation
reused the same policy. Removing and re-adding a configured peer dropped the term too.

The term was appended once, at startup, to the peers that existed then, while `AddPeer` built
import policy separately.

**The fix**

- Startup and `AddPeer` now build a peer's IPv4 and IPv6 import policy in one function.
- The daemon remembers that reject-Invalid is on, so a peer added later gets the same terms as
  one present at startup. With `reject_invalid = false` neither gets the term.

**Operator note:** after upgrading, Invalid routes from runtime-added peers are rejected. Peers
that were persisted and loaded again at a restart already had the term.
