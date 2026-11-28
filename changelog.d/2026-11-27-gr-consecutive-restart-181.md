## 2026-11-27 (pathvectord: delete still-stale routes on a consecutive restart without the N bit)

Issue [#181](https://github.com/dbrucknr/pathvector/issues/181). RFC 4724 §4.2, as replaced by
RFC 8538 §4.1: "If the "N" bit has not been exchanged with the peer, then to deal with possible
consecutive restarts, a route (from the peer) previously marked as stale MUST be deleted." The
daemon re-marked every retained route instead, so a peer that kept dropping before End-of-RIB could
keep an old route indefinitely.

- Without the N bit, a second loss now deletes the routes the peer has not re-announced since the
  first, in both address families: from the Adj-RIB-In, Loc-RIB, FIB and blackhole book, with
  withdrawals to the other peers. Re-announced routes are retained and marked stale.
- With the N bit exchanged in the session being lost, they are all retained.
- A session loss now also drops the interrupted session's End-of-RIB bookkeeping.

A test that expected an un-refreshed route to survive a second loss without the N bit now refreshes
it first.
