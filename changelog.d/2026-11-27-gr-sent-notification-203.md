## 2026-11-27 (Graceful Restart: a sent NOTIFICATION no longer retains routes without the N bit)

Issue [#203](https://github.com/dbrucknr/pathvector/issues/203). RFC 4724 §4 keeps the normal BGP
procedures for a session that ends "due to the sending or receiving of a BGP NOTIFICATION message";
RFC 8538 §4 changes that only for speakers that exchanged the "N" bit. Only the receiving half was
followed:

- Hold Timer expiry, message header errors and unexpected messages in Established retained the
  peer's routes for its whole restart time without the N bit.
- The converse was wrong too: with the N bit, an UPDATE-error session reset and the daemon's own
  automatic resets flushed the routes, although RFC 8538 §4 says the speaker generating the
  NOTIFICATION "MUST also follow the rules for the Receiving Speaker".

**Behaviour changes**

- Without the N bit, Hold Timer expiry and detected errors now flush the peer's routes. A silent
  peer is withdrawn when the Hold Timer expires.
- With the N bit, they retain them, and so do UPDATE-error resets and automatic resets (for
  example Cease / Out of Resources after an outbound or event backlog).
- A TCP failure with no NOTIFICATION retains routes as before.
- Operator stop, peer removal and the maximum-prefix Cease flush as before. They still send a plain
  Cease rather than a Hard Reset (`TODO.md`).
- `pathvectord_bgp_sessions_terminated_total` has a new `reason="notification_sent"`. Losses
  previously counted as `unclean` (Hold Timer expiry, header and FSM errors) or `operator_stop`
  (UPDATE errors, automatic resets) are now counted there.

**Breaking API change (`pathvector-session`)**

- New variant `TerminationReason::NotificationSent(NotificationMessage)`. `Unclean` now means no
  NOTIFICATION in either direction; `OperatorStop` now means `Stop`, `Notification` or `Retire`.

Not exercised against GoBGP, FRR or BIRD by a new test.
