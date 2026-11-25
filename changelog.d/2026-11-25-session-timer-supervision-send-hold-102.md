## 2026-11-25 (session timers survive load and backpressure; RFC 9687 Send Hold Timer)

Issue [#102](https://github.com/dbrucknr/pathvector/issues/102). The session loop's `biased;`
`select!` polled commands and inbound messages ahead of the timers, and awaited socket writes and
event-channel sends inline. Reproduced before the fix:

- a KEEPALIVE that was due was sent only after all 5,000 ready UPDATEs had been processed, and the
  HoldTimer only after all 20,000 ready ROUTE-REFRESH messages;
- a ConnectRetry waited behind 10,000 ready commands;
- with the peer not reading, the HoldTimer never fired and `Stop` had no effect;
- with the event consumer stalled, no KEEPALIVE was sent, `Stop` had no effect and a dead peer was
  not detected.

**The fix**

- The session task waits in one place. Overdue timers and ready input alternate, so neither starves
  the other (`transport/schedule.rs`, no I/O).
- Writes are buffered and flushed alongside everything else, in batches of about 8 KiB
  (`transport/link.rs`).
- Events that do not fit the channel are held in order and the peer is not read meanwhile
  (`transport/outbox.rs`).
- An overdue HoldTimer first reads up to 16 messages that have already arrived, so a session that
  was behind does not declare a talking peer dead.

**RFC 9687 (Send Hold Timer, updates RFC 4271)** was not implemented. A peer that kept sending
KEEPALIVEs behind a closed TCP window kept the session up for ever. It is now implemented, enabled
by default at the greater of 8 minutes and twice the negotiated hold time, and configurable per
session with the validated `SendHoldTime`.

**Behaviour changes**

- Sessions close with NOTIFICATION code 8 and `TerminationReason::SendHoldTimerExpired` when nothing
  can be sent for the `SendHoldTime`. The daemon reports it as `reason="send_hold_timer_expired"` and
  retains routes for Graceful Restart only if the RFC 8538 N bit was exchanged.
- A session whose events are never consumed is reset with Cease / Out of Resources once 64 events
  are held.
- Sending an UPDATE now restarts the KeepaliveTimer (RFC 4271 §8.2.2).
- A NOTIFICATION that cannot be written no longer loses the `Terminated` event. This was also fixed
  on `main` first, by [#167](https://github.com/dbrucknr/pathvector/pull/167); its tests are kept,
  ported to the split transport ports.
- Dropping a session handle now ends its task. It used to spin on the closed command channel.
- UPDATEs and ROUTE-REFRESH are sent only in Established, as the API documented.
- `pathvector_session_event_send_blocked_seconds` now measures how long events waited, per blocked
  episode; the session is no longer parked for that time.

**Breaking API changes (`pathvector-session`)**

- `BgpTransport` is now `into_split()` into a `BgpReader` and a `BgpWriter` (`queue` without waiting,
  cancel-safe `flush`).
- `SessionConfig` and `FsmConfig` have a new `send_hold_time` field.
- New variants: `FsmInput::SendHoldTimerExpired`, `FsmOutput::{Start,Stop}SendHoldTimer`,
  `NotificationError::SendHoldTimerExpired`, `TerminationReason::SendHoldTimerExpired`.

New metrics: `pathvector_session_send_hold_expired_total`,
`pathvector_session_event_backlog_resets_total`.

**Measurements**

`pathvector-loadtest`, one loader with a 1,133,510-prefix RIPE RIS table plus a 9 s control peer,
loopback, release build, Apple M2 Max; base is the commit this change sits on. One loader only, so
this is not PR-1's two-full-table-peer run.

| | Base | This change |
|---|---|---|
| Initial convergence, median of 19 runs (range) | 5.81 s (5.67–6.08) | 5.75 s (5.36–5.89) |
| Reconvergence, median of 9 runs (range) | 5.99 s (5.92–6.11) | 5.94 s (5.90–7.19, one outlier) |
| Peer teardown, median of 9 runs | 2.07 s | 2.09 s |
| Control peer longest silence in convergence (hold 9 s) | ≤ 3.01 s | ≤ 3.01 s |
| `event_send_blocked` total in convergence, median of 18 alternated runs (range) | 640 ms (364–915) | 634 ms (395–973) |

Base and branch runs were alternated except for six a side in the first two rows. `keepalive_lateness` is unchanged in kind. It grows only while `watch_routes` snapshots run: with the
harness temporarily set to a 9 s loader hold time and 60 s churn phases (5 alternated runs a side,
about 20 KEEPALIVEs per session per run), the loader and control sessions were late by nearly the
same total within each run on both sides (base 1.35–2.57 s, this change 0.20–2.85 s). That points at
daemon-wide stalls, not at either session loop; the cause was not isolated. The `event_send_blocked`
metric now samples a blocked episode rather than one parked send.

The failures this change fixes (a stalled consumer, a non-reading peer, input that never pauses) do
not arise in these loopback runs, so they are shown by tests, not by these numbers.
