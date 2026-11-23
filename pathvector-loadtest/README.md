# pathvector-loadtest

Multi-peer full-table load harness for `pathvectord`. It exists to produce the
evidence [`PRODUCTION_READINESS.md`](../PRODUCTION_READINESS.md) **PR-1** asks
for: when the daemon is busy with heavy work for one peer, do *other* peers
keep their KEEPALIVEs, and does the management plane keep answering?

It spawns a real `pathvectord`, connects **N loader peers** that each announce
a full table from an MRT dump, plus one quiet **control peer** with a short
hold timer, drives the scenarios below, and measures from two vantage points:

| From outside (black box) | From inside (the daemon's own histograms) |
|---|---|
| Control peer: longest silence between daemon messages vs the `hold/3` cadence and the hold time | `pathvectord_state_lock_hold_seconds{kind}` / `_wait_seconds{kind}` |
| gRPC `list_peers` latency, probed every 100 ms (`--probe-interval-ms 0` disables it) | `pathvectord_event_loop_batch_events` |
| Peak RSS (`ps`, every 500 ms) | `pathvector_session_event_send_blocked_seconds{peer}` |
| Daemon WARN/ERROR log lines | `pathvector_session_keepalive_lateness_seconds{peer}` |

Each scenario is a *window*: `/metrics` is scraped at both ends and the
histograms are diffed, so every report covers exactly that scenario's work.
The control peer's verdict is **OK** (keepalives on cadence), **LATE**
(keepalives arrived, but later than 1.5× the cadence) or **FAILED** (silence
exceeded the hold time, or the session was lost). The process exits non-zero
on any FAILED window or aborted scenario.

## Scenarios

| Name | What it does |
|---|---|
| `idle` | No load. Validates the measurement itself: the control peer must see keepalives at exactly the negotiated cadence. |
| `converge` | Every loader sends the full table simultaneously. |
| `cow` | Loader 0 churns a small prefix set (withdraw + re-announce) twice: alone, then while a client continuously streams `watch_routes` snapshots. Compare the two reports — it tests whether a management client holding a RIB snapshot makes the next mutation clone the whole RIB under the write lock. |
| `teardown` | Loader 0 vanishes abruptly (TCP close, no NOTIFICATION) while holding a full table. |
| `reconverge` | Loader 0 returns and re-sends the full table into an already-populated RIB. |
| `export` | Flips one loader's export policy reject→accept (full Loc-RIB dump to it) then back (full withdraw). **Needs ≥ 2 loaders**: a prefix is never advertised back to the peer its best path came from, so with one loader there is nothing to send. |

Not yet covered (PR-1 exit criteria): Graceful Restart recovery, route
refresh, and RPKI cache replacement (needs `mock_rtr_server`).

## Running

Peers are identified by **source IP**, so every simulated peer needs its own
address.

**Linux:** all of `127.0.0.0/8` is loopback — nothing to do.

**macOS:** only `127.0.0.1` exists. Add aliases (needs sudo), run, then remove
them:

```bash
for n in 2 3 4; do sudo ifconfig lo0 alias 127.0.0.$n up; done
# … run the harness …
for n in 2 3 4; do sudo ifconfig lo0 -alias 127.0.0.$n; done
```

The harness checks this up front and prints these exact commands if an
address cannot be bound. Alternatively pass `--source-addrs a,b,…` (all but
the last are loaders, the last is the control peer) to use addresses you
already have, e.g. `127.0.0.1` plus a LAN address for a one-loader run.

```bash
cargo build --release -p pathvectord -p pathvector-loadtest

# Two full-table loaders + control peer (loaders .2 .3, control .4):
./target/release/loadtest --mrt latest-bview.gz

# Quick smoke run on the first 20k prefixes:
./target/release/loadtest --mrt latest-bview.gz --limit 20000

# One scenario, daemon at debug logging:
./target/release/loadtest --mrt latest-bview.gz --scenarios teardown \
    --daemon-log 'pathvector_session=debug,pathvectord=debug,warn'
```

`--mrt` takes any RIPE RIS / RouteViews `TABLE_DUMP_V2` file (`.gz` ok):
`curl -O https://data.ris.ripe.net/rrc00/latest-bview.gz`. IPv4 unicast only.
Run `loadtest --help` for every option. The generated daemon config and log
land in `--work-dir` (default `target/loadtest`).

## Reading the output

```
━━ initial convergence (2 loaders × 1133510 prefixes) (6.20 s)
  control peer   2 msgs, longest silence 3.00 s (expected 3.00 s, hold 9.00 s) → OK
  gRPC list_peers 40 probes (0 failed): p50 210 ms, p99 1.94 s, max 1.94 s
  write-lock hold by call site
    kind                          count        total          max
    event_batch                    5686       3.09 s       ≤ 2.50 s
```

- **max** is an *upper bound* — the smallest histogram bucket containing every
  sample in the window — not an exact maximum. Buckets run 100 µs … 30 s.
- **count** for `event_batch` is the number of times the event loop took the
  lock, not the number of UPDATEs; see the `event-loop batches` line for how
  many events were coalesced per hold.
- A window shorter than the keepalive interval can show "0 msgs"; that is
  normal, not a stall. Judge the idle-baseline window first.

## Known limitations

- **Identical tables.** Every loader announces the same dump, so best-path
  selection is a tie-break rather than real multi-upstream churn. The lock
  and event-loop costs are representative; best-path churn is not.
- **Loopback.** No real link latency or loss.
- **The harness perturbs what it measures.** The 10 Hz `list_peers` probe is a
  real management client; on a loaded table it is not free (see the PR-1
  findings in `CHANGELOG.md`). Treat it as a realistic background client,
  not a zero-cost observer.
- **Daemon metrics were unreliable under load** (found by this harness; fixed
  in GH #105). The event loop used to call its metrics hooks only for the first
  event of each coalesced batch, so gauges went stale and `session_up` could
  stick at 1. The harness still settles on Loc-RIB size and reads per-peer
  state over gRPC rather than trusting a single gauge, and it prints a
  `METRIC DISCREPANCY` note whenever a gauge disagrees with the daemon's own
  state, so a regression is visible.
