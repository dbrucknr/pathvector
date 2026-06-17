# pathvector-mrt

MRT `TABLE_DUMP_V2` replayer for benchmarking and validating pathvectord against a
real-world internet routing table.

---

## What is an MRT file?

MRT (Multi-threaded Routing Toolkit) is a binary format for recording BGP routing table
snapshots and update streams. `TABLE_DUMP_V2` is the variant used by route collectors
like [RIPE NCC RIS](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/)
and [RouteViews](https://www.routeviews.org/) to publish daily snapshots of what they see
from hundreds of BGP peers.

A full-table snapshot (`bview` file) contains the best route for every IPv4 and IPv6
prefix currently in the internet routing table — roughly **900,000–1,100,000 prefixes**
depending on the date.

---

## What does pathvector-mrt do?

It reads an MRT snapshot, converts each entry into a BGP UPDATE message, and sends those
messages to a live `pathvectord` over a real BGP TCP session. Then it polls `pathvectord`
via gRPC until the RIB stabilises.

This measures two things:

1. **Announcement throughput** — how fast can pathvectord accept BGP UPDATEs?
2. **RIB convergence time** — how long from the first UPDATE until the Loc-RIB is stable?

Convergence is detected by snapshot polling: open a fresh `watch_routes` stream, count
`Current` events until `EndInitial`, repeat at `--idle-ms` intervals until two consecutive
snapshots report the same route count. This avoids the broadcast-channel overflow problem
that affects stream-based detection at high update rates.

---

## Quick start

```bash
# Download a RIPE RIS full-table dump (~90 MB gzip)
curl -O https://data.ris.ripe.net/rrc00/latest-bview.gz

# Build, start pathvectord, run the replayer
just mrt ./latest-bview.gz
```

Or manually:

```bash
# 1. Start pathvectord with the MRT config
pathvectord pathvector-e2e/fixtures/mrt-pathvectord.toml &

# 2. Run the replayer
cargo run -p pathvector-mrt --release -- --mrt ./latest-bview.gz
```

---

## Output

```
Parsing MRT dump: ./latest-bview.gz
  Prefixes:   1,133,510
  Parse time: 3.4s

Connecting to gRPC at http://127.0.0.1:51200...
  gRPC reachable

Connecting to BGP peer 127.0.0.1:1179 as AS65001 (router-id 10.0.0.1)
  Session established

Announcing 1,133,510 prefixes...
  Done: 1,133,510 prefixes, 5,438 UPDATE messages, 3.30s (343,920/s)

Waiting for RIB convergence (snapshot polling)...
  snapshot: 892,430 routes
  snapshot: 1,133,415 routes
  snapshot: 1,133,415 routes

── Results ──────────────────────────────────────────────────────
  Announcement:   3.30s  (1,133,510 prefixes, 343,920/s)
  RIB convergence:3.70s  (announcement start to stable snapshot)
  Total:          7.00s
  Unique attr sets: 168,840
  Accepted:  1,133,415 / 1,133,510 sent
  Rejected:  95 (0.0%)
─────────────────────────────────────────────────────────────────
```

### Interpreting the results

- **Announcement time** — wall-clock from the first UPDATE to the last. Limited by TCP
  throughput; pathvectord accepts updates as fast as the socket buffer allows.
- **RIB convergence** — from first UPDATE until the RIB is stable. This is the number
  that matters for production: it tells you how long a restarting daemon needs before its
  routing decisions are reliable again.
- **Accepted vs sent** — the small rejection rate (~0.01%) is expected. The MRT snapshot
  records multiple peer perspectives per prefix; only the best-path winner enters Loc-RIB.

### Benchmark context (Apple M2 Max)

| Metric | Result | Context |
|---|---|---|
| Announcement throughput | **343,920 prefixes/sec** | On par with BIRD 2.x (~100–300k/sec) |
| RIB convergence | **3.70 s** | Between BIRD (~2–5s, written in C) and GoBGP (~15–30s) |
| Total | **7.00 s** | Includes announcement + convergence |

---

## CLI flags

```
pathvector-mrt [OPTIONS] --mrt <FILE>

Options:
  --mrt <FILE>              MRT file to replay (.mrt or .mrt.gz)
  --peer <ADDR>             pathvectord BGP address [default: 127.0.0.1:1179]
  --my-as <AS>              Our BGP AS number [default: 65001]
  --router-id <IP>          Our BGP router-ID [default: 10.0.0.1]
  --grpc <URL>              pathvectord gRPC address [default: http://127.0.0.1:51200]
  --idle-ms <MS>            Snapshot polling interval in milliseconds [default: 1000]
  --timeout-secs <SECS>     Hard timeout before aborting [default: 120]
```

---

## Running tests

```bash
cargo test -p pathvector-mrt
```

---

## License

MIT
