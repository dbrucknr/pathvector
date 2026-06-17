# pathvector-stress

Synthetic load harness for pathvectord.  No Docker required — spawns daemons
as local subprocesses and drives route injection through each daemon's native
gRPC API.

## What it measures

**Stage 1 — pathvectord only**

| Metric | How |
|---|---|
| Convergence time | Wall clock from first `originate_routes` call to last batch returning |
| Peak RSS | `ps -p <pid> -o rss=` sampled every 500 ms |
| Final RSS | RSS snapshot after origination completes |
| Error / warn count | pathvectord stderr lines containing `ERROR` / `WARN` |

Three escalating phases: 10k → 100k → 500k prefixes, accumulated (500k run
includes all routes from the previous phases).

**Withdrawal phase** — withdraws all 500k routes and reports how much RSS is
reclaimed.  Normal allocator page-retention means only ~7% is returned to the
OS immediately; this is expected and not a leak.

**Churn phase** — announces and withdraws the same 10k prefixes 5 times.  RSS
should be flat across cycles; any growth indicates a memory leak.

**Stage 1b — GoBGP 1:1 comparison**

Runs the same three phases against GoBGP 4.x using `AddPathStream` (GoBGP's
client-streaming batch RPC), then prints a side-by-side table of convergence
time and peak RSS.

---

## Prerequisites

### Always required

- Rust (stable, MSRV 1.86+)
- `protoc` on `PATH` — the build script compiles GoBGP v4 proto files

  macOS: `brew install protobuf`

### GoBGP comparison only

- GoBGP 4.x installed — the harness looks for `gobgpd` in `$GOPATH/bin` then
  falls back to `PATH`

  ```
  go install github.com/osrg/gobgp/v4/cmd/gobgpd@latest
  ```

  Verify: `gobgpd --version` should print `gobgpd version 4.x.x`.

---

## Running

### Quick start (pathvectord phases only, dev build)

```
just stress
```

This builds `pathvectord` and `stress` in debug mode and runs all phases.
Debug builds are slower; use the release variant for numbers worth recording.

### Release build — recommended for benchmark results

```
cargo build --release -p pathvectord -p pathvector-stress
./target/release/stress
```

Or via just:

```
just stress-release
```

### GoBGP comparison

The GoBGP comparison runs automatically as the final section of `just stress`
(or `./target/release/stress`).  If `gobgpd` is not found the harness exits
with a clear error message rather than silently skipping the comparison.

To skip the GoBGP comparison and run only the pathvectord phases, comment out
the `gobgp_bench::run(...)` call in `src/main.rs` (no flag exists yet — this
is intentional; the comparison is the main point of the harness).

---

## Ports used

| Port | Daemon | Notes |
|---|---|---|
| 59372 | pathvectord gRPC | Chosen to avoid Docker Desktop's range and the standard 51200 |
| 59373 | gobgpd gRPC | One above pathvectord; `--api-hosts :59373` flag |
| 11179 | pathvectord BGP | Non-privileged alternative to 179 |

If a run crashes without killing its child processes, orphans can hold these
ports.  Clean them up with:

```bash
lsof -ti :59372 :59373 | xargs kill -9
```

---

## Interpreting results

### Convergence time

Time from the first batch call to the last batch returning.  Both daemons use
their native gRPC batch APIs (`originate_routes` / `AddPathStream`) so the
comparison is API-to-API, not wire-BGP-to-wire-BGP.  The numbers reflect RIB
insertion throughput plus gRPC serialisation overhead.

### Peak RSS

Sampled by `ps` every 500 ms.  On macOS, this matches Activity Monitor
(resident set size).  The harness seeds `fetch_max` with the pre-phase RSS so
peak is always ≥ baseline.

### Ratio column

`Ratio (pv/go) < 1.0` means pathvectord is faster.  `> 1.0` means GoBGP is
faster.

---

## Baseline results (2026-06-17, Apple M2 Max, release binary)

### Convergence time

| Phase | pathvectord | GoBGP 4.5.0 | Ratio (pv/go) |
|---|---|---|---|
| 10k  | 0.03 s | 0.05 s | 0.48× |
| 100k | 0.21 s | 0.38 s | 0.54× |
| 500k | 0.85 s | 1.62 s | 0.52× |

pathvectord converges ~2× faster than GoBGP at all three sizes.

### Peak RSS

| Phase | pathvectord | GoBGP 4.5.0 |
|---|---|---|
| 10k  | 33.9 MB  | 50.7 MB  |
| 100k | 265.1 MB | 121.3 MB |
| 500k | 1.4 GB   | 451.8 MB |

pathvectord uses ~3× more memory than GoBGP at 500k routes (~2.6 KB/route vs
~0.9 KB/route).  The gap is attributed to per-route attribute cloning rather
than attribute interning — every route stores its own copy of next-hop, local-
pref, and origin even when thousands of routes share the same values.

---

## Architecture notes

- `src/main.rs` — pathvectord phases, withdrawal, churn
- `src/gobgp_bench.rs` — GoBGP comparison phase
- `proto/api/` — GoBGP v4 proto files copied from the Go module cache
- `build.rs` — `tonic-prost-build` compiles the proto files; `protoc` required

The GoBGP client is generated at build time from the v4 proto.  If you upgrade
GoBGP, copy the new proto files from `$GOPATH/pkg/mod/github.com/osrg/gobgp/v4@vX.Y.Z/proto/api/`
into `proto/api/` and rebuild.

---

## Platform support

Tested on macOS (M2 Max).  `ps -p <pid> -o rss=` is macOS-specific; on Linux,
the harness would need to read `/proc/<pid>/status` instead.  The RSS sampler
is the only platform-specific piece — all other harness logic is portable.
