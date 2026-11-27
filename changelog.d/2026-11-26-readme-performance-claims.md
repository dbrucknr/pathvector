## 2026-11-26 — README claims match what was measured

- Removed the BIRD and GoBGP figures next to the MRT replay results; no run of
  either daemon through that replay backs them.
- Relabelled the stress-test timings: each is the time to add that phase's routes
  over gRPC, not to converge a table of that size.
- Described MRT announcement time and throughput as UPDATE construction plus
  transmission, since the timer covers both.
- Removed the "~99% fewer UPDATE messages" claim, and corrected when MRT
  convergence timing starts and the `--idle-ms` default.
- Dropped "production-quality" and "published crate" from the root README.
