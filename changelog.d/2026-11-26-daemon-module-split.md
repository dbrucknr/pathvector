## 2026-11-26 (pathvectord: `daemon/mod.rs` split into smaller modules)

A structural change with no intended change in behaviour. `daemon/mod.rs` had grown to about
21,700 lines, most of them inline tests.

- The inline test modules moved to `daemon/tests/`, grouped by topic. Test function names are
  unchanged; their module paths are not (`daemon::stall_tests` is now `daemon::tests::stall`).
- Production code moved to `bootstrap`, `command`, `peering`, `state`, `rib_snapshot`,
  `rpki_feed` and `event_loop`. The module docs in `daemon/mod.rs` say which layer each is in.
- Log events from the moved code carry the new module path as their target. A filter on
  `pathvectord::daemon` still matches them.
