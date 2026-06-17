# Testing in pathvector

This document describes the testing philosophy, patterns, and tooling used across the
pathvector workspace. It covers all seven test layers — unit, doc, property-based, fuzz,
snapshot, end-to-end, and dependency-inversion — and is intended as a reference for
contributors.

---

## What test should I write?

```
New pure function with a correctness invariant that should hold
for all inputs?                                 → proptest (pathvector-types, pathvector-policy, pathvector-rib)

New codec encode/decode path (BGP messages)?    → fuzz target in pathvector-fuzz/
                                                  + unit test in pathvector-session

New CLI command output format?                  → snapshot test (ratatui TestBackend + insta)

New gRPC handler or end-to-end behaviour?       → pathvector-e2e test (Docker + GoBGP)

New DaemonClient method or CLI command?         → unit test via MockDaemonClient in pathvector/src/client_trait.rs
                                                  (no network, no daemon — just inject mock)

New Linux kernel integration?                   → unit test the validation layer cross-platform,
                                                  Linux syscall test in pathvector-sys under
                                                  #[cfg(target_os = "linux")]

Everything else?                                → unit test in a #[cfg(test)] mod tests block
                                                  in the same file as the code being tested
```

---

## Quick Start:
1. `just e2e-images`
2. `just ci`
3. `just lint-linux`

## Philosophy

We strive for transparency and aim for perfection in terms of system reliability.

BGP is a protocol where bugs have real consequences. A routing loop, a missed community
strip, or an incorrect best-path decision can cause traffic to be misdirected or dropped
at internet scale. Testing in pathvector reflects that seriousness:

- **Tests are not an afterthought.** Every public function has at least one unit test.
  Every module maintains close to 100% line coverage.
- **Coverage is measured, not assumed.** We use `llvm-cov` to identify uncovered lines
  after every implementation session and close gaps before moving on. The workspace
  currently targets ≥ 80% line coverage across all crates.
- **Example code is compiled.** All `# Examples` blocks in documentation are compiled
  and executed as part of `cargo test`. A documentation example that drifts from the
  actual API is caught immediately.
- **Invariants are proven, not sampled.** For correctness-critical behaviour we use
  property-based testing to verify that invariants hold across thousands of randomly
  generated inputs — not just the cases we thought to write by hand.
- **The trust boundary is fuzz-tested.** Arbitrary byte input from a remote peer is
  fed through the codec decode path to ensure no panics or memory errors are possible
  regardless of what an adversarial peer sends.
- **UIs are snapshot-tested.** The TUI dashboard render functions are verified against
  stored golden snapshots. Any change to screen layout or text is caught immediately,
  and intentional changes are reviewed and accepted before they become the new baseline.
- **Protocol behaviour is validated against real peers.** The Docker-based e2e suite
  runs `pathvectord` and GoBGP as containers on an isolated bridge network and asserts
  on the full session and route lifecycle.
- **I/O is inverted out of business logic.** The `DaemonClient` trait separates gRPC
  I/O from command dispatch. Every CLI subcommand is unit-tested using `MockDaemonClient`
  without any network connection, giving fast, deterministic, hermetic tests for the
  entire command surface.

---

## Test layers

| Layer | What it covers | Command |
|---|---|---|
| Unit tests | Individual functions, edge cases, RFC-cited behaviour | `cargo test` |
| Doc tests | All `# Examples` blocks compiled and executed | `cargo test` |
| Property tests | Invariants over thousands of random inputs | `cargo test prop_` |
| Fuzz targets | Arbitrary bytes into the codec — no panics ever | `just fuzz-smoke` |
| Snapshot tests | TUI render output locked to golden `.snap` files | `cargo test` |
| End-to-end tests | Full session + route lifecycle against real GoBGP | `just e2e` |
| Dependency inversion | CLI commands tested via `MockDaemonClient`, no network | `cargo test` |

---

## Unit tests

Every source file contains a `#[cfg(test)] mod tests { ... }` block co-located with the
code it tests. Tests are named `test_{type}_{behaviour}`, e.g. `test_asn_is_private`,
`test_aspath_prepend_to_set_creates_new_segment`.

```sh
cargo test -p pathvector-types
cargo test -p pathvector-policy
cargo test                        # all crates in the workspace
```

---

## Doc tests

All `# Examples` blocks in `///` doc comments and in `README.md` files are compiled and
run as doc tests. The `#![doc = include_str!("../README.md")]` pattern in each crate's
`lib.rs` pulls the README into the crate documentation and subjects its code blocks to
the same compilation check.

Where a doc example requires a concrete route type that is not publicly exported (e.g.
in `pathvector-policy`), the example is marked `ignore` with a comment explaining why.

---

## Property-based tests

For behaviour that should hold across all possible inputs we use
[`proptest`](https://crates.io/crates/proptest). Property tests live in a dedicated
`src/prop_tests.rs` module within each crate, included via `#[cfg(test)] mod prop_tests;`
in `lib.rs`. Proptest generates 256 random cases per invariant by default, shrinking
failing cases to the smallest reproducing input automatically.

### `pathvector-types`

| Invariant | Why it matters |
|---|---|
| `u32 → Asn → u32` roundtrip is lossless | Wire encoding depends on exact value preservation |
| `Asn::is_four_byte()` iff value > 65535 | Controls AS_TRANS substitution in the session layer |
| `Asn::is_private()` matches exactly the two IANA ranges | Strip-on-export must not touch public ASNs |
| `AsPath::from_sequence(asns).path_length() == asns.len()` | Path length drives best-path selection |
| `prepend(asn)` always increases `path_length` by exactly 1 | Every re-advertisement must lengthen the path by 1 |
| After `prepend(asn)`, `contains(asn)` is true | Loop detection reads back what prepend wrote |
| `prepend` on a non-empty path preserves `origin_as` | Originating AS must never change during propagation |
| `Community::from_parts(h, l).high() == h` and `.low() == l` | Bit-packing for `high:low` format must be exact |
| `Community::new(v).as_u32() == v` | Raw value preservation |
| `Community::is_well_known()` iff `high() == 0xFFFF` | Well-known community detection cannot miss or over-match |
| `LargeCommunity::from_bytes(lc.to_bytes()) == lc` | 12-byte wire roundtrip must be lossless |
| Large community fields are independent | No field bleeds into another during construction |
| `Nlri::prefix_len()` matches the construction mask | Prefix length must survive storage |
| Masked network address is contained within its own prefix | Fundamental CIDR containment property |
| A prefix always overlaps itself | Self-overlap is an axiom of prefix containment |
| `is_default_route()` iff `prefix_len == 0` | Default route identification used in policy and RIB |
| `is_host_route()` iff `prefix_len == 32` (IPv4) | Host route identification used in blackhole and loopback handling |
| `Origin::from_u8(origin.as_u8()) == Some(origin)` | Wire byte roundtrip must recover the original value |
| `Origin::from_u8(v)` is `None` for v > 2 | Parser must reject invalid origin bytes |
| `LocalPref` ordering matches underlying `u32` | Best-path selection (higher wins) must sort correctly |
| `Med` ordering matches underlying `u32` | Best-path selection (lower wins) must sort correctly |

### `pathvector-session`

| Invariant | Why it matters |
|---|---|
| Encode → decode roundtrip for all five message types | A lossy roundtrip silently corrupts wire messages |
| `prop_decode_never_panics` over arbitrary byte inputs | Codec must not panic regardless of peer input |
| Out-of-range length fields produce errors, not panics | Malformed framing must be rejected cleanly |

### `pathvector-policy`

| Invariant | Why it matters |
|---|---|
| Empty policy always applies the default action | The fallthrough path must never be silently wrong |
| Catch-all Accept term always accepts | `AnyCondition` must genuinely match everything |
| Catch-all Reject term always rejects | Reject is terminal with no escape |
| All-Next terms reach the default action | Fallthrough chain must terminate correctly |
| `PrependAsPath(N)` increases path length by exactly N | Loop prevention depends on accurate path length |
| `RemoveCommunity` never increases community count | A remove operation must not add communities |
| `AddCommunity` increases community count by exactly 1 | Add must be idempotent to count |
| `SetLocalPref(V)` sets local_pref to exactly V | Attribute modification must be exact |
| Community added then matched by `CommunityCondition` | Add + match must be consistent |
| Community added then removed is no longer matched | Round-trip correctness for community manipulation |
| `SetCommunities(V)` replaces the full list with exactly V | Replace must be total, not additive |
| `AnyCondition` always matches; `Not(AnyCondition)` never does | Logical combinators must be correct |
| `ActionSequence` with Accept terminates with Accept | Compound actions must respect terminal decisions |
| `prop_policy_evaluation_is_deterministic` | Same input always produces the same decision |
| `prop_first_match_wins_accept_blocks_later_reject` | A matched Accept never passes to a later Reject term |

### `pathvector-rib`

| Invariant | Why it matters |
|---|---|
| `select_best` winner is always a key in the input candidate map | A phantom-peer winner would corrupt withdrawal tracking |
| Non-empty candidate set always returns `Some` | Spurious `None` silently drops a valid prefix from Loc-RIB |
| `select_best` is deterministic on the same input | Flapping best-path would oscillate FIB installs for a stable set |
| Winner holds highest LOCAL_PREF when all values are distinct | LOCAL_PREF is the primary inbound policy lever |
| `LocRib::is_empty()` and `len() == 0` always agree | Divergence makes capacity checks unreliable |
| `best_routes().count() == len()` after any inserts | Mismatch means a stale best or a prefix with no installed route |
| A single insert always makes `best()` `Some` for that prefix | Missing best after insert would silently black-hole traffic |
| `best_peer()` is always present in `candidates()` for that prefix | Stale best-peer pointer forwards traffic toward a withdrawn next-hop |
| After `withdraw_peer`, exclusively-owned prefixes have no best | Stale best after teardown keeps traffic flowing toward a down peer |
| `AdjRibIn::insert` → `get` roundtrips exactly | Lossy insert corrupts the pre-policy store for soft reconfig |
| Second `AdjRibIn::insert` returns the displaced route | Losing the old route prevents detection of attribute changes |
| `AdjRibIn::withdraw` → `get` returns `None` | Stale entry would be re-installed by soft reconfig |
| `AdjRibOut::insert` → `get` roundtrips exactly | Lossy insert sends a different UPDATE than export policy produced |
| `AdjRibOut::withdraw` → `get` returns `None` | Stale entry suppresses the WITHDRAW the peer must receive |

### `pathvector-sys`

`pathvector-sys` is the sole crate in the workspace permitted to write `unsafe` code. All
unsafe lives in one place — the `apply_tcp_md5sig` Linux path — making it easy to audit
and reason about. The property tests focus on the validation boundary that fires before
any syscall, keeping them cross-platform (they pass on macOS and Linux alike).

| Invariant | Why it matters |
|---|---|
| Keys of 0–80 bytes never produce `InvalidInput` | All keys in the valid range must pass length guard; EBADF (fd=-1) or Ok(()) are acceptable |
| Keys longer than 80 bytes always produce `InvalidInput` | RFC 2385 key length limit; must be enforced before the kernel call |
| Any IPv6 address always returns `Unsupported` | IPv6 peer MD5 is not yet implemented; must not silently succeed |

---

## Fuzz testing

Property tests prove invariants hold for all *valid* inputs generated by a strategy.
Fuzz testing proves that *arbitrary* byte sequences — including ones no sane
implementation would produce — never cause a panic or memory error. These are
complementary: property tests are RFC conformance evidence; fuzz targets are the
panic-safety story for the external attack surface.

The only code reachable from an untrusted remote peer is the session codec decode path.
Every byte received over TCP passes through `BgpCodec::decode` → `BgpMessage::decode`,
so that is what the fuzz targets exercise.

### Targets

| Target | What it covers |
|---|---|
| `session_framing` | Feeds raw `&[u8]` into `BgpCodec::decode`. If the framing layer accepts a frame, the round-trip encode → decode is also exercised. |
| `session_message` | Patches the 2-byte length field to match input length, then calls `BgpMessage::decode` directly. Drives body-parsing for all five message types regardless of framing. |

Targets live in `fuzz/fuzz_targets/` at the workspace root. The seed corpus in
`fuzz/corpus/` pre-populates one valid example of each message type so the fuzzer
starts from real message boundaries rather than discovering the `0xFF × 16` marker
pattern from scratch.

### Nightly requirement and the macOS PATH issue

`cargo fuzz` uses `-Zsanitizer=address`, which requires a nightly compiler. On macOS
with Rust installed via Homebrew, `cargo` is a standalone stable binary that ignores
`rust-toolchain.toml`. Two env-var tricks that look like they should work but don't:

- `CARGO=<nightly-path> cargo fuzz ...` — Homebrew's `cargo` overwrites `CARGO` before
  spawning subcommands.
- `~/.rustup/toolchains/.../bin/cargo fuzz ...` — `cargo-fuzz` hardcodes
  `Command::new("cargo")` and never reads the `CARGO` env var.

**The only lever that works is `PATH`**: if the nightly bin directory appears before
Homebrew's, the hardcoded `"cargo"` lookup resolves to nightly. The `Justfile` handles
this automatically using `rustup which --toolchain nightly cargo`.

### Running fuzz targets

Install `just` once: `cargo install just`. Then from the workspace root:

| Recipe | What it does |
|---|---|
| `just fuzz-build` | Compile all targets — fast compile check, no fuzzing |
| `just fuzz-smoke` | 60 s smoke run of every target — what CI runs |
| `just fuzz-framing` | Extended run of `session_framing` — runs until Ctrl-C |
| `just fuzz-message` | Extended run of `session_message` — runs until Ctrl-C |

The fuzzer saves new interesting inputs to `fuzz/corpus/` automatically. Commit a
grown corpus back to the repo so future runs start from a richer baseline.

**Reproducing a crash:** inputs are saved to `fuzz/artifacts/<target>/crash-<hash>`.
Reproduce with:

```sh
just fuzz-framing fuzz/artifacts/session_framing/crash-<hash>
```

### Editor support (Zed)

The fuzz crate declares its own `[workspace]` (required by `cargo fuzz`) so rust-analyzer
does not index it by default. `.zed/settings.json` adds it as a linked project for full
LSP support. Other editors: add `"rust-analyzer.linkedProjects": ["fuzz/Cargo.toml"]`.

---

## Snapshot tests

The TUI dashboard (`pathvector/src/dashboard.rs`) renders peers and routes into a
ratatui widget tree. Snapshot testing locks the exact text output of each render
function to a golden file. If a commit accidentally changes column widths, truncates
values, or drops a row, the test fails immediately — before the change ships.

### How it works

[`insta`](https://crates.io/crates/insta) stores golden files in
`pathvector/src/snapshots/`. Each test renders a private widget function into a
`ratatui::backend::TestBackend` (an in-memory, headless terminal buffer), converts
the buffer to a string via `TestBackend`'s `Display` impl, and asserts it matches
the stored snapshot:

```rust
let output = render_to_string(80, 6, |f| {
    let area = f.area();
    render_peers(f, &state, area);
});
insta::assert_snapshot!(output);
```

The snapshot files are plain text and look exactly like the terminal output:

```
"┌ Peers ───────────────────────────────────────────────────────────────────────┐"
"│ADDRESS          REMOTE-AS  TYPE  STATE        UPTIME    RCV   ACC   ADV      │"
"│10.0.0.1         65001      eBGP  Established  01:01:01  5     4     3        │"
"│                                                                              │"
"│                                                                              │"
"└──────────────────────────────────────────────────────────────────────────────┘"
```

### The elapsed-time problem

The status bar renders `last_refresh.elapsed()` — a value that changes every
second. To make snapshots deterministic, the elapsed calculation is extracted into
a pure helper:

```rust
pub(crate) fn build_status_bar_line(
    addr: &str,
    elapsed_secs: u64,
    error: Option<&str>,
) -> Line<'static> { ... }
```

The live render path calls this with the real elapsed seconds; tests call it with
a fixed value such as `0` or `65`. The status bar branches (normal vs. error) are
covered by targeted `assert!` tests on the span content and style, not snapshots.

### Reviewing snapshot changes

When you intentionally change the dashboard layout:

1. Run `cargo test -p pathvector` — failing tests produce `.snap.new` files alongside
   the existing `.snap` files in `pathvector/src/snapshots/`.
2. Inspect the diff to confirm the change is intentional.
3. Accept: `cargo insta review` (interactive) or rename `.snap.new` → `.snap` manually.
4. Commit both the code change and the updated `.snap` files together.

Never accept a snapshot change you haven't read. The diff is the contract.

### Snapshot coverage

| Test | What it locks |
|---|---|
| `snapshot_render_peers_empty` | Peers pane with no peers (header + empty body) |
| `snapshot_render_peers_established` | Peers pane with one eBGP established peer |
| `snapshot_render_peers_idle` | Peers pane with one iBGP idle peer (yellow state colour) |
| `snapshot_render_routes_empty` | Routes pane with no routes (header + empty body) |
| `snapshot_render_routes_with_route` | Routes pane with one route (all columns populated) |

---

## Dependency inversion

The `DaemonClient` trait in `pathvector-client` is the seam between I/O and logic.
Any code that calls the daemon accepts `impl DaemonClient` instead of the concrete
`PathvectorClient`, which lets tests inject a `MockDaemonClient` without any network
or process dependency.

### Pattern

```rust
// Production
async fn run() -> Result<(), CliError> {
    let args = Cli::parse();
    run_with(args, |addr| PathvectorClient::connect(addr).map_err(CliError::from)).await
}

// Testable core
async fn run_with<C: DaemonClient, F: FnOnce(&str) -> Result<C, CliError>>(
    args: Cli,
    connect: F,
) -> Result<(), CliError> { ... }

// Test
async fn run_cmd(args: &[&str], mock: MockDaemonClient) -> Result<(), CliError> {
    let cli = Cli::parse_from(args);
    run_with(cli, |_addr| Ok(mock)).await
}
```

### MockDaemonClient

`MockDaemonClient` lives in `pathvector/src/client_trait.rs` under `#[cfg(test)]`.
It stores canned responses for every `DaemonClient` method and records calls for
later inspection:

```rust
let mut mock = MockDaemonClient::new();
mock.peers = vec![...];                    // canned list_peers response
mock.force_error = Some(ClientError::...); // force all methods to fail
// after run:
assert_eq!(mock.import_calls, [("10.0.0.1".to_owned(), true)]);
```

The `DashboardState::refresh` method follows the same pattern — it accepts
`&mut impl DaemonClient`, so the same mock works for dashboard tests too.

### CLI test coverage

Every subcommand is covered by at least one happy-path and one error-path test,
giving deterministic, sub-millisecond feedback for the full command surface without
spinning up a daemon:

| Area | Tests |
|---|---|
| `peer list` | empty, with peers, propagates error |
| `peer get` | found, not found, invalid IP |
| `route list` | empty, with routes, peer filter, invalid peer filter |
| `route best` | found, not found |
| `route candidates` | empty, with results |
| `policy set-import` | accept, reject |
| `policy set-export` | accept, reject |

---

## End-to-end tests

Unit tests and property tests verify *internal consistency* — roundtrips, invariants,
and RFC-cited edge cases. They cannot catch interoperability bugs: if both sides of a
`tests/transport.rs` session share the same codec bug, they will silently agree.

The `pathvector-e2e` crate closes this gap by running `pathvectord` and GoBGP as Docker
containers on an isolated bridge network, then asserting on the full session and route
lifecycle through the `PathvectorClient` management API.

### Why Docker for both daemons

GoBGP only ships Linux binaries — there are no macOS prebuilts. Running both services in
containers means the suite works identically on macOS and Linux without any native
dependency installation. More importantly, BGP (port 179) stays container-to-container
on the Docker bridge network. The macOS Docker Desktop TCP proxy only intercepts
host→container connections; container-to-container traffic goes through the Linux kernel
bridge directly, which is what allows the handshake to complete on macOS.

### Architecture

```
  ┌──────────────────────────────────────────────────────────────┐
  │  Test process (host)                                          │
  │                                                               │
  │  pathvector-e2e crate                                         │
  │    │                                                          │
  │    ├── PathvectorClient ─── gRPC (HTTP/2) ──────────────┐    │
  │    │     localhost:<dynamic host port>                   │    │
  │    │                                                     │    │
  │    └── testcontainers-rs ── docker exec (gobgp CLI) ─┐  │    │
  │                                                       │  │    │
  └───────────────────────────────────────────────────────┼──┼────┘
                                                          │  │
  ┌── Docker bridge network (per-test) ──────────────────▼──▼────┐
  │                                                               │
  │  gobgpd container              pathvectord container          │
  │  image: pathvector-gobgpd-test image: pathvector-e2e          │
  │                                                               │
  │    ◄────── BGP session (port 179, container-to-container) ──► │
  │                                                               │
  └───────────────────────────────────────────────────────────────┘
```

Each `Harness::new()` creates a fresh `docker network create` with a unique name, removed
on `Drop`, giving complete isolation between tests. The harness calls `docker inspect`
to obtain the `gobgpd` container's bridge IP (required because `PeerConfig.address` is
`Ipv4Addr`, not a hostname), then writes a per-test `pathvectord.toml` bind-mounted into
the `pathvectord` container. Routes are injected via `docker exec <id> gobgp global rib add`.

### Docker images

| Image | Built from | Purpose |
|---|---|---|
| `pathvector-gobgpd-test:latest` | `pathvector-e2e/Dockerfile` | GoBGP 4.6.0 on Alpine; includes `gobgp` CLI |
| `pathvector-e2e:latest` | `pathvector-e2e/Dockerfile.pathvectord` | Multi-stage Rust build; debian:bookworm-slim runtime |

Both are Linux/arm64 on Apple Silicon and Linux/amd64 on x86 CI runners. The GoBGP
version is pinned in the `Justfile` (`gobgp-version := "4.6.0"`).

> **After changing pathvectord source code, always rebuild the image before running
> e2e tests.** The image embeds the compiled binary; `just e2e` does this automatically.
> Running tests against a stale image is the most common source of confusing failures —
> a `serde(default)` field added to config will be silently ignored by an old binary.

### Running the suite

**Prerequisite: Docker must be running.**

```sh
# Build both images, then run all e2e tests serially.
just e2e
```

To run a single test:

```sh
just e2e-images
cargo test -p pathvector-e2e -- --test-threads=1 announced_route_appears_in_rib
```

To start the compose environment for manual inspection:

```sh
just e2e-up    # start gobgpd + pathvectord in the background
just e2e-logs  # stream logs
just e2e-down  # stop and clean up
```

### Scenario coverage

#### Session (`session.rs`)

| Test | RFC | What it proves |
|---|---|---|
| `session_reaches_established` | RFC 4271 §8 | OPEN + KEEPALIVE exchange succeeds end-to-end |
| `peer_state_fields_correct_after_established` | RFC 4271 §8 | AS numbers, peer type, hold-time populated correctly |
| `list_peers_includes_gobgp_peer` | RFC 4271 §8 | Management API reflects live session state |
| `wait_for_established_respects_deadline` | — | Test harness deadline fires correctly |
| `wait_for_route_respects_deadline` | — | Route polling helper respects deadline |
| `wait_for_route_withdrawn_respects_deadline` | — | Withdrawal polling helper respects deadline |

#### Routes (`routes.rs`)

| Test | RFC | What it proves |
|---|---|---|
| `announced_route_appears_in_rib` | RFC 4271 §9.2 | IPv4 UPDATE received and installed in Loc-RIB with correct attributes |
| `withdrawn_route_removed_from_rib` | RFC 4271 §9.3 | IPv4 WITHDRAW removes route from Loc-RIB |
| `multiple_routes_all_installed` | RFC 4271 §9.2 | Multiple prefixes handled correctly; `list_routes` returns all |
| `partial_withdrawal_leaves_others_intact` | RFC 4271 §9.3 | Withdraw of one prefix does not disturb others |
| `list_candidates_returns_peer_route` | RFC 4271 §9.1 | Candidate map populated; `list_candidates` API works |
| `unknown_prefix_returns_none` | RFC 4271 §9.1 | `get_best_route` returns `None` for absent prefix |
| `announced_v6_route_appears_in_rib` | RFC 4760 | IPv6 MP_REACH_NLRI UPDATE installed in `loc_rib_v6` |
| `withdrawn_v6_route_removed_from_rib` | RFC 4760 | IPv6 MP_UNREACH_NLRI removes route from `loc_rib_v6` |

#### Policy (`policy.rs`)

| Test | RFC | What it proves |
|---|---|---|
| `no_import_policy_rejects_ebgp_prefix` | RFC 8212 §4 | eBGP default-reject: no import policy → route blocked |
| `explicit_import_accept_installs_ebgp_prefix` | RFC 8212 | Positive control: explicit accept → route installed |
| `no_export_policy_suppresses_advertisement_to_peer` | RFC 8212 §4 | eBGP default-reject: no export policy → route not forwarded |
| `explicit_export_accept_propagates_to_sink` | RFC 8212 | Positive control: explicit accept → route forwarded to sink |
| `soft_reconfig_import_accept_installs_route` | — | Runtime `SetImportDefault(Accept)` installs routes without session teardown |
| `soft_reconfig_export_accept_propagates_to_sink` | — | Runtime `SetExportDefault(Accept)` propagates routes to sink without session teardown |
| `import_default_v6_reject_blocks_ipv6_allows_ipv4` | — | `import_default_v6 = "reject"` blocks IPv6 while `import_default = "accept"` admits IPv4 from the same peer |

#### Authentication (`auth.rs`)

| Test | RFC | What it proves |
|---|---|---|
| `md5_matching_key_session_establishes` | RFC 2385 | Matching `md5_password` on both sides → BGP session reaches Established |
| `md5_key_mismatch_session_never_establishes` | RFC 2385 | Mismatched keys → session cannot establish; **CI-only** (see note below) |

> **CI-only gate on the negative MD5 test.** TCP MD5SIG is enforced at the Linux kernel
> level. Docker Desktop on macOS runs inside a Linux VM whose kernel is built without
> `CONFIG_TCP_MD5SIG`. On that host, `setsockopt(TCP_MD5SIG)` in the container succeeds
> (the call is accepted by the kernel and silently ignored), so mismatched keys still
> allow the TCP handshake through — the negative test would pass for the wrong reason.
> GitHub Actions CI runners use native Linux Docker where `CONFIG_TCP_MD5SIG` is always
> compiled in. `md5_key_mismatch_session_never_establishes` is gated on `CI=1` so it
> only asserts on a host that can actually enforce the kernel-level check.
>
> The positive test (`md5_matching_key_session_establishes`) runs everywhere: even when
> `setsockopt` is a no-op, both sides have TCP MD5SIG configured consistently and the
> session reaches Established.

#### Outbound propagation (`outbound.rs`)

| Test | RFC | What it proves |
|---|---|---|
| `announced_route_propagates_to_sink` | RFC 4271 §9.2 | Route accepted from source → re-advertised to sink peer |
| `multiple_routes_all_propagate_to_sink` | RFC 4271 §9.2 | Multiple prefixes each forwarded |
| `withdrawn_route_removed_from_sink` | RFC 4271 §9.3 | Withdrawal from source → WITHDRAW sent to sink |
| `source_route_visible_in_pathvectord_rib` | RFC 4271 §9.2 | Intermediate Loc-RIB correctly populated in two-peer topology |
| `originated_v6_route_propagates_to_gobgp` | RFC 4760 | IPv6 origination → MP_REACH_NLRI forwarded to GoBGP |

#### Origination (`origination.rs`)

| Test | RFC | What it proves |
|---|---|---|
| `originated_route_appears_in_rib` | RFC 4271 §9.2 | Originated route injected via gRPC appears in Loc-RIB |
| `originated_route_propagates_to_gobgp` | RFC 4271 §9.2 | Originated route forwarded to established eBGP peer |
| `withdrawn_originated_route_removed_from_rib` | RFC 4271 §9.3 | Withdrawal removes originated route from Loc-RIB |
| `withdrawn_originated_route_removed_from_gobgp` | RFC 4271 §9.3 | Withdrawal sends WITHDRAW to peer; GoBGP removes it |
| `batch_originate_all_propagate` | RFC 4271 §9.2 | Batch origination: all prefixes forwarded in one or more UPDATEs |
| `list_originated_routes_tracks_state` | — | `list_originated_routes` gRPC reflects current originated set |
| `re_originate_same_prefix_replaces_route` | RFC 4271 §9.2 | Re-originating a prefix updates attributes and re-advertises |
| `originated_route_has_correct_attributes` | RFC 4271 §5 | ORIGIN, NEXT_HOP, AS_PATH, LOCAL_PREF set correctly |
| `withdraw_then_reoriginate_reappears_in_gobgp` | RFC 4271 §9.2 | Withdraw → re-originate sends a fresh UPDATE (not suppressed) |
| `withdraw_nonexistent_is_noop` | — | Withdrawing an unknown prefix does not panic or corrupt state |
| `batch_withdraw_removes_specified_prefixes` | RFC 4271 §9.3 | Batch withdrawal removes exactly the specified set |
| `originated_route_with_blackhole_community_propagates` | RFC 7999 | BLACKHOLE-tagged route forwarded to peers that accept it |
| `originated_and_peer_routes_coexist` | RFC 4271 §9.2 | Local originated routes and peer-received routes coexist correctly |

### Protocol validation notes

These are lessons from the initial GoBGP interoperability validation (2026-05-31) that
are worth recording even though the Docker suite now handles automated testing.

| Symptom | Cause | Fix applied |
|---|---|---|
| NOTIFICATION Code 2 Subcode 3 (Bad BGP Identifier) | `bgp_id` in `127.0.0.0/8` — GoBGP rejects loopback BGP IDs | Use a non-loopback address, e.g. `10.0.0.2` |
| Session drops on first UPDATE | `FourByteAsn` capability omitted — GoBGP sends 2-byte AS_PATH, decoder reads 4 bytes per ASN | Added `Capability::FourByteAsn(local_as)` to `SessionConfig::capabilities` |
| Repeated self-connection NOTIFICATIONs | GoBGP dials its own listener without `passive-mode` | Set `passive-mode = true` in GoBGP neighbor transport config |

---

## TCP MD5 authentication safety (`pathvector-sys`)

RFC 2385 (TCP MD5) is a security feature. We hold it to a higher standard than ordinary
protocol code: the same bug that accepts a wrong key would silently let a spoofed session
through. This section documents every layer of assurance applied to `apply_tcp_md5sig`.

### Isolation

All `unsafe` code in the workspace lives in `pathvector-sys` and nowhere else. Every
other crate, including `pathvectord`, inherits `unsafe_code = "forbid"` from the
workspace `Cargo.toml`. `pathvector-sys` overrides this to `unsafe_code = "allow"` only
for the one function that calls `setsockopt`. The isolation means a code reviewer can
audit the entire unsafe surface by reading a single 60-line function.

The kernel struct (`tcp_md5sig`) is defined locally in `pathvector-sys/src/tcp.rs` as
`#[repr(C)] struct TcpMd5Sig` rather than using `libc::tcp_md5sig`. This is because
`libc::tcp_md5sig` is not exposed on all Linux target architectures in all `libc`
versions (notably absent on `aarch64` in `libc 0.2.x`). The local definition matches
the kernel ABI exactly (`<linux/tcp.h>`), documented with field offsets and sizes.

### Validation layers

| Layer | What it checks | Test |
|---|---|---|
| Input validation (pre-syscall) | Key > 80 bytes → `InvalidInput` before any kernel call | `test_key_too_long_returns_error` |
| Input validation (pre-syscall) | Key at exactly 80 bytes passes the guard | `test_key_at_exact_limit_passes_length_guard` |
| Input validation (pre-syscall) | IPv6 address → `Unsupported` (not yet implemented) | `test_ipv6_returns_unsupported` |
| Syscall success path (Linux) | Real `TcpListener` fd → `setsockopt` succeeds | `test_apply_succeeds_on_real_socket_linux` |
| Syscall idempotence (Linux) | Calling twice on the same peer updates the key | `test_apply_twice_same_peer_succeeds_linux` |
| Syscall error path (Linux) | Invalid fd → OS error, not panic or `InvalidInput` | `test_invalid_fd_returns_os_error_linux` |
| Property: valid key range | All keys 0–80 bytes never produce `InvalidInput` | `prop_key_within_limit_never_rejected_for_length` |
| Property: over-limit key | All keys > 80 bytes always produce `InvalidInput` | `prop_key_over_limit_always_rejected` |
| Property: IPv6 | Any IPv6 address always returns `Unsupported` | `prop_ipv6_always_unsupported` |
| E2E interop (positive) | Matching keys → BGP session reaches Established against real GoBGP | `md5_matching_key_session_establishes` |
| E2E interop (negative, CI) | Mismatched keys → session never establishes on native Linux | `md5_key_mismatch_session_never_establishes` |

### Platform behaviour

| Platform | `setsockopt(TCP_MD5SIG)` | Enforcement | Notes |
|---|---|---|---|
| Linux (native) | Succeeds if `CAP_NET_ADMIN` held | Kernel enforces signature on every segment | CI and production |
| Linux in Docker Desktop VM | Returns `ENOPROTOOPT` (no `CONFIG_TCP_MD5SIG`) | Not enforced | Handled: `ENOPROTOOPT`/`EOPNOTSUPP` → `Ok(())` with a warning; session continues |
| macOS (native) | No-op; `#[cfg(not(target_os = "linux"))]` | Not enforced | Development-only; no kernel path taken |

The graceful-degrade on `ENOPROTOOPT` is the reason the positive e2e test passes on
macOS: both sides are configured consistently, the no-op call succeeds, and the session
establishes without kernel-level authentication — which is the correct behaviour for a
host that cannot enforce it.

---

## Coverage measurement

We use `cargo-llvm-cov` to measure line and branch coverage.

```sh
# Install once
cargo install cargo-llvm-cov

# Run with line coverage report
cargo llvm-cov --workspace

# Identify uncovered lines in a specific crate
cargo llvm-cov -p pathvector-policy --show-missing-lines
```

**Current coverage (approximate, measured on M2 Max):**

| Crate | Lines |
|---|---|
| `pathvector-types` | ≈ 95% |
| `pathvector-session` | ≈ 90% |
| `pathvector-policy` | ≈ 95% |
| `pathvector-rib` | ≈ 90% |
| `pathvector-sys` | ≈ 85% |
| `pathvector-client` | ≈ 75% |
| `pathvector` (CLI) | ≈ 80% |

**Deliberately uncovered:**
- `pathvectord/src/main.rs` — binary entry point; cannot call `main` in unit tests.
- `pathvector/src/main.rs::main` — same reason; the `run_with` core is covered.
- `dashboard::run_dashboard` — requires a real crossterm terminal; covered indirectly
  by `DashboardState::refresh` and snapshot tests of the render functions.
- Doc examples marked `ignore` — require a concrete route type not available in doc-test scope.
- `apply_linux` on non-Linux — the Linux kernel path is `#[cfg(target_os = "linux")]`;
  macOS coverage runs exclude it by definition.

---

## Correctness approaches by concern

### Type safety

- **Newtypes** prevent mixing conceptually distinct `u32` values. `Asn`, `LocalPref`,
  `Med`, and `Community` are all newtypes — you cannot pass a `Med` where an `Asn` is
  expected.
- **Sealed traits** (`IpAddress` in `ipnetx`, `EvaluateTerm` in `pathvector-policy`)
  prevent external code from implementing internal interfaces.
- **`unsafe_code = "forbid"`** is enforced at the workspace level. The single exception
  is `pathvector-sys`, which overrides to `"allow"` and is the designated home for all
  unsafe code in the workspace. No other crate may write `unsafe`.

### BGP protocol correctness

| Behaviour | RFC | Test |
|---|---|---|
| AS path prepend inserts at front of first Sequence segment | RFC 4271 §5.1.2 | `test_aspath_prepend_to_sequence` |
| Prepend creates new Sequence when first segment is a Set | RFC 4271 §5.1.2 | `test_aspath_prepend_to_set_creates_new_segment` |
| Prepend creates new Sequence when first segment has 255 ASNs | RFC 4271 §5.1.2 | `test_aspath_prepend_overflow_creates_new_segment` |
| `AS_SET` counts as 1 in path length | RFC 4271 §9.1.2.2 | `test_aspath_path_length_set_counts_as_one` |
| Confederation segments count as 0 in path length | RFC 5065 | `test_aspath_path_length_confed_counts_as_zero` |
| `NO_EXPORT` is `0xFFFFFF01` | RFC 1997 | `test_community_well_known_no_export` |
| `BLACKHOLE` community value `0xFFFF029A` | RFC 7999 | `test_community_blackhole` |
| Extended community transitivity bit | RFC 4360 | `test_extended_community_non_transitive` |
| Route Target type/subtype byte layout | RFC 4360 | `test_extended_community_route_target_as2` |
| `LOCAL_PREF` absent on eBGP routes matches no condition | RFC 4271 §5.1.5 | `test_local_pref_condition_absent` |
| `MED` absent matches no condition | RFC 4271 §5.1.4 | `test_med_condition_absent` |
| Policy first-match-wins semantics | — | `test_first_match_wins` |
| Non-matching term does not modify route | — | `test_non_matching_term_does_not_modify_route` |

### Edge cases targeted by hand

- `PrefixListCondition` specificity: a less-specific route does NOT match a list
  containing only a more-specific entry (`10.0.0.0/8` does not match a list with
  `10.1.0.0/24`).
- `CompareOp::Equal` and `CompareOp::NotEqual` inside `LocalPrefCondition` and
  `MedCondition` — not just `GreaterOrEqual` and `LessThan`.
- `LocalPref(0)` and `Med(u32::MAX)` as boundary values.
- Combined modifying actions (`SetLocalPref + AddCommunity + Accept`) verified to apply
  all modifications before accepting.
- Multiple `Next`-returning terms verified to accumulate modifications across term
  boundaries.

---

## Running the full test suite

```sh
# All tests, all crates (fast, no Docker required)
cargo test

# Property tests only
cargo test prop_

# Fuzz smoke run (requires nightly)
just fuzz-smoke

# End-to-end tests (requires Docker)
just e2e

# Everything CI runs, in the same order
just ci
```

---

## Adding tests for new code

When adding a new type or function:

1. Write at least one unit test in the `#[cfg(test)] mod tests` block of the same file.
2. Write a `# Examples` block in the doc comment — it will be compiled automatically.
3. If the function has edge cases (optional attributes, empty collections, boundary
   values), add explicit tests for each.
4. If the function has a correctness invariant that should hold for all inputs, add a
   proptest.
5. If the function is on the external attack surface (decode path, gRPC handler), add a
   fuzz target or extend an existing one.
6. If the function renders a TUI widget or formats visible output, add a snapshot test
   using `ratatui::backend::TestBackend` and `insta::assert_snapshot!`. Commit the
   generated `.snap` file alongside the code.
7. If the function makes network or I/O calls, extract an `impl Trait` seam so tests
   can inject a mock. Follow the `DaemonClient` / `MockDaemonClient` pattern.
8. Run coverage and close any remaining gaps before committing.
