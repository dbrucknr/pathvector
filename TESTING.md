# Testing in pathvector

This document describes the testing philosophy, patterns, and tooling used across the
pathvector workspace. It covers all five test layers — unit, doc, property-based, fuzz,
and end-to-end — and is intended as a reference for contributors.

---

## Philosophy

BGP is a protocol where bugs have real consequences. A routing loop, a missed community
strip, or an incorrect best-path decision can cause traffic to be misdirected or dropped
at internet scale. Testing in pathvector reflects that seriousness:

- **Tests are not an afterthought.** Every public function has at least one unit test.
  Every module maintains close to 100% line coverage.
- **Coverage is measured, not assumed.** We use `llvm-cov` to identify uncovered lines
  after every implementation session and close gaps before moving on.
- **Example code is compiled.** All `# Examples` blocks in documentation are compiled
  and executed as part of `cargo test`. A documentation example that drifts from the
  actual API is caught immediately.
- **Invariants are proven, not sampled.** For correctness-critical behaviour we use
  property-based testing to verify that invariants hold across thousands of randomly
  generated inputs — not just the cases we thought to write by hand.
- **The trust boundary is fuzz-tested.** Arbitrary byte input from a remote peer is
  fed through the codec decode path to ensure no panics or memory errors are possible
  regardless of what an adversarial peer sends.
- **Protocol behaviour is validated against real peers.** The Docker-based e2e suite
  runs `pathvectord` and GoBGP as containers on an isolated bridge network and asserts
  on the full session and route lifecycle.

---

## Test layers

| Layer | What it covers | Command |
|---|---|---|
| Unit tests | Individual functions, edge cases, RFC-cited behaviour | `cargo test` |
| Doc tests | All `# Examples` blocks compiled and executed | `cargo test` |
| Property tests | Invariants over thousands of random inputs | `cargo test prop_` |
| Fuzz targets | Arbitrary bytes into the codec — no panics ever | `just fuzz-smoke` |
| End-to-end tests | Full session + route lifecycle against real GoBGP | `just e2e` |

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
| `pathvector-gobgpd-test:latest` | `e2e/Dockerfile` | GoBGP 4.6.0 on Alpine; includes `gobgp` CLI |
| `pathvector-e2e:latest` | `e2e/Dockerfile.pathvectord` | Multi-stage Rust build; debian:bookworm-slim runtime |

Both are Linux/arm64 on Apple Silicon and Linux/amd64 on x86 CI runners. The GoBGP
version is pinned in the `Justfile` (`gobgp-version := "4.6.0"`).

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

| Test | File | RFC | What it proves |
|---|---|---|---|
| `session_reaches_established` | session.rs | RFC 4271 §8 | OPEN + KEEPALIVE exchange succeeds end-to-end |
| `peer_state_fields_correct_after_established` | session.rs | RFC 4271 §8 | AS numbers, peer type, hold-time populated correctly |
| `list_peers_includes_gobgp_peer` | session.rs | RFC 4271 §8 | Management API reflects live session state |
| `wait_for_established_respects_deadline` | session.rs | — | Test harness deadline fires correctly |
| `announced_route_appears_in_rib` | routes.rs | RFC 4271 §9.2 | UPDATE received and installed in Loc-RIB with correct attributes |
| `withdrawn_route_removed_from_rib` | routes.rs | RFC 4271 §9.3 | WITHDRAW removes route from Loc-RIB |
| `multiple_routes_all_installed` | routes.rs | RFC 4271 §9.2 | Multiple prefixes handled correctly; `list_routes` returns all |
| `partial_withdrawal_leaves_others_intact` | routes.rs | RFC 4271 §9.3 | Withdraw of one prefix does not disturb others |
| `list_candidates_returns_peer_route` | routes.rs | RFC 4271 §9.1 | Candidate map populated; `list_candidates` API works |
| `unknown_prefix_returns_none` | routes.rs | RFC 4271 §9.1 | `get_best_route` returns `None` for absent prefix |

### Protocol validation notes

These are lessons from the initial GoBGP interoperability validation (2026-05-31) that
are worth recording even though the Docker suite now handles automated testing.

| Symptom | Cause | Fix applied |
|---|---|---|
| NOTIFICATION Code 2 Subcode 3 (Bad BGP Identifier) | `bgp_id` in `127.0.0.0/8` — GoBGP rejects loopback BGP IDs | Use a non-loopback address, e.g. `10.0.0.2` |
| Session drops on first UPDATE | `FourByteAsn` capability omitted — GoBGP sends 2-byte AS_PATH, decoder reads 4 bytes per ASN | Added `Capability::FourByteAsn(local_as)` to `SessionConfig::capabilities` |
| Repeated self-connection NOTIFICATIONs | GoBGP dials its own listener without `passive-mode` | Set `passive-mode = true` in GoBGP neighbor transport config |

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

**Deliberately uncovered:**
- `pathvectord/src/main.rs` — the binary entry point; unit tests cannot call `main`.
- Doc examples marked `ignore` — require a concrete route type not available in doc-test scope.

---

## Correctness approaches by concern

### Type safety

- **Newtypes** prevent mixing conceptually distinct `u32` values. `Asn`, `LocalPref`,
  `Med`, and `Community` are all newtypes — you cannot pass a `Med` where an `Asn` is
  expected.
- **Sealed traits** (`IpAddress` in `ipnetx`, `EvaluateTerm` in `pathvector-policy`)
  prevent external code from implementing internal interfaces.
- **No `unsafe` code** anywhere in the workspace, enforced by workspace-level lint:
  `unsafe_code = "forbid"`.

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
6. Run coverage and close any remaining gaps before committing.
