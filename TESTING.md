# Testing in pathvector

This document describes the testing philosophy, patterns, and tooling used across the pathvector workspace. It is intended as a reference for contributors and as documentation for anyone curious about how correctness is established in a BGP implementation.

---

## Philosophy

BGP is a protocol where bugs have real consequences. A routing loop, a missed community strip, or an incorrect best-path decision can cause traffic to be misdirected or dropped at internet scale. Testing in pathvector reflects that seriousness:

- **Tests are not an afterthought.** Every public function has at least one unit test. Every module maintains close to 100% line coverage.
- **Coverage is measured, not assumed.** We use `llvm-cov` to identify uncovered lines after every implementation session and close gaps before moving on.
- **Example code is compiled.** All `# Examples` blocks in documentation are compiled and executed as part of `cargo test`. A documentation example that drifts from the actual API is caught immediately.
- **Invariants are proven, not sampled.** For correctness-critical behaviour, we use property-based testing to verify that invariants hold across thousands of randomly generated inputs — not just the cases we thought to write by hand.

---

## Test layers

### Unit tests

Every source file contains a `#[cfg(test)] mod tests { ... }` block co-located with the code it tests. This keeps tests close to the implementation and makes it easy to see what is and is not covered when reading a module.

Tests are named `test_{type}_{behaviour}`, e.g. `test_asn_is_private`, `test_aspath_prepend_to_set_creates_new_segment`.

```
cargo test -p pathvector-types
cargo test -p pathvector-policy
cargo test                        # all crates in the workspace
```

### Doc tests

All `# Examples` blocks in `///` doc comments and in `README.md` files are compiled and run as doc tests. This means:

- Example code that fails to compile is a test failure.
- Example code whose assertions fail is a test failure.
- Documentation that drifts from the API is caught automatically.

The `#![doc = include_str!("../README.md")]` pattern in each crate's `lib.rs` pulls the README into the crate documentation and subjects its code blocks to the same compilation check.

Where a doc example requires a concrete route type that is not publicly exported (e.g. in `pathvector-policy`), the example is marked `ignore` with a comment explaining why.

### Property-based tests

For behaviour that should hold across all possible inputs — not just the cases we thought of — we use [`proptest`](https://crates.io/crates/proptest).

Property tests live in a dedicated `src/prop_tests.rs` module within each crate that uses them, included via `#[cfg(test)] mod prop_tests;` in `lib.rs`.

Each property test defines a **strategy** (how to generate random inputs) and an **invariant** (what must always be true). Proptest generates 256 random cases per invariant by default, shrinking failing cases to the smallest reproducing input automatically.

**Current property-tested invariants in `pathvector-types`:**

| Invariant | Why it matters |
|---|---|
| `u32 → Asn → u32` roundtrip is lossless | Wire encoding depends on exact value preservation |
| `Asn::is_four_byte()` iff value > 65535 | Controls AS_TRANS substitution logic in the session layer |
| `Asn::is_private()` matches exactly the two IANA ranges | Strip-on-export logic must not touch public ASNs |
| `AsPath::from_sequence(asns).path_length() == asns.len()` | Path length drives best-path selection |
| `prepend(asn)` always increases `path_length` by exactly 1 | Every re-advertisement must lengthen the path by 1 |
| After `prepend(asn)`, `contains(asn)` is true | Loop detection reads back what prepend wrote |
| `prepend` on a non-empty path preserves `origin_as` | The originating AS must never change during propagation |
| `Community::from_parts(h, l).high() == h` and `.low() == l` | Bit-packing for the `high:low` community format must be exact |
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

**Current property-tested invariants in `pathvector-policy`:**

| Invariant | Why it matters |
|---|---|
| Empty policy always applies the default action | Ensures the fallthrough path is never silently wrong |
| Catch-all Accept term always accepts | Validates that `AnyCondition` genuinely matches everything |
| Catch-all Reject term always rejects | Validates that Reject is terminal with no escape |
| All-Next terms reach the default action | Verifies the fallthrough chain terminates correctly |
| `PrependAsPath(N)` increases path length by exactly N | Loop prevention depends on accurate path length |
| `RemoveCommunity` never increases community count | A remove operation must not add communities |
| `AddCommunity` increases community count by exactly 1 | Add must be idempotent to count |
| `SetLocalPref(V)` sets local_pref to exactly V | Attribute modification must be exact |
| Community added then matched by `CommunityCondition` | Add + match must be consistent |
| Community added then removed is no longer matched | Round-trip correctness for community manipulation |
| `SetCommunities(V)` replaces the full list with exactly V | Replace must be total, not additive |
| `AnyCondition` always matches; `Not(AnyCondition)` never does | Logical combinators must be correct |
| `ActionSequence` with Accept terminates with Accept | Compound actions must respect terminal decisions |
| `ActionSequence` with Reject terminates with Reject | Same for Reject |

---

## Coverage measurement

We use `cargo-llvm-cov` to measure line and branch coverage. After each implementation session, we run coverage and close any uncovered lines before committing.

```bash
# Install once
cargo install cargo-llvm-cov

# Run with line coverage report
cargo llvm-cov --workspace

# Identify uncovered lines in a specific crate
cargo llvm-cov -p pathvector-policy --show-missing-lines
```

**What we deliberately leave uncovered:**

- `pathvectord/src/main.rs` — the binary entry point. Unit tests cannot execute a `main` function; this is expected and not a gap.
- Doc examples marked `ignore` — these require a concrete route type not available in doc-test scope.

---

## Correctness approaches by concern

### Type safety

- **Newtypes** prevent mixing conceptually distinct `u32` values. `Asn`, `LocalPref`, `Med`, and `Community` are all newtypes — you cannot pass a `Med` where an `Asn` is expected.
- **Sealed traits** (`IpAddress` in `ipnetx`, `EvaluateTerm` in `pathvector-policy`) prevent external code from implementing internal interfaces, preserving invariants the implementation depends on.
- **No `unsafe` code** is permitted anywhere in the workspace. This is enforced by a workspace-level lint: `unsafe_code = "forbid"`.

### BGP protocol correctness

Protocol-specific behaviour is tested against the relevant RFC:

| Behaviour | RFC | Test |
|---|---|---|
| AS path prepend inserts at front of first Sequence segment | RFC 4271 §5.1.2 | `test_aspath_prepend_to_sequence` |
| Prepend creates new Sequence when first segment is a Set | RFC 4271 §5.1.2 | `test_aspath_prepend_to_set_creates_new_segment` |
| Prepend creates new Sequence when first segment has 255 ASNs | RFC 4271 §5.1.2 | `test_aspath_prepend_overflow_creates_new_segment` |
| `AS_SET` counts as 1 in path length regardless of size | RFC 4271 §9.1.2.2 | `test_aspath_path_length_set_counts_as_one` |
| Confederation segments count as 0 in path length | RFC 5065 | `test_aspath_path_length_confed_counts_as_zero` |
| `NO_EXPORT` is a well-known community (`0xFFFFFF01`) | RFC 1997 | `test_community_well_known_no_export` |
| `BLACKHOLE` community value (`0xFFFF029A`) | RFC 7999 | `test_community_blackhole` |
| Extended community transitivity bit (bit 6) | RFC 4360 | `test_extended_community_non_transitive` |
| Route Target type/subtype byte layout | RFC 4360 | `test_extended_community_route_target_as2` |
| `LOCAL_PREF` absent on eBGP routes matches no condition | RFC 4271 §5.1.5 | `test_local_pref_condition_absent` |
| `MED` absent matches no condition | RFC 4271 §5.1.4 | `test_med_condition_absent` |
| Policy first-match-wins semantics | — | `test_first_match_wins` |
| Non-matching term does not modify route | — | `test_non_matching_term_does_not_modify_route` |

### Edge cases targeted by hand

Beyond the property-based invariants, specific edge cases are tested explicitly because they are protocol boundary conditions or common sources of bugs:

- `PrefixListCondition` specificity direction: a less-specific route does NOT match a prefix-list containing only a more-specific entry. (e.g. `10.0.0.0/8` does not match a list containing `10.1.0.0/24`.)
- `CompareOp::Equal` and `CompareOp::NotEqual` exercised inside `LocalPrefCondition` and `MedCondition` — not just `GreaterOrEqual` and `LessThan`.
- `LocalPref(0)` and `Med(u32::MAX)` as boundary values.
- Combined modifying actions (`SetLocalPref + AddCommunity + Accept`) verified to apply all modifications before accepting.
- Multiple `Next`-returning terms verified to accumulate modifications across term boundaries.

---

## Running the full test suite

```bash
# All tests, all crates
cargo test

# With output for failing tests
cargo test -- --nocapture

# Property tests only
cargo test prop_

# Coverage report (requires cargo-llvm-cov)
cargo llvm-cov --workspace --open
```

---

## Adding tests for new code

When adding a new type or function:

1. Write at least one unit test in the `#[cfg(test)] mod tests` block of the same file.
2. Write a `# Examples` block in the doc comment — it will be compiled automatically.
3. If the function has edge cases (optional attributes, empty collections, boundary values), add explicit tests for each.
4. If the function has a correctness invariant that should hold for all inputs, add a proptest.
5. Run coverage and close any remaining gaps before committing.
