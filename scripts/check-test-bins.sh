#!/usr/bin/env bash
# Guards against a [[bin]] target (including auto-discovered src/bin/*.rs
# targets) that Cargo will treat as testable (the `test` field defaults to
# `true`) but isn't a real test harness. Without an explicit `test = false`,
# `cargo test`/`cargo nextest run` invoke the compiled binary with
# `--list --format terse` during discovery; if the binary's real `main`
# doesn't understand that flag and does real work unconditionally (spawns a
# server, connects somewhere, runs a workload), the whole test run hangs
# indefinitely with no error output. This bit `pathvector-stress`'s `stress`
# binary and `pathvector-e2e`'s `mock_rtr_server`/`mock_bgp_peer` (see
# CHANGELOG.md 2026-07-04) before `test = false` was added to each.
#
# Invoked directly (not via `just check-test-bins`) from CI's test job:
# `just` eagerly evaluates every top-level backtick-assigned Justfile
# variable for any recipe invocation, including `nightly-bin`/`cargo-fuzz-bin`
# (used only by the fuzz recipes) — those fail on a runner that hasn't
# installed cargo-fuzz/nightly, which the test job never does. Calling this
# script directly avoids going through `just` (and its unrelated Justfile
# parse-time evaluation) entirely.
set -euo pipefail

failed=0
while IFS=$'\t' read -r name manifest src_path; do
    pkg_dir=$(dirname "$manifest")
    if ! grep -rq '#\[test\]' "$pkg_dir/src" 2>/dev/null; then
        echo "ERROR: bin target '$name' ($src_path) has no #[test] anywhere in its crate's src/, but is not marked test = false in $manifest."
        echo "  cargo test / cargo nextest run will invoke this binary with --list --format terse during discovery."
        echo "  If its main() does real work unconditionally, this hangs the whole test run indefinitely with no error output."
        echo "  Fix: add '[[bin]]' with 'name = \"$name\"' and 'test = false' to $manifest (unless you're adding real #[test]s to this crate)."
        failed=1
    fi
done < <(cargo metadata --format-version 1 --no-deps | jq -r '
    .packages[] | .manifest_path as $manifest | .targets[] |
    select(.kind[] == "bin") | select(.test == true) |
    "\(.name)\t\($manifest)\t\(.src_path)"
')

if [ "$failed" -eq 1 ]; then
    exit 1
fi
echo "OK: every bin target with test=true has real #[test]s in its crate."
