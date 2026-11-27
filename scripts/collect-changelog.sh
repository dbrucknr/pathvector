#!/usr/bin/env bash
# Folds the per-PR entries in changelog.d/ into CHANGELOG.md, newest date
# first, and deletes the collected files. See changelog.d/README.md.
#
# Every fragment is checked before anything is written, so a bad one leaves
# the working tree untouched. Compatible with macOS's bash 3.2.
set -euo pipefail
export LC_ALL=C

cd "$(dirname "$0")/.."

fragments=()
failed=0
for f in changelog.d/*.md; do
    [ -e "$f" ] || continue
    name=${f##*/}
    [ "$name" = README.md ] && continue
    if [[ ! $name =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}-.+\.md$ ]]; then
        echo "ERROR: $f: name must be YYYY-MM-DD-short-slug.md" >&2
        failed=1
        continue
    fi
    if ! head -n 1 "$f" | grep -q '^## '; then
        echo "ERROR: $f: first line must be a '## ' heading" >&2
        failed=1
        continue
    fi
    fragments+=("$f")
done
[ "$failed" -eq 0 ] || exit 1

if [ "${#fragments[@]}" -eq 0 ]; then
    echo "No changelog fragments to collect."
    exit 0
fi

if ! grep -qx -- '---' CHANGELOG.md; then
    echo "ERROR: CHANGELOG.md has no '---' line to insert after" >&2
    exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

# Header, up to and including the first '---'.
awk '{ print } $0 == "---" { exit }' CHANGELOG.md >"$tmp"

# Fragments, newest first, each followed by a '---' separator. Trailing blank
# lines and separators in a fragment are dropped so they aren't doubled.
for ((i = ${#fragments[@]} - 1; i >= 0; i--)); do
    echo >>"$tmp"
    awk '
        { line[NR] = $0 }
        END {
            n = NR
            while (n > 0 && (line[n] ~ /^[[:space:]]*$/ || line[n] == "---")) n--
            for (j = 1; j <= n; j++) print line[j]
        }
    ' "${fragments[$i]}" >>"$tmp"
    printf '\n---\n' >>"$tmp"
done

# Everything that followed the header.
awk 'found { print } !found && $0 == "---" { found = 1 }' CHANGELOG.md >>"$tmp"

# cat, not mv, to keep CHANGELOG.md's file mode.
cat "$tmp" >CHANGELOG.md
rm -- "${fragments[@]}"

echo "Collected ${#fragments[@]} fragment(s) into CHANGELOG.md."
