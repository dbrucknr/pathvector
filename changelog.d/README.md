# Changelog fragments

**Don't edit `CHANGELOG.md` in a pull request.** Add a new file here instead.

Every PR used to insert its entry at the top of `CHANGELOG.md`, so each merge
put the other open PRs into conflict, and resolving it re-ran CI. Separate
files don't conflict.

## Adding an entry

Create `changelog.d/YYYY-MM-DD-short-slug.md`. Include the issue number or
branch topic in the slug so that two PRs don't pick the same name.

The file holds one entry, written exactly as it will appear in `CHANGELOG.md`:

```markdown
## 2026-01-31 (crate: what changed — issue #123)

Why it was wrong or missing, what it does now, the RFC clause if one applies,
and the tests that prove it.
```

The first line must be the `## ` heading. Don't add a trailing `---`.

## Collecting

```bash
./scripts/collect-changelog.sh
```

This moves every fragment to the top of `CHANGELOG.md`, newest date first, and
deletes the fragment files. Run it before a release (see `RELEASING.md`), or
whenever the directory gets crowded, and commit the result on its own.
