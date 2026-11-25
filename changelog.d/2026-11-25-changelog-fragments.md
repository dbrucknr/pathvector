## 2026-11-25 (docs: one changelog file per PR)

Every PR inserted its entry at the top of `CHANGELOG.md`, so each merge to `main` put other open
PRs into conflict and resolving it re-ran CI. Replaying 42 recent sync merges, 24 conflicted in
`CHANGELOG.md` and nowhere else.

- PRs now add `changelog.d/YYYY-MM-DD-slug.md` and leave `CHANGELOG.md` alone.
- `scripts/collect-changelog.sh` folds the fragments into `CHANGELOG.md`, newest first.
