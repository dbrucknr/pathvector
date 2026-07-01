# Releasing pathvector

## The short version

```bash
# Make sure main is clean and CI is green first, then:
git tag v0.1.0
git push origin v0.1.0
```

That's it. GitHub Actions handles everything else automatically.

---

## What happens when you push a tag

Pushing a `v*.*.*` tag triggers two jobs in `.github/workflows/publish.yml`:

**`publish` job** (also runs on every main push)
- Builds the `pathvectord` Docker image
- Pushes it to `ghcr.io/dbrucknr/pathvector` with tags `:v0.1.0`, `:v0.1`, and `:sha-<short>`

**`release` job** (tag pushes only)
- Builds static binaries in parallel across 4 targets (~15–20 min total):

  | Archive | What it is |
  |---|---|
  | `pathvectord-v0.1.0-x86_64-unknown-linux-musl.tar.gz` | Daemon, Linux x86_64, fully static |
  | `pathvectord-v0.1.0-aarch64-unknown-linux-musl.tar.gz` | Daemon, Linux arm64, fully static |
  | `pathvector-v0.1.0-x86_64-unknown-linux-musl.tar.gz` | CLI, Linux x86_64, fully static |
  | `pathvector-v0.1.0-aarch64-unknown-linux-musl.tar.gz` | CLI, Linux arm64, fully static |
  | `pathvector-v0.1.0-aarch64-apple-darwin.tar.gz` | CLI, macOS Apple Silicon |
  | `pathvector-v0.1.0-x86_64-apple-darwin.tar.gz` | CLI, macOS Intel |

- Creates a GitHub Release at `github.com/dbrucknr/pathvector/releases/tag/v0.1.0`
- Attaches all 6 archives as downloadable assets
- Auto-generates release notes from merged PRs since the last tag

---

## Step-by-step checklist

1. **Verify CI is green on main** — check `github.com/dbrucknr/pathvector/actions` before tagging. The release workflow does not wait for CI; a broken tag is harder to undo than a skipped one.

2. **Update `CHANGELOG.md`** — add a section for the new version. Keep the existing format (date + bullet items).

3. **Choose a version number** — pathvector follows [SemVer](https://semver.org/):
   - `PATCH` (`v0.1.1`) — bug fixes, no API changes
   - `MINOR` (`v0.2.0`) — new features, backwards-compatible
   - `MAJOR` (`v1.0.0`) — breaking changes (not yet; project is pre-1.0)

4. **Create and push the tag from main:**
   ```bash
   git checkout main
   git pull
   git tag v0.1.0
   git push origin v0.1.0
   ```

5. **Watch the Actions run** — go to the Actions tab and open the "Publish" workflow triggered by the tag. Both `publish` and `release` jobs should appear. The `release` matrix shows 4 parallel jobs, one per target.

6. **Verify the release page** — once the jobs finish, go to `github.com/dbrucknr/pathvector/releases`. The new release should have 6 `.tar.gz` assets attached and auto-generated release notes listing the PRs included since the last tag.

---

## If something goes wrong

**A release job failed mid-way** — fix the underlying issue (e.g., a compile error on one target), then delete the tag and re-push:
```bash
git tag -d v0.1.0                  # delete local tag
git push origin :refs/tags/v0.1.0  # delete remote tag
# fix the issue, then re-tag
git tag v0.1.0
git push origin v0.1.0
```
The existing GitHub Release (if partially created) will be overwritten.

**You tagged the wrong commit** — same procedure as above. Delete both the local and remote tag, then re-tag the correct commit.

**The `aarch64-unknown-linux-musl` build failed inside cross** — this target builds inside a Docker container. If protoc installation fails, check `Cross.toml` at the workspace root. The `pre-build` hook must install `protobuf-compiler` before cargo runs.

---

## Installing a released binary (reference)

```bash
# On a Linux x86_64 server:
curl -L https://github.com/dbrucknr/pathvector/releases/latest/download/pathvectord-v0.1.0-x86_64-unknown-linux-musl.tar.gz \
  | tar xz
sudo mv pathvectord /usr/local/bin/

# Verify:
pathvectord --version
```
