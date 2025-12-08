# Release Process

This project uses [Release Please](https://github.com/googleapis/release-please) for automated semantic versioning and releases.

## How It Works

1. **Commit with Conventional Commits**: Use the [Conventional Commits](https://www.conventionalcommits.org/) format for your commit messages:
   - `feat:` - New features (triggers a minor version bump)
   - `fix:` - Bug fixes (triggers a patch version bump)
   - `chore:`, `docs:`, `style:`, `refactor:`, `test:` - No version bump
   - `feat!:` or `fix!:` or `BREAKING CHANGE:` - Breaking changes (triggers a major version bump)

2. **Push to Main**: When you push to the `main` branch, the Release Please GitHub Action will:
   - Analyze your commits since the last release
   - Determine the next version number based on conventional commits
   - Create or update a Release PR with:
     - Updated version in `Cargo.toml`
     - Updated `CHANGELOG.md` with all changes
     - A git tag

3. **Merge the Release PR**: When you merge the Release PR:
   - A GitHub release will be created automatically
   - The `release-assets.yml` workflow will trigger and build binaries for:
     - Linux AMD64
     - Linux ARM64
     - macOS AMD64 (Intel)
     - macOS ARM64 (Apple Silicon)
   - These binaries will be attached to the GitHub release

## Example Commit Messages

```bash
# Patch release (0.1.5 -> 0.1.6)
git commit -m "fix: resolve connection timeout issue"

# Minor release (0.1.5 -> 0.2.0)
git commit -m "feat: add support for custom relay ports"

# Major release (0.1.5 -> 1.0.0)
git commit -m "feat!: redesign protocol for better performance

BREAKING CHANGE: The new protocol is not compatible with previous versions"

# No release
git commit -m "chore: update dependencies"
git commit -m "docs: improve README documentation"
```

## Manual Release

If you need to manually trigger a release or adjust the version:

1. Update the version in `.release-please-manifest.json`
2. Update the version in `Cargo.toml`
3. Push to main - Release Please will pick up the change

## Workflow Files

- `.github/workflows/release-trigger.yml` - Runs Release Please on every push to main
- `.github/workflows/release-assets.yml` - Builds and uploads release binaries when a release is published
- `release-please-config.json` - Configuration for Release Please
- `.release-please-manifest.json` - Tracks the current version



