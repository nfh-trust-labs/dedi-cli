# Contributing

## Building and testing locally

```
go build ./...
go vet ./...
gofmt -l .      # should print nothing; run `gofmt -w .` to fix
go test ./...
```

Run all four before opening a PR — CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs the same checks on push and on every PR, across `ubuntu-latest`, `macos-latest`, and `windows-latest`, but running them locally first saves a round trip.

## Building release binaries locally

Real releases are cut by tagging (see "Releasing" below), but you can build the same cross-platform binaries locally at any time — e.g. to sanity-check a change on an OS/arch you don't have, or to hand someone a binary before an official release exists. This uses [GoReleaser](https://goreleaser.com) in snapshot mode, which skips tagging and publishing entirely:

```
go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=publish
```

This cross-compiles `dedi-cli` for linux/darwin/windows × amd64/arm64 (no cgo involved, so no OS-specific toolchain needed) and writes archives + `checksums.txt` to `dist/` (gitignored). The binaries are stamped with a snapshot version like `0.0.0-SNAPSHOT-<commit>` — check with `dedi-cli --version` after extracting.

## Pull requests

- Add tests for new behavior. `internal/sign`, `internal/crypto`, `internal/protocol`, and `internal/validate` are well covered; keep it that way.
- Match the existing error-message conventions: errors should be actionable, naming the offending value and, where relevant, how to work around it (e.g. `--skip-validation`). See commit `a006dba` for examples.
- Keep changes scoped — avoid bundling unrelated refactors with a fix or feature.

## Releasing

Pushing a tag matching `v*` (e.g. `v0.1.0`) triggers [.github/workflows/release.yml](.github/workflows/release.yml), which runs GoReleaser in real release mode: it builds the same cross-platform binaries as above, generates `checksums.txt`, writes a changelog from the commits since the last tag, and publishes all of it as a GitHub Release — no manual steps beyond the tag push.

```
git tag v0.1.0
git push origin v0.1.0
```

## Reporting issues

- Bugs and feature requests: open a [GitHub issue](https://github.com/nfh-trust-labs/dedi-cli/issues).
- Security vulnerabilities: do **not** open a public issue — see [SECURITY.md](SECURITY.md).
