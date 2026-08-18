# Contributing

## Building and testing locally

```
go build ./...
go vet ./...
gofmt -l .      # should print nothing; run `gofmt -w .` to fix
go test ./...
```

Run all four before opening a PR — there's no CI yet ([#1](https://github.com/nfh-trust-labs/dedi-cli/issues/1)), so this is the only check in place.

## Pull requests

- Add tests for new behavior. `internal/sign`, `internal/crypto`, `internal/protocol`, and `internal/validate` are well covered; keep it that way.
- Match the existing error-message conventions: errors should be actionable, naming the offending value and, where relevant, how to work around it (e.g. `--skip-validation`). See commit `a006dba` for examples.
- Keep changes scoped — avoid bundling unrelated refactors with a fix or feature.

## Reporting issues

- Bugs and feature requests: open a [GitHub issue](https://github.com/nfh-trust-labs/dedi-cli/issues).
- Security vulnerabilities: do **not** open a public issue — see [SECURITY.md](SECURITY.md).
