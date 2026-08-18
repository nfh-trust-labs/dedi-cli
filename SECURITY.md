# Security Policy

## Supported versions

`dedi-cli` does not yet have tagged releases ([#2](https://github.com/nfh-trust-labs/dedi-cli/issues/2)); only the latest commit on `main` is supported.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Instead, use GitHub's private vulnerability reporting: go to the
[Security tab](https://github.com/nfh-trust-labs/dedi-cli/security) of this
repository and click "Report a vulnerability". This opens a private advisory
visible only to you and the maintainers.

Given that `dedi-cli` handles private key material (Ed25519 signing keys) and
implements the DeDi protocol's signature scheme, please include:

- The affected version/commit
- Steps to reproduce
- The potential impact (e.g. key exposure, signature forgery, validation bypass)

## Response process

We aim to acknowledge new reports within 5 business days. If the report is
confirmed, we'll work on a fix and coordinate disclosure timing with you
before any public advisory is published.
