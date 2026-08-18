# dedi-cli

`dedi-cli` generates Ed25519 keypairs, signs DeDi manifests/files, and locally
verifies signatures — for a publisher who wants to sign and check their own
DeDi files by hand, without needing the [DeDi crawler](https://github.com/nfh-trust-labs/dedi-crawler)
or any network access.

## Install

```
go install github.com/nfh-trust-labs/dedi-cli/cmd/dedi-cli@latest
```

(Requires Go. Pre-built binaries aren't published yet — that's a planned
follow-up.)

Or build from a clone:

```
git clone https://github.com/nfh-trust-labs/dedi-cli.git
cd dedi-cli
go build -o dedi-cli ./cmd/dedi-cli
```

## keygen

```
dedi-cli keygen --kid my-key-1 --out key.json
```

Writes the private key to `key.json` (mode `0600` on Unix — keep it secret;
see "Key handling" below) and prints the public JWK for reference. Refuses to
overwrite an existing `key.json` unless you also pass `--force`:

```
dedi-cli keygen --kid my-key-1 --out key.json --force
```

## sign

```
dedi-cli sign --key key.json --in unsigned.json --out signed.json
```

Reads an unsigned manifest or DeDi file, auto-detecting which one from its
shape (a top-level `domain` means a manifest, a top-level `publisher` means a
DeDi file). The input should have every field filled in except the signing
key and `proof`:

- If the manifest's `keys` array (or the file's `publisher.key`) doesn't yet
  contain a key matching `--key`, `sign` adds it.
- If it already contains an entry for that key's `kid` but with different key
  material, `sign` errors out rather than silently overwriting it — that
  combination almost always means the wrong `--key` was passed, or the input
  has stale key data.
- It then computes the JCS-canonicalized signing input and writes `proof`
  (`verification_method`, `canonicalization`, `jws`).

**Schema validation.** Before signing a DeDi file, `sign` validates
`records[].details` against the registry's `schema`:

- If `registry.schema` is an inline JSON Schema object, every record is
  validated against it. A violation fails the command with an error naming
  the offending record and reminding you how to bypass it:
  `schema validation failed: record "r1": ... (pass --skip-validation to sign anyway)`.
- If `registry.schema` is a URL reference, it can't be resolved without
  network access, so validation is skipped automatically with a printed
  notice — verify the records against that schema yourself before signing.
- Pass `--skip-validation` to skip inline-schema validation on purpose (e.g.
  you've already validated elsewhere). This does not validate the envelope
  itself (unknown fields, enum values, etc.) — only `records[].details`
  against `registry.schema`.

**Batch mode.** If `--in` is a directory, every top-level `*.json` file in it
(non-recursive) is signed with the same `--key` and written to `--out`, which
must then also be a directory (created automatically if it doesn't exist),
preserving filenames:

```
dedi-cli sign --key key.json --in unsigned/ --out signed/
```

Batch mode is **not transactional**: if one file fails partway through, files
already written to `--out` before the failure remain on disk.

## verify

```
dedi-cli verify --in signed.json
```

Checks that `proof.jws` is a valid signature over the document (recomputing
the same JCS canonicalization `sign` uses). This is a purely local check —
unlike the crawler's full verification chain, it does **not** check
domain-binding, freshness, registry state, or that the signing key is listed
in a trusted manifest; those require a live crawl.

By default, `verify` trusts whatever key is embedded in the document itself
(`keys[]` for a manifest, `publisher.key` for a file) — this only proves the
document is internally self-consistent, not that the key is one you actually
trust. Pass `--key` with a public JWK file (the same JSON `keygen` prints) to
check the signature against a key you already trust instead:

```
dedi-cli verify --in signed.json --key trusted_key_pub.json
```

## Key handling

- Private keys are stored as plain JSON files (RFC 8037-style JWK, `d` is the
  raw Ed25519 seed) — there's no OS keychain or secret-manager integration.
  Treat `key.json` like a password: never commit it, and back it up somewhere
  safe if you'll need to re-sign later.
- `keygen` writes private keys with file mode `0600` on Unix (owner
  read/write only). **On Windows, Go's file-permission bits are largely
  ignored** — the OS's own file/folder permissions are what actually protect
  the file there, so lock down the containing folder yourself.
- The public JWK (`kid`, `kty`, `crv`, `x`) printed by `keygen` is safe to
  share — it's what goes into a signed manifest's `keys[]` and what you'd
  hand to someone else to `verify --key` against.

## Deliberately out of scope

- A `publish` subcommand — writing to `.well-known/dedi.index.json` and
  hosting it is a real operational workflow, a different problem than
  signing.
- Resolving and validating against a URL-referenced `registry.schema` — this
  tool makes no network calls; `sign` skips it automatically and `verify`
  doesn't check schemas at all.
- Validating that the unsigned input itself structurally conforms to the
  protocol's own manifest/DeDi file envelope schemas (`additionalProperties:
  false`, required fields, enums like `type`/`state`) — `sign` only goes as
  far as parsing into Go structs, which is lenient in exactly the ways JSON
  Schema is strict (e.g. a typo'd `type` or an extra unknown property is
  silently accepted).
- Cross-file trust-chain checks (is this file's key actually listed in a
  verified manifest?), domain-binding, and freshness/expiry — these need a
  live crawl context (`verify` only checks the signature itself).
