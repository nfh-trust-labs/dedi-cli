package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
	"github.com/nfh-trust-labs/dedi-cli/internal/sign"
	"github.com/nfh-trust-labs/dedi-cli/internal/validate"
	"github.com/spf13/cobra"
)

func newSignCmd() *cobra.Command {
	var keyPath, inPath, outPath string
	var skipValidation bool

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign an unsigned DeDi manifest or file",
		Long: `Sign an unsigned DeDi manifest or file.

The input JSON should already have every field filled in except "proof" —
this command adds the signing key to the manifest's "keys" array (or the
file's "publisher.key") if it isn't there yet, then adds "proof". Manifest
vs. DeDi file is auto-detected from shape.

Before signing a DeDi file, records[].details is validated against the
registry's inline schema (a URL-referenced schema can't be checked locally
and is skipped automatically). Pass --skip-validation to sign anyway.

If --in is a directory, every top-level *.json file in it is signed with
the same key and written to --out (which must then also be a directory,
created if needed). Batch mode is not transactional: if one file fails,
earlier files already written to --out remain on disk.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyPath == "" || inPath == "" || outPath == "" {
				return fmt.Errorf("--key, --in, and --out are all required")
			}

			key, err := sign.LoadPrivateJWK(keyPath)
			if err != nil {
				return fmt.Errorf(`load key: %w (--key should be a private key JSON file created by "dedi-cli keygen")`, err)
			}
			priv, err := key.PrivateKey()
			if err != nil {
				return fmt.Errorf("key: %w", err)
			}

			inInfo, err := os.Stat(inPath)
			if err != nil {
				return fmt.Errorf("stat --in: %w", err)
			}

			if !inInfo.IsDir() {
				return signFile(cmd.OutOrStdout(), inPath, outPath, key, priv, skipValidation)
			}

			outInfo, err := os.Stat(outPath)
			if err == nil && !outInfo.IsDir() {
				return fmt.Errorf("--in is a directory but --out (%s) is an existing file", outPath)
			} else if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("stat --out: %w", err)
			}
			if err := os.MkdirAll(outPath, 0o755); err != nil {
				return fmt.Errorf("create --out directory: %w", err)
			}

			matches, err := filepath.Glob(filepath.Join(inPath, "*.json"))
			if err != nil {
				return fmt.Errorf("list --in: %w", err)
			}
			for _, match := range matches {
				dst := filepath.Join(outPath, filepath.Base(match))
				if err := signFile(cmd.OutOrStdout(), match, dst, key, priv, skipValidation); err != nil {
					return fmt.Errorf("sign %s: %w", match, err)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&keyPath, "key", "", "path to the private key JSON (required)")
	cmd.Flags().StringVar(&inPath, "in", "", "path to the unsigned manifest/DeDi file JSON, or a directory of them (required)")
	cmd.Flags().StringVar(&outPath, "out", "", "path to write the signed JSON to, or a directory when --in is a directory (required)")
	cmd.Flags().BoolVar(&skipValidation, "skip-validation", false, "skip validating a DeDi file's records against its inline registry schema before signing")
	return cmd
}

// signFile signs a single unsigned manifest/DeDi file at inPath and writes
// the result to outPath.
func signFile(w io.Writer, inPath, outPath string, key sign.PrivateJWK, priv ed25519.PrivateKey, skipValidation bool) error {
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	kind, err := detectDocumentKind(raw)
	if err != nil {
		return err
	}

	var signedJSON []byte
	switch kind {
	case documentKindManifest:
		m, err := protocol.ParseManifest(raw)
		if err != nil {
			return fmt.Errorf("parse manifest: %w", err)
		}
		if err := sign.EnsureManifestKey(m, key.PublicKey()); err != nil {
			return fmt.Errorf("key: %w", err)
		}
		signed, err := sign.SignManifest(*m, priv, key.Kid)
		if err != nil {
			return fmt.Errorf("sign manifest: %w", err)
		}
		if signedJSON, err = json.MarshalIndent(signed, "", "  "); err != nil {
			return fmt.Errorf("marshal signed manifest: %w", err)
		}
	case documentKindDeDiFile:
		f, err := protocol.ParseDeDiFile(raw)
		if err != nil {
			return fmt.Errorf("parse dedi file: %w", err)
		}
		if err := validateBeforeSigning(w, f, skipValidation); err != nil {
			return err
		}
		if err := sign.EnsurePublisherKey(f, key.PublicKey()); err != nil {
			return fmt.Errorf("key: %w", err)
		}
		signed, err := sign.SignDeDiFile(*f, priv)
		if err != nil {
			return fmt.Errorf("sign dedi file: %w", err)
		}
		if signedJSON, err = json.MarshalIndent(signed, "", "  "); err != nil {
			return fmt.Errorf("marshal signed file: %w", err)
		}
	}

	if err := os.WriteFile(outPath, signedJSON, 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	fmt.Fprintf(w, "Signed %s written to %s\n", kind, outPath)
	return nil
}

// validateBeforeSigning checks f.Records against f.Registry.Schema, unless
// the schema is a URL reference (can't be resolved without network access —
// skipped automatically) or skipValidation is set (skipped on request).
func validateBeforeSigning(w io.Writer, f *protocol.DeDiFile, skipValidation bool) error {
	if f.Registry.Schema.IsURL() {
		fmt.Fprintf(w, "registry.schema is a URL reference (%s) — skipping schema validation (no network access); verify manually if needed.\n", f.Registry.Schema.URL)
		return nil
	}
	if skipValidation {
		fmt.Fprintf(w, "schema validation skipped for registry %q (--skip-validation).\n", f.Registry.Name)
		return nil
	}
	schema, err := validate.CompileInlineSchema(f.Registry.Schema.Inline)
	if err != nil {
		return fmt.Errorf("schema validation failed: %w (pass --skip-validation to sign anyway)", err)
	}
	if err := validate.ValidateRecords(f.Records, schema); err != nil {
		return fmt.Errorf("schema validation failed: %w (pass --skip-validation to sign anyway)", err)
	}
	return nil
}

type documentKind string

const (
	documentKindManifest documentKind = "manifest"
	documentKindDeDiFile documentKind = "dedi file"
)

// detectDocumentKind sniffs whether raw is a manifest or a DeDi file by its
// top-level shape: a manifest has a top-level "domain"; a DeDi file has
// "publisher" (whose own "domain" is nested, not top-level) instead. These
// are mutually exclusive per both schemas, and — unlike "keys" or
// "publisher.key" — always present regardless of whether the signing key
// has been added yet, so this sniff works before or after EnsureManifestKey/
// EnsurePublisherKey has run.
func detectDocumentKind(raw []byte) (documentKind, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", fmt.Errorf("parse input: %w", err)
	}
	_, hasDomain := probe["domain"]
	_, hasPublisher := probe["publisher"]
	switch {
	case hasDomain && !hasPublisher:
		return documentKindManifest, nil
	case hasPublisher && !hasDomain:
		return documentKindDeDiFile, nil
	default:
		return "", fmt.Errorf(`could not determine document type: expected exactly one of "domain" (manifest) or "publisher" (dedi file)`)
	}
}
