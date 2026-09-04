package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
	"github.com/nfh-trust-labs/dedi-cli/internal/sign"
	"github.com/nfh-trust-labs/dedi-cli/internal/validate"
	"github.com/spf13/cobra"
)

const (
	schemaFetchTimeout  = 10 * time.Second
	schemaFetchMaxBytes = 1 << 20 // 1 MiB

	// nextUpdateExpiringSoonWindow is how close to now next_update has to be
	// (while still in the future) before sign warns that the document will
	// need to be refreshed again soon.
	nextUpdateExpiringSoonWindow = 48 * time.Hour
)

func newSignCmd() *cobra.Command {
	var keyPath, inPath, outPath string
	var skipValidation, force bool

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign an unsigned DeDi manifest or file",
		Long: `Sign an unsigned DeDi manifest or file.

The input JSON should already have every field filled in except "proof" —
this command adds the signing key to the manifest's "keys" array (or the
file's "publisher.key") if it isn't there yet, then adds "proof". Manifest
vs. DeDi file is auto-detected from shape.

Before signing a DeDi file, records[].details is validated against the
registry's schema. If the schema is inline, it's used directly; if it's a
URL reference, sign fetches it with a single GET request (10s timeout, 1MiB
limit) — the only network access this tool ever makes, and only for this.
A fetch failure is treated the same as a validation failure: pass
--skip-validation to sign anyway.

For a beckn_subscriber registry specifically, each record's subscriber_id
is also checked against publisher.domain: it must be that domain itself or
a subdomain of it, the same rule DeDi enforces at registration time (a
record that fails it is silently never reflected in DeDi). --skip-validation
bypasses this check too.

After signing, the resulting manifest or DeDi file is validated against the
protocol's own envelope schema (unknown fields, missing required fields,
enum values like type/registry.state) — this applies to both document
kinds. --skip-validation skips this too.

The manifest's (or file's) next_update is also checked: if it's already in
the past, sign refuses to sign — such a document may silently not be picked
up downstream — unless --force is passed. If it's in the future but within
48 hours, sign proceeds but warns that the document will need to be
refreshed again soon.

If --in is a directory, every top-level *.json file in it is signed with
the same key and written to --out (which must then also be a directory,
created if needed). This is best-effort: every file is attempted even if
some fail, a summary is printed at the end, and the command exits non-zero
if any file failed.`,
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
				return signFile(cmd.OutOrStdout(), inPath, outPath, key, priv, skipValidation, force)
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

			w := cmd.OutOrStdout()
			failed := 0
			for _, match := range matches {
				dst := filepath.Join(outPath, filepath.Base(match))
				if err := signFile(w, match, dst, key, priv, skipValidation, force); err != nil {
					failed++
					fmt.Fprintf(w, "FAILED %s: %v\n", match, err)
				}
			}

			fmt.Fprintf(w, "\n%d of %d files signed", len(matches)-failed, len(matches))
			if failed > 0 {
				fmt.Fprintf(w, ", %d failed\n", failed)
				return fmt.Errorf("%d of %d files failed to sign", failed, len(matches))
			}
			fmt.Fprintln(w)
			return nil
		},
	}

	cmd.Flags().StringVar(&keyPath, "key", "", "path to the private key JSON (required)")
	cmd.Flags().StringVar(&inPath, "in", "", "path to the unsigned manifest/DeDi file JSON, or a directory of them (required)")
	cmd.Flags().StringVar(&outPath, "out", "", "path to write the signed JSON to, or a directory when --in is a directory (required)")
	cmd.Flags().BoolVar(&skipValidation, "skip-validation", false, "skip validating a DeDi file's records against its registry schema (and, for beckn_subscriber, subscriber_id), and skip validating the signed output against the protocol's envelope schema")
	cmd.Flags().BoolVar(&force, "force", false, "sign even if next_update is already in the past")
	return cmd
}

// signFile signs a single unsigned manifest/DeDi file at inPath and writes
// the result to outPath.
func signFile(w io.Writer, inPath, outPath string, key sign.PrivateJWK, priv ed25519.PrivateKey, skipValidation, force bool) error {
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	kind, err := detectDocumentKind(raw)
	if err != nil {
		return err
	}

	if skipValidation {
		fmt.Fprintf(w, "validation skipped for %s (--skip-validation).\n", kind)
	}

	var signedJSON []byte
	switch kind {
	case documentKindManifest:
		m, err := protocol.ParseManifest(raw)
		if err != nil {
			return err
		}
		if err := checkNextUpdate(w, documentKindManifest, m.NextUpdate, force); err != nil {
			return err
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
			return err
		}
		if err := checkNextUpdate(w, documentKindDeDiFile, f.NextUpdate, force); err != nil {
			return err
		}
		if !skipValidation {
			if err := validateRecords(w, raw, f); err != nil {
				return err
			}
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

	if !skipValidation {
		if err := validateEnvelope(signedJSON, kind); err != nil {
			return err
		}
	}

	if err := os.WriteFile(outPath, signedJSON, 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	fmt.Fprintf(w, "Signed %s written to %s\n", kind, outPath)
	return nil
}

// validateEnvelope checks signedJSON — the final signed document — against
// the protocol's own envelope schema for kind. Runs post-sign, not on the
// raw input: both schemas require "proof" (and, for a manifest, "keys"
// with minItems 1), which are only present once signing has filled them
// in — validating the raw pre-sign input against these schemas would fail
// on every invocation.
func validateEnvelope(signedJSON []byte, kind documentKind) error {
	var err error
	switch kind {
	case documentKindManifest:
		err = validate.ValidateManifestEnvelope(signedJSON)
	case documentKindDeDiFile:
		err = validate.ValidateDeDiFileEnvelope(signedJSON)
	}
	if err != nil {
		return fmt.Errorf("envelope validation failed: %w (pass --skip-validation to sign anyway)", err)
	}
	return nil
}

// validateRecords checks f.Records against f.Registry.Schema, and — for a
// beckn_subscriber registry — each record's subscriber_id against
// f.Publisher.Domain. If the schema is a URL reference, it's fetched first
// (the only network access sign ever makes). raw is passed through only so
// a subscriber_id mismatch can be reported with a "line N, column M"
// location.
func validateRecords(w io.Writer, raw []byte, f *protocol.DeDiFile) error {
	inlineSchema := f.Registry.Schema.Inline
	if f.Registry.Schema.IsURL() {
		fmt.Fprintf(w, "fetching registry.schema from %s for validation...\n", f.Registry.Schema.URL)
		fetched, err := fetchSchema(f.Registry.Schema.URL)
		if err != nil {
			return fmt.Errorf("fetch registry.schema from %s: %w (pass --skip-validation to sign without validating)", f.Registry.Schema.URL, err)
		}
		inlineSchema = fetched
	}

	schema, err := validate.CompileInlineSchema(inlineSchema)
	if err != nil {
		return fmt.Errorf("schema validation failed: %w (pass --skip-validation to sign anyway)", err)
	}
	if err := validate.ValidateRecords(f.Records, schema); err != nil {
		return fmt.Errorf("schema validation failed: %w (pass --skip-validation to sign anyway)", err)
	}
	if err := validate.ValidateSubscriberIDs(raw, f); err != nil {
		return fmt.Errorf("subscriber_id validation failed: %w (pass --skip-validation to sign anyway)", err)
	}
	return nil
}

// checkNextUpdate enforces that a document's next_update is not already in
// the past — such a document may silently not be picked up downstream —
// returning an error unless force is set (in which case it warns instead).
// If next_update is in the future but within nextUpdateExpiringSoonWindow,
// it warns rather than failing, since the document will need to be
// refreshed again soon.
func checkNextUpdate(w io.Writer, kind documentKind, nextUpdate time.Time, force bool) error {
	remaining := time.Until(nextUpdate)

	if remaining <= 0 {
		msg := fmt.Sprintf("%s next_update (%s) is in the past — it will not be picked up until updated", kind, nextUpdate.Format(time.RFC3339))
		if !force {
			return fmt.Errorf("%s (pass --force to sign anyway)", msg)
		}
		fmt.Fprintf(w, "warning: %s (--force)\n", msg)
		return nil
	}

	if remaining <= nextUpdateExpiringSoonWindow {
		fmt.Fprintf(w, "warning: %s next_update (%s) is only %s away — this document will need to be refreshed again soon\n",
			kind, nextUpdate.Format(time.RFC3339), remaining.Round(time.Minute))
	}
	return nil
}

// fetchSchema retrieves a URL-referenced JSON Schema, capped at
// schemaFetchTimeout/schemaFetchMaxBytes so a slow or oversized response
// can't hang or balloon sign's memory use.
func fetchSchema(url string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), schemaFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, schemaFetchMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(body) > schemaFetchMaxBytes {
		return nil, fmt.Errorf("response exceeds %d byte limit", schemaFetchMaxBytes)
	}
	return json.RawMessage(body), nil
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
		return "", fmt.Errorf("parse input: %w", protocol.WrapJSONError(raw, err))
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
