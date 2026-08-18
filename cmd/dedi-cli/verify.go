package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nfh-trust-labs/dedi-cli/internal/crypto"
	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
	"github.com/spf13/cobra"
)

func newVerifyCmd() *cobra.Command {
	var inPath, keyPath string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Locally verify a signed DeDi manifest or file's signature",
		Long: `Locally verify a signed DeDi manifest or file's signature.

This only checks that "proof.jws" is a valid signature over the document,
under RFC 8785 JCS canonicalization. It does not check domain-binding,
freshness, registry state, or that the signing key is listed in a trusted
manifest — those require a live crawl and are the crawler's job, not this
tool's.

By default the document's own embedded key is used (keys[] for a manifest,
publisher.key for a file), which only proves the document is internally
consistent — not that the key itself is trustworthy. Pass --key with a
public JWK file (the same JSON keygen prints) to check against a key you
already trust instead.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if inPath == "" {
				return fmt.Errorf("--in is required")
			}

			raw, err := os.ReadFile(inPath)
			if err != nil {
				return fmt.Errorf("read input: %w", err)
			}

			kind, err := detectDocumentKind(raw)
			if err != nil {
				return err
			}

			var jws string
			var embeddedKey protocol.Key
			var kid string

			switch kind {
			case documentKindManifest:
				m, err := protocol.ParseManifest(raw)
				if err != nil {
					return fmt.Errorf("parse manifest: %w", err)
				}
				k, found := findKeyByKid(m.Keys, m.Proof.VerificationMethod)
				if !found {
					return fmt.Errorf("verification_method %q not found in manifest keys[] (the document may be malformed or was hand-edited after signing)", m.Proof.VerificationMethod)
				}
				embeddedKey, jws, kid = k, m.Proof.JWS, m.Proof.VerificationMethod
			case documentKindDeDiFile:
				f, err := protocol.ParseDeDiFile(raw)
				if err != nil {
					return fmt.Errorf("parse dedi file: %w", err)
				}
				if f.Proof.VerificationMethod != f.Publisher.Key.Kid {
					return fmt.Errorf("verification_method %q does not match publisher.key.kid %q (the document may be malformed or was hand-edited after signing)",
						f.Proof.VerificationMethod, f.Publisher.Key.Kid)
				}
				embeddedKey, jws, kid = f.Publisher.Key, f.Proof.JWS, f.Publisher.Key.Kid
			}

			verifyKey := embeddedKey
			usedTrustedKey := false
			if keyPath != "" {
				raw, err := os.ReadFile(keyPath)
				if err != nil {
					return fmt.Errorf(`read --key: %w (--key should be a public JWK JSON file, e.g. the one "dedi-cli keygen" prints)`, err)
				}
				if err := json.Unmarshal(raw, &verifyKey); err != nil {
					return fmt.Errorf(`parse --key: %w (--key should be a public JWK JSON file, e.g. the one "dedi-cli keygen" prints)`, err)
				}
				usedTrustedKey = true
			}

			pub, err := verifyKey.Ed25519PublicKey()
			if err != nil {
				return fmt.Errorf("key: %w", err)
			}

			signingInput, err := crypto.SigningInput(raw)
			if err != nil {
				return fmt.Errorf("canonicalize: %w", err)
			}
			if err := crypto.Verify(pub, signingInput, jws); err != nil {
				return fmt.Errorf("signature verification failed: %w", err)
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "OK: %s signature is valid (kid=%s)\n", kind, kid)
			if !usedTrustedKey {
				fmt.Fprintln(w, "note: verified against the key embedded in the document itself — this proves")
				fmt.Fprintln(w, "internal consistency, not that the key is trusted. Pass --key to check against")
				fmt.Fprintln(w, "a key you already trust.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inPath, "in", "", "path to the signed manifest or DeDi file JSON (required)")
	cmd.Flags().StringVar(&keyPath, "key", "", "path to a public JWK JSON to verify against, instead of trusting the document's embedded key")
	return cmd
}

func findKeyByKid(keys []protocol.Key, kid string) (protocol.Key, bool) {
	for _, k := range keys {
		if k.Kid == kid {
			return k, true
		}
	}
	return protocol.Key{}, false
}
