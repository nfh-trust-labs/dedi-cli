package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nfh-trust-labs/dedi-cli/internal/sign"
	"github.com/spf13/cobra"
)

func newKeygenCmd() *cobra.Command {
	var kid, out string
	var force bool

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new Ed25519 keypair",
		Long: `Generate a new Ed25519 keypair.

Writes the private key as JSON to --out (mode 0600 on Unix) and prints the
public JWK for reference. Refuses to overwrite an existing --out file unless
--force is also passed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if kid == "" {
				return fmt.Errorf("--kid is required")
			}
			if out == "" {
				return fmt.Errorf("--out is required")
			}
			if !force {
				if _, err := os.Stat(out); err == nil {
					return fmt.Errorf("key file %s already exists (pass --force to overwrite)", out)
				} else if !os.IsNotExist(err) {
					return fmt.Errorf("check %s: %w", out, err)
				}
			}

			key, err := sign.GenerateKey(kid)
			if err != nil {
				return fmt.Errorf("generate key: %w", err)
			}
			if err := sign.SavePrivateJWK(out, key); err != nil {
				return fmt.Errorf("save key: %w", err)
			}

			pubJSON, err := json.MarshalIndent(key.PublicKey(), "", "  ")
			if err != nil {
				return fmt.Errorf("marshal public key: %w", err)
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Private key written to %s (mode 0600 — keep this secret).\n\n", out)
			fmt.Fprintln(w, `Public key (for reference — "dedi-cli sign" adds this to the`)
			fmt.Fprintln(w, `manifest's "keys" array or the file's "publisher.key" for you):`)
			fmt.Fprintln(w, string(pubJSON))
			return nil
		},
	}

	cmd.Flags().StringVar(&kid, "kid", "", "key ID to embed in the generated key (required)")
	cmd.Flags().StringVar(&out, "out", "", "path to write the private key JSON to (required)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite --out if it already exists")
	return cmd
}
