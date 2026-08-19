// Command dedi-cli generates Ed25519 keys, signs, and locally verifies
// DeDi protocol manifests and files.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is stamped at build time via:
//
//	go build -ldflags "-X main.version=v1.2.3"
var version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "dedi-cli",
		Short:   "Generate keys, sign, and verify DeDi protocol manifests and files",
		Version: version,
	}
	root.AddCommand(newKeygenCmd())
	root.AddCommand(newSignCmd())
	root.AddCommand(newVerifyCmd())
	return root
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
