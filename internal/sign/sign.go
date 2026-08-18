package sign

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/nfh-trust-labs/dedi-cli/internal/crypto"
	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
)

// SignManifest signs m with priv under kid, replacing m.Proof. kid should
// name a key already present in m.Keys — SignManifest doesn't check this
// itself; that's the job of a full verification chain (like the DeDi
// crawler's), not this signing package.
func SignManifest(m protocol.Manifest, priv ed25519.PrivateKey, kid string) (protocol.Manifest, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return protocol.Manifest{}, fmt.Errorf("sign manifest: marshal: %w", err)
	}
	jwsStr, err := signRaw(priv, raw)
	if err != nil {
		return protocol.Manifest{}, fmt.Errorf("sign manifest: %w", err)
	}
	m.Proof = protocol.Proof{
		VerificationMethod: kid,
		Canonicalization:   protocol.CanonicalizationJCS,
		JWS:                jwsStr,
	}
	return m, nil
}

// SignDeDiFile signs f with priv, replacing f.Proof. The verification
// method is always f.Publisher.Key.Kid — a DeDi file carries exactly one
// embedded key, unlike a manifest's keys[] list.
func SignDeDiFile(f protocol.DeDiFile, priv ed25519.PrivateKey) (protocol.DeDiFile, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return protocol.DeDiFile{}, fmt.Errorf("sign dedi file: marshal: %w", err)
	}
	jwsStr, err := signRaw(priv, raw)
	if err != nil {
		return protocol.DeDiFile{}, fmt.Errorf("sign dedi file: %w", err)
	}
	f.Proof = protocol.Proof{
		VerificationMethod: f.Publisher.Key.Kid,
		Canonicalization:   protocol.CanonicalizationJCS,
		JWS:                jwsStr,
	}
	return f, nil
}

// signRaw strips whatever "proof" doc already has (its prior value doesn't
// matter — it's about to be replaced), canonicalizes, and signs. The same
// crypto.SigningInput call a verifier makes to check the result.
func signRaw(priv ed25519.PrivateKey, doc []byte) (string, error) {
	signingInput, err := crypto.SigningInput(doc)
	if err != nil {
		return "", err
	}
	return crypto.Sign(priv, signingInput)
}
