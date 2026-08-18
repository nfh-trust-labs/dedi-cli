package protocol

// Proof is the detached-JWS proof block attached to a manifest or a DeDi
// file. VerificationMethod must equal the signing key's "kid" (the
// manifest's own keys[] for a manifest; publisher.key.kid for a file).
type Proof struct {
	VerificationMethod string `json:"verification_method"`
	Canonicalization   string `json:"canonicalization"` // must be "JCS"
	JWS                string `json:"jws"`
}
