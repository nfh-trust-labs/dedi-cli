// Package protocol implements the DeDi protocol's wire types: the manifest
// (/.well-known/dedi.index.json) and DeDi files (dedi.<registry>.json),
// per the protocol's dedi-manifest.schema.json and dedi-file.schema.json.
package protocol

const (
	// TypeManifest is the manifest's optional "type" discriminator.
	TypeManifest = "dedi-manifest"
	// TypeDeDiFile is a DeDi file's required "type" discriminator.
	TypeDeDiFile = "dedi-file"

	// CanonicalizationJCS is the only supported proof.canonicalization value.
	CanonicalizationJCS = "JCS"

	// RegistryStateLive marks a registry as authoritative.
	RegistryStateLive = "live"
	// RegistryStateInactive marks a registry as retired / not authoritative.
	RegistryStateInactive = "inactive"
)
