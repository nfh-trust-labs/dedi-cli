package sign

import (
	"fmt"

	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
)

// EnsureManifestKey makes sure pub is present in m.Keys, appending it if no
// entry has pub.Kid yet. If an entry with pub.Kid already exists but doesn't
// match pub exactly, it errors instead of silently overwriting — that
// combination almost always means the wrong key file was used, or the
// manifest's keys[] carries stale data from a previous key.
func EnsureManifestKey(m *protocol.Manifest, pub protocol.Key) error {
	for _, k := range m.Keys {
		if k.Kid != pub.Kid {
			continue
		}
		if k != pub {
			return fmt.Errorf("manifest already has a key %q that does not match the signing key (pass the matching --key, or remove/update that stale keys[] entry before signing)", pub.Kid)
		}
		return nil
	}
	m.Keys = append(m.Keys, pub)
	return nil
}

// EnsurePublisherKey makes sure f.Publisher.Key matches pub, filling it in
// if unset. If it's already set to something else, it errors instead of
// silently overwriting, for the same reason as EnsureManifestKey.
func EnsurePublisherKey(f *protocol.DeDiFile, pub protocol.Key) error {
	var zero protocol.Key
	if f.Publisher.Key == zero {
		f.Publisher.Key = pub
		return nil
	}
	if f.Publisher.Key != pub {
		return fmt.Errorf("publisher.key %q does not match the signing key %q (pass the matching --key, or update publisher.key in the input before signing)", f.Publisher.Key.Kid, pub.Kid)
	}
	return nil
}
