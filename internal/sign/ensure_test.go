package sign

import (
	"testing"

	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
)

func TestEnsureManifestKey(t *testing.T) {
	keyA := protocol.Key{Kid: "key-a", Kty: "OKP", Crv: "Ed25519", X: "aaaa"}
	keyAConflict := protocol.Key{Kid: "key-a", Kty: "OKP", Crv: "Ed25519", X: "bbbb"}
	keyB := protocol.Key{Kid: "key-b", Kty: "OKP", Crv: "Ed25519", X: "cccc"}

	tests := []struct {
		name     string
		keys     []protocol.Key
		pub      protocol.Key
		wantKeys []protocol.Key
		wantErr  bool
	}{
		{
			name:     "appends when kid absent",
			keys:     []protocol.Key{keyB},
			pub:      keyA,
			wantKeys: []protocol.Key{keyB, keyA},
		},
		{
			name:     "no-op when kid already present and matching",
			keys:     []protocol.Key{keyA, keyB},
			pub:      keyA,
			wantKeys: []protocol.Key{keyA, keyB},
		},
		{
			name:    "errors when kid present with different key material",
			keys:    []protocol.Key{keyAConflict},
			pub:     keyA,
			wantErr: true,
		},
		{
			name:     "appends to an empty list",
			keys:     nil,
			pub:      keyA,
			wantKeys: []protocol.Key{keyA},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &protocol.Manifest{Keys: tc.keys}
			err := EnsureManifestKey(m, tc.pub)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("EnsureManifestKey() error = %v", err)
			}
			if len(m.Keys) != len(tc.wantKeys) {
				t.Fatalf("Keys = %+v, want %+v", m.Keys, tc.wantKeys)
			}
			for i, k := range tc.wantKeys {
				if m.Keys[i] != k {
					t.Errorf("Keys[%d] = %+v, want %+v", i, m.Keys[i], k)
				}
			}
		})
	}
}

func TestEnsurePublisherKey(t *testing.T) {
	keyA := protocol.Key{Kid: "key-a", Kty: "OKP", Crv: "Ed25519", X: "aaaa"}
	keyAConflict := protocol.Key{Kid: "key-a", Kty: "OKP", Crv: "Ed25519", X: "bbbb"}

	tests := []struct {
		name       string
		existing   protocol.Key
		pub        protocol.Key
		wantResult protocol.Key
		wantErr    bool
	}{
		{
			name:       "fills in when unset",
			existing:   protocol.Key{},
			pub:        keyA,
			wantResult: keyA,
		},
		{
			name:       "no-op when already set and matching",
			existing:   keyA,
			pub:        keyA,
			wantResult: keyA,
		},
		{
			name:     "errors when already set to a different key",
			existing: keyAConflict,
			pub:      keyA,
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &protocol.DeDiFile{Publisher: protocol.Publisher{Key: tc.existing}}
			err := EnsurePublisherKey(f, tc.pub)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("EnsurePublisherKey() error = %v", err)
			}
			if f.Publisher.Key != tc.wantResult {
				t.Errorf("Publisher.Key = %+v, want %+v", f.Publisher.Key, tc.wantResult)
			}
		})
	}
}
