package validate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
	"golang.org/x/net/idna"
)

// BecknSubscriberSchemaURL is the canonical schema URL for the
// beckn_subscriber registry type — the same URL dedi-crawler's
// DefaultSchemaTagMap keys off of to tag a registry "beckn_subscriber".
// Deliberately distinct from beckn_subscriber_reference's schema URL: that
// registry's subscriber_id is a different kind of identifier, not bound to
// the registry's namespace (see dedi-crawler's reference_discovery.go).
//
// A var, not a const, purely so an end-to-end test can point it at a local
// httptest.Server instead of making sign's schema-fetch step hit the real
// URL over the network.
var BecknSubscriberSchemaURL = "https://raw.githubusercontent.com/LF-Decentralized-Trust-labs/decentralized-directory-protocol/main/schemas/beckn_subscriber.json"

type subscriberDetails struct {
	SubscriberID string `json:"subscriber_id"`
}

// ValidateSubscriberIDs checks, for a registry whose schema is exactly
// BecknSubscriberSchemaURL, that every record's subscriber_id is either
// f.Publisher.Domain itself or a subdomain of it — the rule the DeDi server
// enforces at registration time (a record that fails it is silently never
// reflected in DeDi). Publisher.Domain, not Namespace, is the authoritative
// field here: it's literally "the publisher's domain" the rule is stated in
// terms of (in a validly-signed file the two are always equal anyway — see
// dedi-crawler's own domain-binding check in internal/verify/verify.go,
// which requires both to match the crawled domain). Registries referencing
// a different or inline schema are skipped, as is any record with an empty
// subscriber_id — presence and shape are schema validation's job, not this
// check's.
//
// raw is the original input bytes, used only to point a mismatch error at
// a "line N, column M" location — the check itself runs entirely off f.
func ValidateSubscriberIDs(raw []byte, f *protocol.DeDiFile) error {
	if !f.Registry.Schema.IsURL() || f.Registry.Schema.URL != BecknSubscriberSchemaURL {
		return nil
	}
	for _, r := range f.Records {
		var d subscriberDetails
		if err := json.Unmarshal(r.Details, &d); err != nil {
			return fmt.Errorf("record %q: unmarshal details: %w", r.RecordName, err)
		}
		if d.SubscriberID == "" {
			continue
		}
		if !subscriberIDMatchesDomain(d.SubscriberID, f.Publisher.Domain) {
			return fmt.Errorf("record %q%s: subscriber_id %q does not match publisher domain %q (must be the domain itself or a subdomain of it)",
				r.RecordName, locationHint(raw, r.Details, d.SubscriberID), d.SubscriberID, f.Publisher.Domain)
		}
	}
	return nil
}

// locationHint returns a " (line N, column M)" suffix pinpointing
// subscriberID's quoted value within details inside raw, or "" if it can't
// be located. Best-effort: json.RawMessage preserves the exact source
// bytes it was decoded from, so bytes.Index reliably finds details' own
// position in raw; a value needing JSON escaping (rare for a domain-shaped
// subscriber_id) or a byte-for-byte duplicate details block elsewhere in
// the file are the only ways this comes back empty or points at the wrong
// occurrence.
func locationHint(raw []byte, details json.RawMessage, subscriberID string) string {
	base := bytes.Index(raw, details)
	if base == -1 {
		return ""
	}
	offset := base
	if i := bytes.Index(details, []byte(`"`+subscriberID+`"`)); i != -1 {
		offset = base + i
	}
	line, col := protocol.LineCol(raw, offset)
	return fmt.Sprintf(" (line %d, column %d)", line, col)
}

// subscriberIDMatchesDomain reports whether id is exactly domain, or a
// dot-anchored subdomain of it (the "." guard is what stops
// "evilexample.org" from matching "example.org"). Ported from
// registry-service's subscriberIDMatchesDomain, minus its attestation
// branch (an "attestor:attested" domain needs live verified-namespace
// state this offline command has no way to obtain — a DeDi file's
// publisher domain is always treated as a plain domain here).
func subscriberIDMatchesDomain(id, domain string) bool {
	i, d := canonicalizeHost(id), canonicalizeHost(domain)
	return i == d || strings.HasSuffix(i, "."+d)
}

// canonicalizeHost normalizes a hostname for comparison: strips a trailing
// FQDN dot, then IDNA-normalizes so e.g. "café.com" and "xn--caf-dma.com"
// compare equal; falls back to a plain lowercase if IDNA normalization
// fails (e.g. invalid input containing whitespace).
func canonicalizeHost(s string) string {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return s
	}
	if ascii, err := idna.Lookup.ToASCII(s); err == nil {
		return ascii
	}
	return strings.ToLower(s)
}
