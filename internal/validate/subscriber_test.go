package validate

import (
	"encoding/json"
	"testing"

	"github.com/nfh-trust-labs/dedi-cli/internal/protocol"
)

func becknSubscriberFile(publisherDomain string, records []protocol.Record) *protocol.DeDiFile {
	return &protocol.DeDiFile{
		Publisher: protocol.Publisher{Domain: publisherDomain},
		Registry: protocol.Registry{
			Schema: protocol.SchemaRef{URL: BecknSubscriberSchemaURL},
		},
		Records: records,
	}
}

func subscriberRecord(subscriberID string) protocol.Record {
	details, _ := json.Marshal(map[string]string{"subscriber_id": subscriberID})
	return protocol.Record{RecordName: "r1", Details: details}
}

func TestValidateSubscriberIDs_ExactDomainMatch(t *testing.T) {
	f := becknSubscriberFile("example.org", []protocol.Record{subscriberRecord("example.org")})
	if err := ValidateSubscriberIDs(f); err != nil {
		t.Errorf("ValidateSubscriberIDs() error = %v, want nil", err)
	}
}

func TestValidateSubscriberIDs_SubdomainMatch(t *testing.T) {
	f := becknSubscriberFile("example.org", []protocol.Record{subscriberRecord("bap.example.org")})
	if err := ValidateSubscriberIDs(f); err != nil {
		t.Errorf("ValidateSubscriberIDs() error = %v, want nil", err)
	}
}

func TestValidateSubscriberIDs_Mismatch(t *testing.T) {
	f := becknSubscriberFile("example.org", []protocol.Record{subscriberRecord("other.com")})
	err := ValidateSubscriberIDs(f)
	if err == nil {
		t.Fatal("expected a subscriber_id mismatch error")
	}
}

func TestValidateSubscriberIDs_PrefixSquattingRejected(t *testing.T) {
	// "evilexample.org" ends with "example.org" as a raw string suffix, but
	// is not a dot-anchored subdomain of it — must be rejected.
	f := becknSubscriberFile("example.org", []protocol.Record{subscriberRecord("evilexample.org")})
	if err := ValidateSubscriberIDs(f); err == nil {
		t.Fatal("expected evilexample.org to be rejected as a match for example.org")
	}
}

func TestValidateSubscriberIDs_CaseInsensitive(t *testing.T) {
	f := becknSubscriberFile("Example.ORG", []protocol.Record{subscriberRecord("BAP.example.org")})
	if err := ValidateSubscriberIDs(f); err != nil {
		t.Errorf("ValidateSubscriberIDs() error = %v, want nil", err)
	}
}

func TestValidateSubscriberIDs_TrailingDot(t *testing.T) {
	f := becknSubscriberFile("example.org.", []protocol.Record{subscriberRecord("example.org")})
	if err := ValidateSubscriberIDs(f); err != nil {
		t.Errorf("ValidateSubscriberIDs() error = %v, want nil", err)
	}
}

func TestValidateSubscriberIDs_NonSubscriberSchemaURL_Skipped(t *testing.T) {
	f := &protocol.DeDiFile{
		Publisher: protocol.Publisher{Domain: "example.org"},
		Registry: protocol.Registry{
			Schema: protocol.SchemaRef{URL: "https://example.org/schemas/Public_key.json"},
		},
		Records: []protocol.Record{subscriberRecord("totally-different.com")},
	}
	if err := ValidateSubscriberIDs(f); err != nil {
		t.Errorf("ValidateSubscriberIDs() error = %v, want nil for a non-beckn_subscriber schema", err)
	}
}

func TestValidateSubscriberIDs_InlineSchema_Skipped(t *testing.T) {
	f := &protocol.DeDiFile{
		Publisher: protocol.Publisher{Domain: "example.org"},
		Registry: protocol.Registry{
			Schema: protocol.SchemaRef{Inline: json.RawMessage(`{"type":"object"}`)},
		},
		Records: []protocol.Record{subscriberRecord("totally-different.com")},
	}
	if err := ValidateSubscriberIDs(f); err != nil {
		t.Errorf("ValidateSubscriberIDs() error = %v, want nil for an inline schema", err)
	}
}

func TestValidateSubscriberIDs_EmptySubscriberID_Skipped(t *testing.T) {
	f := becknSubscriberFile("example.org", []protocol.Record{
		{RecordName: "r1", Details: json.RawMessage(`{}`)},
	})
	if err := ValidateSubscriberIDs(f); err != nil {
		t.Errorf("ValidateSubscriberIDs() error = %v, want nil when subscriber_id is absent", err)
	}
}

func TestValidateSubscriberIDs_MalformedDetails(t *testing.T) {
	f := becknSubscriberFile("example.org", []protocol.Record{
		{RecordName: "r1", Details: json.RawMessage(`not valid json`)},
	})
	if err := ValidateSubscriberIDs(f); err == nil {
		t.Fatal("expected an unmarshal error")
	}
}
