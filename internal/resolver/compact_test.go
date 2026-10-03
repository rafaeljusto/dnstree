package resolver_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// TestCompactDenial covers a zone that signs as it answers (RFC 9824): a name
// that is not there comes back NOERROR, with a signed record at the name whose
// types say NXNAME. Read as a NODATA it would be a name that exists.
func TestCompactDenial(t *testing.T) {
	for name, test := range map[string]struct {
		zone     string
		leaf     fakens.Behaviour
		minimise bool
		qname    string
		qtype    string
		want     trace.StepKind
		compact  bool
		note     string
	}{
		"a signed NXNAME is a name that is not there": {
			zone: exampleZone, qname: "nothing.example.com", qtype: "A",
			want: trace.KindNXDomain, compact: true, note: "compact denial, RFC 9824"},
		"a name with other types stays a NODATA": {
			zone: exampleZone, qname: "www.example.com", qtype: "MX", want: trace.KindNoData},
		"an empty non-terminal stays a NODATA": {
			zone: deepZone, qname: "b.c.example.com", qtype: "A", want: trace.KindNoData},
		"a minimised walk ends on the name that is not there": {
			zone: deepZone, minimise: true, qname: "x.y.example.com", qtype: "A",
			want: trace.KindNXDomain, compact: true, note: "compact denial, RFC 9824"},
		"an NXNAME nothing signed stays a NODATA": {
			zone: exampleZone, leaf: fakens.Behaviour{BadSignature: true}, qname: "nothing.example.com", qtype: "A",
			want: trace.KindNoData, note: "NXNAME, unproved"},
	} {
		t.Run(name, func(t *testing.T) {
			h, cfg := signedZoneAs(t, test.zone, fakens.DenialCompact, test.leaf)
			cfg.Minimise = test.minimise

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), test.qname, test.qtype)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			answer := tr.Result()
			if answer == nil || answer.Kind != test.want {
				t.Fatalf("got %+v, want %s: %s", answer, test.want, format(steps(tr)))
			}
			if answer.Compact != test.compact {
				t.Errorf("got compact %v, want %v", answer.Compact, test.compact)
			}
			if answer.Rcode != "NOERROR" {
				t.Errorf("got rcode %s, want the NOERROR the server sent", answer.Rcode)
			}
			if test.note != "" && !slices.Contains(answer.Notes, test.note) {
				t.Errorf("got notes %q, want %q", answer.Notes, test.note)
			}
			if test.compact && (answer.DNSSEC == nil || answer.DNSSEC.State != trace.Secure ||
				!strings.HasSuffix(answer.DNSSEC.Reason, "does not exist")) {
				t.Errorf("got %+v, want the absence of the name proved", answer.DNSSEC)
			}
			for _, warning := range tr.Warnings {
				if strings.Contains(warning, "RFC 8020") {
					t.Errorf("got %q, want no empty non-terminal warning", warning)
				}
			}
		})
	}
}

// TestCompactDenialUnsigned covers the same zone asked without signatures. It
// owes such a client the NXDOMAIN, there being no record it could read instead.
func TestCompactDenialUnsigned(t *testing.T) {
	h, cfg := signedZoneAs(t, exampleZone, fakens.DenialCompact, fakens.Behaviour{})
	cfg.DNSSEC = false

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "nothing.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	answer := tr.Result()
	if answer == nil || answer.Kind != trace.KindNXDomain || answer.Compact || answer.Rcode != "NXDOMAIN" {
		t.Fatalf("got %+v, want a plain NXDOMAIN: %s", answer, format(steps(tr)))
	}
}
