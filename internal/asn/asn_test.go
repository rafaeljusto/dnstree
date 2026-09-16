package asn_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/asn"
	"github.com/rafaeljusto/dnstree/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// cymru is the origin zone as Team Cymru serves it, for the addresses these
// tests ask about.
const cymru = `
@       IN SOA ns hostmaster 1 7200 3600 1209600 3600
@       IN NS  ns
ns      IN A   127.0.0.1
4.3.2.1 IN TXT "15169 | 1.2.3.0/24 | US | arin | 1992-12-01"
1.0.0.5 IN TXT "64500 | 5.0.0.0/8 | NL | ripencc | 1993-05-01"
`

// TestLookupThroughResolver goes through the host's own resolver interface,
// pointed at a fake nameserver, so the name this package builds has to be right
// for anything to come back.
func TestLookupThroughResolver(t *testing.T) {
	resolver := asn.New(lookupAgainst(t, cymru))

	info, err := resolver.Lookup(t.Context(), netip.MustParseAddr("1.2.3.4"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if info == nil {
		t.Fatal("got nothing for 1.2.3.4, want the AS that announces it")
	}
	want := trace.ASNInfo{
		Number: 15169, Prefix: "1.2.3.0/24", CountryCode: "US",
		Registry: "arin", Allocated: "1992-12-01",
	}
	if *info != want {
		t.Errorf("got %+v, want %+v", *info, want)
	}
}

func TestLookupUnknownAddress(t *testing.T) {
	resolver := asn.New(lookupAgainst(t, cymru))

	// The zone answers, but has nothing to say about this one.
	info, err := resolver.Lookup(t.Context(), netip.MustParseAddr("9.9.9.9"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if info != nil {
		t.Errorf("got %+v, want nothing", info)
	}
}

// TestAnnotate covers what the resolver does with a whole trace: every server
// gets its AS, an address that turns up twice is asked about once, and an
// address nothing knows about is simply left alone.
func TestAnnotate(t *testing.T) {
	var asked atomic.Int64
	lookup := lookupAgainst(t, cymru)
	counted := func(ctx context.Context, name string) ([]string, error) {
		asked.Add(1)
		return lookup(ctx, name)
	}

	tr := &trace.Trace{Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{
		step("1.2.3.4"),
		step("5.0.0.1"),
		step("1.2.3.4"), // the same nameserver, one zone further down
		step("9.9.9.9"), // nothing announces it
		{Zone: ".", Kind: trace.KindError},
	}}}

	asn.New(counted).Annotate(t.Context(), tr)

	if len(tr.Warnings) != 0 {
		t.Errorf("got warnings %q, want none", tr.Warnings)
	}
	if got := asked.Load(); got != 3 {
		t.Errorf("asked %d times, want 3: one per distinct address", got)
	}

	steps := tr.Root.Children
	for i, want := range []uint32{15169, 64500, 15169, 0, 0} {
		got := steps[i].Server.ASN
		switch {
		case want == 0 && got != nil:
			t.Errorf("step %d: got %+v, want no AS", i, got)
		case want == 0:
		case got == nil:
			t.Errorf("step %d: got no AS, want %d", i, want)
		case got.Number != want:
			t.Errorf("step %d: got AS%d, want AS%d", i, got.Number, want)
		}
	}
}

// TestAnnotateWithoutLookups covers the promise that this is best effort: the
// trace survives a resolver that cannot answer at all.
func TestAnnotateWithoutLookups(t *testing.T) {
	broken := func(context.Context, string) ([]string, error) {
		return nil, errors.New("no resolver here")
	}

	tr := &trace.Trace{Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{
		step("1.2.3.4"),
	}}}
	asn.New(broken).Annotate(t.Context(), tr)

	if tr.Root.Children[0].Server.ASN != nil {
		t.Error("got an AS out of a broken resolver, want none")
	}
	if len(tr.Warnings) != 1 || !strings.Contains(tr.Warnings[0], "no resolver here") {
		t.Fatalf("got warnings %q, want one saying why nothing could be looked up", tr.Warnings)
	}

	// A trace with nothing to look up is not worth a warning.
	empty := &trace.Trace{Root: &trace.Step{Zone: ".", Kind: trace.KindZone}}
	asn.New(broken).Annotate(t.Context(), empty)
	if len(empty.Warnings) != 0 {
		t.Errorf("got warnings %q, want none", empty.Warnings)
	}

	asn.New(broken).Annotate(t.Context(), nil) // and nothing at all is fine too
}

// lookupAgainst answers TXT queries from a fake nameserver, through the same
// resolver interface the host's own resolver is used by.
func lookupAgainst(tb testing.TB, zone string) asn.Lookup {
	tb.Helper()

	server := fakens.New(tb, fakens.Config{Origin: "origin.asn.cymru.com.", Zone: zone})
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Addr.String())
		},
	}
	return resolver.LookupTXT
}

func step(addr string) *trace.Step {
	return &trace.Step{
		Zone:   ".",
		Server: trace.Server{Name: "ns.example.", IP: netip.MustParseAddr(addr), Port: 53},
		Kind:   trace.KindReferral,
	}
}
