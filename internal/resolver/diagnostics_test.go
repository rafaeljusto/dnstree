package resolver_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/resolver"
	"github.com/rafaeljusto/dnstree/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/internal/trace"
	"github.com/rafaeljusto/dnstree/internal/transport"
)

// A hierarchy of its own, two zones deep, so that the records these tests need
// do not change the size of the shared one: a signed zone answers with every
// signature over everything in it, and a denial that no longer fits in a
// datagram is a different test failing for a reason of this test's making.
const (
	serviceRootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
test.               IN NS   ns.test.
ns.test.            IN A    192.0.2.5
`

	serviceZone = `
@    IN SOA    ns hostmaster 1 7200 3600 1209600 3600
@    IN NS     ns
ns   IN A      192.0.2.5
www  IN A      192.0.2.10
svc  IN HTTPS  1 . alpn="h2,h3" ech="AEX+DQBBAAA="
bare IN HTTPS  1 . alpn="h2"
`
)

// service builds that hierarchy, signed or not, with the leaf zone's server
// behaving as the test asks.
func service(tb testing.TB, dnssec bool, leaf fakens.Behaviour) (harness, resolver.Config) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: serviceRootZone, Declared: "192.0.2.1",
		DNSSEC: dnssec,
	})
	hierarchy.Add(fakens.Config{
		Name: "ns.test.", Origin: "test.", Zone: serviceZone, Declared: "192.0.2.5",
		DNSSEC: dnssec, Behaviour: leaf,
	})

	cfg := resolver.Config{}
	if dnssec {
		cfg.DNSSEC, cfg.Anchors = true, root.Anchors(tb)
	}
	return harness{hierarchy, root}, cfg
}

// TestExtendedErrorIsCarried covers a server explaining an answer it did give.
// A code that does not claim the answer was withheld changes nothing about how
// the hop is read; it is only carried, for whoever is reading.
func TestExtendedErrorIsCarried(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{
		Extended: &fakens.ExtendedError{Code: 3, Text: "answer from the shelf"},
	})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil || answer.Kind != trace.KindAnswer {
		t.Fatalf("got %+v, want the answer: %s", answer, format(steps(tr)))
	}
	if len(answer.Extended) != 1 {
		t.Fatalf("got %+v, want the one extended error the server sent", answer.Extended)
	}
	if got := answer.Extended[0]; got.Code != 3 || got.Reason != "Stale Answer" ||
		got.Text != "answer from the shelf" {
		t.Errorf("got %+v, want stale answer (3) with the server's own words", got)
	}
	if answer.Extended[0].Withheld() {
		t.Error("got a withheld answer, want a stale one: nobody kept this back")
	}
}

// TestWithheldAnswerIsNotLame covers the reason for reading extended errors at
// all. A REFUSED alone is a server with no business serving the zone; the same
// REFUSED with a code saying the answer was withheld is somebody standing
// between the question and the zone, and the two are not the same finding.
func TestWithheldAnswerIsNotLame(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{
		Refuse:   true,
		Extended: &fakens.ExtendedError{Code: 18, Text: "not from here"},
	})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	filtered := tr.Filtered()
	if filtered == nil {
		t.Fatalf("got no filtered hop, want the REFUSED read as one: %s", format(steps(tr)))
	}
	if filtered.Zone != "test." {
		t.Errorf("got %s, want the hop into test.", filtered.Zone)
	}
	if filtered.Rcode != "REFUSED" {
		t.Errorf("got %s, want the rcode kept as it arrived", filtered.Rcode)
	}
	if len(filtered.Extended) != 1 || !filtered.Extended[0].Withheld() {
		t.Errorf("got %+v, want the code that says so", filtered.Extended)
	}

	// Turned away is not answered. A script reading the exit code has to tell
	// them apart, and Result is what it reads.
	if tr.Result() != nil {
		t.Errorf("got %+v, want no answer: the zone was never reached", tr.Result())
	}
}

// TestRefusedWithoutExtendedIsStillLame guards the other side of it: nothing
// changes for a server that refuses and says nothing about why.
func TestRefusedWithoutExtendedIsStillLame(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{Refuse: true})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filtered := tr.Filtered(); filtered != nil {
		t.Errorf("got %+v, want a lame server: it never said it withheld anything", filtered)
	}

	lame := false
	for _, step := range steps(tr) {
		lame = lame || step.Kind == trace.KindLame
	}
	if !lame {
		t.Errorf("got no lame hop, want one: %s", format(steps(tr)))
	}
}

// TestClientSubnetIsEchoed covers a server that tailors its answer by network:
// what comes back says how much of the prefix it actually used.
func TestClientSubnetIsEchoed(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{EchoSubnet: true, SubnetScope: 24})
	cfg.Subnet = netip.MustParsePrefix("203.0.113.0/24")

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil {
		t.Fatalf("got no answer: %s", format(steps(tr)))
	}
	if answer.Subnet == nil {
		t.Fatal("got no subnet back, want the one the server echoed")
	}
	if got := answer.Subnet.Prefix.String(); got != "203.0.113.0/24" {
		t.Errorf("got %s, want the prefix that was sent", got)
	}
	if answer.Subnet.Scope != 24 {
		t.Errorf("got scope /%d, want /24", answer.Subnet.Scope)
	}
	for _, warning := range tr.Warnings {
		if strings.Contains(warning, "client subnet") {
			t.Errorf("got %q, want no complaint: the server answered with one", warning)
		}
	}
}

// TestClientSubnetIgnored covers the answer being worth less than it looks. A
// server that echoes nothing tailored nothing, so what came back is what it
// tells everybody, and the reason for asking went unanswered.
func TestClientSubnetIgnored(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{})
	cfg.Subnet = netip.MustParsePrefix("203.0.113.0/24")

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil {
		t.Fatalf("got no answer: %s", format(steps(tr)))
	}
	if answer.Subnet != nil {
		t.Errorf("got %+v, want nothing: this server never echoed one", answer.Subnet)
	}
	if !warned(tr, "ignored the client subnet") {
		t.Errorf("got %q, want a warning that the subnet went unused", tr.Warnings)
	}
}

// TestNoSubnetIsSent covers the default. Telling every server on the way down
// which network the question came from is a thing to ask for, never a thing to
// get by accident.
func TestNoSubnetIsSent(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{EchoSubnet: true, SubnetScope: 24})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if answer := tr.Result(); answer == nil || answer.Subnet != nil {
		t.Errorf("got %+v, want no subnet anywhere: none was asked for", answer)
	}
}

// TestServiceParametersAreDecoded covers reading an HTTPS record for what it
// offers rather than only printing it.
func TestServiceParametersAreDecoded(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "svc.test", "HTTPS")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	answer := tr.Result()
	if answer == nil || len(answer.Records) != 1 {
		t.Fatalf("got %+v, want the one HTTPS record: %s", answer, format(steps(tr)))
	}

	svc := answer.Records[0].Service
	if svc == nil {
		t.Fatal("got no service parameters, want them decoded")
	}
	if svc.Priority != 1 {
		t.Errorf("got priority %d, want 1", svc.Priority)
	}
	if strings.Join(svc.ALPN, ",") != "h2,h3" {
		t.Errorf("got alpn %q, want h2 and h3", svc.ALPN)
	}
	if !svc.ECH {
		t.Error("got no ECH, want the configuration the record publishes")
	}
}

// TestServiceWithoutECH covers the record that publishes none, which must not
// be reported as publishing one.
func TestServiceWithoutECH(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "bare.test", "HTTPS")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	answer := tr.Result()
	if answer == nil || len(answer.Records) != 1 {
		t.Fatalf("got %+v, want the one HTTPS record: %s", answer, format(steps(tr)))
	}
	if svc := answer.Records[0].Service; svc == nil || svc.ECH {
		t.Errorf("got %+v, want service parameters carrying no ECH", svc)
	}
	if warned(tr, "ECH") {
		t.Errorf("got %q, want nothing said about ECH", tr.Warnings)
	}
}

// TestUnsignedECHIsWarnedAbout is the point of decoding ECH at all. The
// configuration that hides the name a client is about to ask for travels in
// this answer; whatever can rewrite the answer can take it out again, and the
// client then asks in the clear without knowing anything went missing.
func TestUnsignedECHIsWarnedAbout(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "svc.test", "HTTPS")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !warned(tr, "ECH configuration") {
		t.Errorf("got %q, want a warning that nothing vouched for it", tr.Warnings)
	}
}

// TestSignedECHIsNotWarnedAbout covers the case the warning exists for the sake
// of: a signed answer, where stripping the configuration would have shown.
func TestSignedECHIsNotWarnedAbout(t *testing.T) {
	h, cfg := service(t, true, fakens.Behaviour{})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "svc.test", "HTTPS")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	answer := tr.Result()
	if answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Secure {
		t.Fatalf("got %+v, want a secure answer to warn about nothing: %s", answer, format(steps(tr)))
	}
	if warned(tr, "ECH") {
		t.Errorf("got %q, want nothing said: the signature covers the configuration", tr.Warnings)
	}
}

// TestBogusECHIsWarnedAbout covers a signed zone whose answer does not verify,
// which is exactly when a reader must not take the configuration on trust.
func TestBogusECHIsWarnedAbout(t *testing.T) {
	h, cfg := service(t, true, fakens.Behaviour{BadSignature: true})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "svc.test", "HTTPS")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !warned(tr, "ECH configuration") {
		t.Errorf("got %q, want the configuration called out: %s", tr.Warnings, format(steps(tr)))
	}
}

// TestSubnetSurvivesTheEDNSFallback covers a server that cannot parse EDNS0 at
// all. The subnet rides in an EDNS0 option, so the query that goes out without
// EDNS0 has to go out without the option too, rather than failing twice.
func TestSubnetSurvivesTheEDNSFallback(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{FormErrEDNS: true})
	cfg.Subnet = netip.MustParsePrefix("203.0.113.0/24")
	cfg.Transport = h.carry(transport.NewUDP(fast))

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	answer := tr.Result()
	if answer == nil || answer.Kind != trace.KindAnswer {
		t.Fatalf("got %+v, want the answer the retry fetched: %s", answer, format(steps(tr)))
	}
}

// warned reports whether any of the warnings mentions text.
func warned(tr *trace.Trace, text string) bool {
	for _, warning := range tr.Warnings {
		if strings.Contains(warning, text) {
			return true
		}
	}
	return false
}

// TestNSIDIsRecorded covers the one thing in a reply that tells the machines
// behind an anycast address apart. Two hops to the same address are the same
// server as far as everything else in a trace can see.
func TestNSIDIsRecorded(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{NSID: "fra2"})
	cfg.NSID = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil {
		t.Fatalf("got no answer: %s", format(steps(tr)))
	}
	if answer.NSID != "fra2" {
		t.Errorf("got %q, want the identifier the server published", answer.NSID)
	}
}

// TestNSIDNotAsked covers the default. A server answers with an identifier
// because it was asked for one, and a walk that did not ask gets none.
func TestNSIDNotAsked(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{NSID: "fra2"})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if answer := tr.Result(); answer == nil || answer.NSID != "" {
		t.Errorf("got %+v, want no identifier anywhere: none was asked for", answer)
	}
}

// TestNSIDUnpublished covers the server with none to give, which is most of
// them below the root. The hop reads as it would without the flag, rather than
// as a hop that went wrong.
func TestNSIDUnpublished(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{})
	cfg.NSID = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil {
		t.Fatalf("got no answer: %s", format(steps(tr)))
	}
	if answer.NSID != "" {
		t.Errorf("got %q, want nothing: this server publishes no identifier", answer.NSID)
	}
}

// TestNSIDIsNotTakenAtItsWord covers an identifier that is not a name at all.
// The bytes are the server's own choice, and they end up on a line of a tree
// that has a charset to keep, so what is not printable stays hex.
func TestNSIDIsNotTakenAtItsWord(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{NSID: "\x00\x1b[2Jfra2"})
	cfg.NSID = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.test", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil {
		t.Fatalf("got no answer: %s", format(steps(tr)))
	}
	if answer.NSID != "001b5b324a66726132" {
		t.Errorf("got %q, want the hex it arrived as", answer.NSID)
	}
}
