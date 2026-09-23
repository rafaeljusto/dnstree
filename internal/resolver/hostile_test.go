package resolver_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/internal/resolver"
	"github.com/rafaeljusto/dnstree/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/internal/trace"
	"github.com/rafaeljusto/dnstree/internal/transport"
)

// tamper is a server, or somebody between us and one, editing what comes back.
// Everything a walk believes arrives through here, so this is where the tests
// that matter put their thumb on the scale.
type tamper struct {
	inner transport.Transport
	edit  func(req, resp *dns.Msg)
}

func (t tamper) Proto() string { return t.inner.Proto() }
func (t tamper) Port() uint16  { return t.inner.Port() }

func (t tamper) Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, name string) (*dns.Msg, time.Duration, error) {
	resp, rtt, err := t.inner.Exchange(ctx, req, server, name)
	if err == nil && resp != nil {
		t.edit(req, resp)
	}
	return resp, rtt, err
}

// TestStrayKeyInTheKeySet covers one unrelated DNSKEY appended to every key
// set. The zone's own records and signature are untouched, so the chain has to
// hold: a set read without looking at the owners would no longer match the
// signature the zone made, and every cut would read bogus.
func TestStrayKeyInTheKeySet(t *testing.T) {
	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, fakens.Behaviour{})
	cfg.Transport = tamper{h.carry(transport.NewUDP(fast)), func(req, resp *dns.Msg) {
		if _, qtype := dnsutil.Question(req); qtype != dns.TypeDNSKEY {
			return
		}
		stray := &dns.DNSKEY{Hdr: dns.Header{Name: "attacker.example.", Class: dns.ClassINET, TTL: 3600}}
		stray.Flags, stray.Protocol, stray.Algorithm = dns.FlagZONE, 3, dns.ECDSAP256SHA256
		stray.PublicKey = "bm90IGEga2V5IGF0IGFsbA=="
		resp.Answer = append(resp.Answer, stray)
	}}

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Secure {
		t.Fatalf("got %+v on the answer, want a key nobody asked for ignored: %s",
			answer.DNSSEC, format(steps(tr)))
	}
	for step := range tr.Steps() {
		if step.DNSSEC != nil && step.DNSSEC.State == trace.Bogus {
			t.Errorf("got %s bogus (%s), want a sound chain", step.Zone, step.DNSSEC.Reason)
		}
	}
}

// refusing stands in for a server that will not take the TCP retry.
type refusing struct{ port uint16 }

func (r refusing) Proto() string { return "tcp" }
func (r refusing) Port() uint16  { return r.port }
func (r refusing) Exchange(context.Context, *dns.Msg, netip.AddrPort, string) (*dns.Msg, time.Duration, error) {
	return nil, 0, errors.New("connection refused")
}

// TestTruncatedAndTCPRefused covers an answer that did not fit and could not be
// fetched again. What is left of the message is not what the server holds, so
// reading it would turn a dropped answer section into NODATA: a statement that
// the name has no record of that type, made out of a lost packet.
func TestTruncatedAndTCPRefused(t *testing.T) {
	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3",
		Behaviour: fakens.Behaviour{TruncateUDP: true},
	})
	h := harness{hierarchy, root}

	cfg := resolver.Config{Transport: h.carry(transport.NewUDP(fast))}
	cfg.TCP = refusing{port: transport.PortDNS}

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	last := steps(tr)[len(steps(tr))-1]
	if last.Kind == trace.KindNoData || last.Kind == trace.KindAnswer {
		t.Fatalf("got %s, want a truncated answer refused rather than read: %s", last.Kind, format(steps(tr)))
	}
	if last.Kind != trace.KindError {
		t.Errorf("got kind %s, want an error", last.Kind)
	}
	if !last.Flags.TC {
		t.Error("got no TC flag on the step, want the truncation recorded")
	}
	if !strings.Contains(last.Err, "did not fit") {
		t.Errorf("got error %q, want it to say the answer did not fit", last.Err)
	}
	if len(tr.Warnings) == 0 {
		t.Error("got no warnings, want the truncation reported")
	}
	var noted bool
	for _, note := range last.Notes {
		if strings.Contains(note, "did not get through") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("got notes %q, want the failed retry named", last.Notes)
	}
}

// counting reports how many messages really went out, which is the number the
// budget is meant to be counting.
type counting struct {
	inner transport.Transport
	sent  atomic.Int64
}

func (c *counting) Proto() string { return c.inner.Proto() }
func (c *counting) Port() uint16  { return c.inner.Port() }
func (c *counting) Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, name string) (*dns.Msg, time.Duration, error) {
	c.sent.Add(1)
	return c.inner.Exchange(ctx, req, server, name)
}

// TestBudgetCountsOnlyQueriesSent covers the budget below an insecure cut.
// There is nothing left to learn from the keys of a zone the chain cannot
// trust, so no DNSKEY query goes out for it — and no slot may be spent on the
// query that was not made, or a walk gives up while it still had budget left.
func TestBudgetCountsOnlyQueriesSent(t *testing.T) {
	const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   ns.com.
ns.com.             IN A    192.0.2.2
`
	const comZone = `
@          IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@          IN NS   ns
ns         IN A    192.0.2.2
example    IN NS   ns.example
ns.example IN A    192.0.2.3
`
	const exampleZone = `
@       IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns
ns      IN A    192.0.2.3
sub     IN NS   ns.sub
ns.sub  IN A    192.0.2.5
`
	const subZone = `
@   IN SOA ns hostmaster 1 7200 3600 1209600 3600
@   IN NS  ns
ns  IN A   192.0.2.5
www IN A   192.0.2.30
`

	build := func(tb testing.TB) (harness, resolver.Config) {
		tb.Helper()

		hierarchy := fakens.NewHierarchy(tb)
		root := hierarchy.Add(fakens.Config{
			Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true})
		// Nobody vouches for com., so everything below it is insecure and its
		// keys are never worth fetching.
		hierarchy.Add(fakens.Config{
			Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2",
			DNSSEC: true, Behaviour: fakens.Behaviour{NoDS: true}})
		hierarchy.Add(fakens.Config{
			Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3", DNSSEC: true})
		hierarchy.Add(fakens.Config{
			Name: "ns.sub.example.com.", Origin: "sub.example.com.", Zone: subZone, Declared: "192.0.2.5", DNSSEC: true})
		return harness{hierarchy, root}, resolver.Config{DNSSEC: true, Anchors: root.Anchors(tb)}
	}

	// The smallest budget that still reaches the answer, and what it really cost.
	for budget := 1; budget <= 20; budget++ {
		h, cfg := build(t)
		counter := &counting{inner: h.carry(transport.NewUDP(fast))}
		cfg.Transport = counter
		cfg.Budget = resolver.Budget{MaxQueries: budget}

		tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.sub.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if tr.Result() == nil {
			continue
		}
		if sent := counter.sent.Load(); sent != int64(budget) {
			t.Fatalf("the walk answered on a budget of %d having sent %d messages, "+
				"so %d slot(s) went on a query that was never made", budget, sent, int64(budget)-sent)
		}
		return
	}
	t.Fatal("the walk never reached an answer within any budget")
}

// TestSideResolutionIgnoresUnownedAddresses covers a server answering the
// address of a nameserver with more than was asked for. Only the records the
// name itself owns are addresses of that nameserver; the rest belong to
// whatever the server chose to name, and following them sends the walk to an
// address no delegation ever pointed at.
func TestSideResolutionIgnoresUnownedAddresses(t *testing.T) {
	const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   ns.com.
ns.com.             IN A    192.0.2.2
net.                IN NS   ns.net.
ns.net.             IN A    192.0.2.6
`
	const comZone = `
@       IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns
ns      IN A    192.0.2.2
example IN NS   ns.outside.net.
`
	const netZone = `
@            IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@            IN NS   ns
ns           IN A    192.0.2.6
outside      IN NS   nsx.outside
nsx.outside  IN A    192.0.2.7
`
	const outsideZone = `
@     IN SOA  nsx hostmaster 1 7200 3600 1209600 3600
@     IN NS   nsx
nsx   IN A    192.0.2.7
ns    IN A    192.0.2.8
`

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	hierarchy.Add(fakens.Config{Name: "ns.net.", Origin: "net.", Zone: netZone, Declared: "192.0.2.6"})
	hierarchy.Add(fakens.Config{Name: "nsx.outside.net.", Origin: "outside.net.", Zone: outsideZone, Declared: "192.0.2.7"})
	hierarchy.Add(fakens.Config{Name: "ns.outside.net.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.8"})
	h := harness{hierarchy, root}

	// The address of a name nobody asked about, bundled into every answer.
	const unowned = "192.0.2.99"
	cfg := resolver.Config{Transport: tamper{h.carry(transport.NewUDP(fast)), func(req, resp *dns.Msg) {
		if _, qtype := dnsutil.Question(req); qtype != dns.TypeA || len(resp.Answer) == 0 {
			return
		}
		rr, err := dns.New("elsewhere.example. 3600 IN A " + unowned)
		if err != nil {
			t.Fatalf("building the record: %v", err)
		}
		resp.Answer = append(resp.Answer, rr)
	}}}

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for step := range tr.Steps() {
		if step.Server.IP.IsValid() && step.Server.IP.String() == unowned {
			t.Fatalf("the walk queried %s, which no record of a nameserver's name carried: %s",
				unowned, format(steps(tr)))
		}
	}
	if answer := tr.Result(); answer == nil || answer.Server.IP.String() != "192.0.2.8" {
		t.Errorf("got %+v, want the answer still to come from the side-resolved server", answer)
	}
}

// TestStrippedDSIsNotADowngrade is the attack the denial of existence is there
// to stop. Every zone is signed and vouched for, and somebody between the walk
// and the servers drops the DS records out of the referrals. Nothing is forged
// and no key is needed: without a proof that a delegation really has no DS, a
// chain that believes the absence walks itself off the secure path and says so
// with an exit code of nought.
func TestStrippedDSIsNotADowngrade(t *testing.T) {
	h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, fakens.Behaviour{})
	cfg.Transport = tamper{h.carry(transport.NewUDP(fast)), func(_, resp *dns.Msg) {
		kept := resp.Ns[:0:0]
		for _, rr := range resp.Ns {
			if dns.RRToType(rr) == dns.TypeDS {
				continue
			}
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeDS {
				continue
			}
			kept = append(kept, rr)
		}
		resp.Ns = kept
	}}

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil || answer.DNSSEC == nil {
		t.Fatalf("got %+v, want a verdict on the answer: %s", answer, format(steps(tr)))
	}
	if answer.DNSSEC.State == trace.Insecure {
		t.Fatalf("got insecure (%s), want a stripped DS not to pass for an unsigned zone",
			answer.DNSSEC.Reason)
	}
	if answer.DNSSEC.State != trace.Bogus {
		t.Errorf("got %s, want bogus", answer.DNSSEC.State)
	}
}

// TestProvenInsecureDelegation covers the honest version of the same shape, in
// each of the ways a parent proves it. A zone nobody vouches for is insecure,
// and has to stay that way: this is the common case on the real internet, and
// turning it into a failure would make --dnssec useless.
func TestProvenInsecureDelegation(t *testing.T) {
	for name, denial := range map[string]fakens.Denial{
		"opt-out NSEC3, the way com. does it": fakens.DenialNSEC3OptOut,
		"an NSEC3 naming the delegation":      fakens.DenialNSEC3,
		"an NSEC, without hashing":            fakens.DenialNSEC,
	} {
		t.Run(name, func(t *testing.T) {
			hierarchy := fakens.NewHierarchy(t)
			root := hierarchy.Add(fakens.Config{
				Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1",
				DNSSEC: true, Denial: denial})
			hierarchy.Add(fakens.Config{
				Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2",
				DNSSEC: true, Denial: denial, Behaviour: fakens.Behaviour{NoDS: true}})
			hierarchy.Add(fakens.Config{
				Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3",
				DNSSEC: true, Denial: denial})
			h := harness{hierarchy, root}

			cfg := resolver.Config{DNSSEC: true, Anchors: root.Anchors(t)}
			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			answer := tr.Result()
			if answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Insecure {
				t.Fatalf("got %+v, want the unsigned cut proven and inherited: %s",
					answer.DNSSEC, format(steps(tr)))
			}
			if root := tr.Root.DNSSEC; root == nil || root.State != trace.Secure {
				t.Errorf("got %+v on the root, want the part above the gap still secure", root)
			}
		})
	}
}

// TestUnprovenInsecureDelegation covers a signed parent that publishes neither
// a DS nor the proof that it has none. That is what a stripped referral looks
// like from below, and it cannot be told apart from one, so it is not insecure.
func TestUnprovenInsecureDelegation(t *testing.T) {
	// The claim is the parent's to make, so it is the root that withholds it:
	// nobody vouches for com., and the root will not sign saying so.
	h, cfg := signed(t, fakens.Behaviour{NoDenial: true}, fakens.Behaviour{NoDS: true}, fakens.Behaviour{})

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	answer := tr.Result()
	if answer == nil || answer.DNSSEC == nil {
		t.Fatalf("got %+v, want a verdict: %s", answer, format(steps(tr)))
	}
	if answer.DNSSEC.State == trace.Insecure {
		t.Fatalf("got insecure (%s), want an unproven claim refused", answer.DNSSEC.Reason)
	}
}

// TestForgedSignerCannotChooseTheCut covers a forged answer whose signature
// names an insecure delegation elsewhere in the zone. The DS of that delegation
// is genuinely denied, so a walk that let the signer pick the cut would verify
// the forgery as insecure and exit nought.
func TestForgedSignerCannotChooseTheCut(t *testing.T) {
	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true})
	hierarchy.Add(fakens.Config{
		Name: "ns.com.", Origin: "com.", Declared: "192.0.2.2", DNSSEC: true,
		Zone: comZone + "unsigned IN NS ns.unsigned\nns.unsigned IN A 192.0.2.9\n"})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3", DNSSEC: true})
	h := harness{hierarchy, root}

	forged := mustRR(t, "www.example.com. 3600 IN A 192.0.2.66")
	junk := mustRR(t, "www.example.com. 3600 IN RRSIG A 13 3 3600 20300101000000 20200101000000 1 unsigned.com. AAAA")
	cfg := resolver.Config{DNSSEC: true, Anchors: root.Anchors(t)}
	cfg.Transport = tamper{h.carry(transport.NewUDP(fast)), func(req, resp *dns.Msg) {
		// The com. referral to example.com. becomes an answer of its own.
		if qname, _ := dnsutil.Question(req); qname != "www.example.com." || resp.Authoritative || !delegates(resp, "example.com.") {
			return
		}
		resp.Authoritative = true
		resp.Answer, resp.Ns, resp.Extra = []dns.RR{forged, junk}, nil, nil
	}}

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	answer := tr.Result()
	if answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Bogus {
		t.Fatalf("got %+v, want the forged answer bogus: %s", answer, format(steps(tr)))
	}
}

// TestUnusableNSEC3IsNotAnExcuse covers a stripped DS replaced by one unsigned
// NSEC3 nothing here can hash. Unknown hashes are ignored, not trusted (RFC
// 5155 section 8.1), so what is left is a parent that proved nothing.
func TestUnusableNSEC3IsNotAnExcuse(t *testing.T) {
	for name, text := range map[string]string{
		"an unknown hash algorithm":        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.com. 3600 IN NSEC3 2 0 0 - BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB NS",
		"more iterations than worth doing": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.com. 3600 IN NSEC3 1 0 101 - BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB NS",
	} {
		t.Run(name, func(t *testing.T) {
			h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, fakens.Behaviour{})
			junk := mustRR(t, text)
			forged := mustRR(t, "www.example.com. 3600 IN A 192.0.2.66")
			cfg.Transport = tamper{h.carry(transport.NewUDP(fast)), func(_, resp *dns.Msg) {
				switch {
				case delegates(resp, "example.com."):
					kept := resp.Ns[:0:0]
					for _, rr := range resp.Ns {
						switch rr.(type) {
						case *dns.DS, *dns.RRSIG:
							continue
						}
						kept = append(kept, rr)
					}
					kept = append(kept, junk)
					resp.Ns = kept
				case resp.Authoritative && len(resp.Answer) > 0 && dns.EqualName(resp.Answer[0].Header().Name, "www.example.com."):
					resp.Answer = []dns.RR{forged}
				}
			}}

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			answer := tr.Result()
			if answer == nil || answer.DNSSEC == nil || answer.DNSSEC.State != trace.Bogus {
				t.Fatalf("got %+v, want the forged answer bogus: %s", answer.DNSSEC, format(steps(tr)))
			}
		})
	}
}

// delegates reports whether resp is a referral to zone.
func delegates(resp *dns.Msg, zone string) bool {
	for _, rr := range resp.Ns {
		if dns.RRToType(rr) == dns.TypeNS && dns.EqualName(rr.Header().Name, zone) {
			return true
		}
	}
	return false
}

func mustRR(tb testing.TB, text string) dns.RR {
	tb.Helper()
	rr, err := dns.New(text)
	if err != nil {
		tb.Fatalf("%s: %v", text, err)
	}
	return rr
}

// TestInterruptedIsNotATimeout covers Ctrl-C while a server is still quiet.
// The hop is cut short and says so, instead of waiting out the timeout and
// then blaming the server for it.
func TestInterruptedIsNotATimeout(t *testing.T) {
	h, cfg := service(t, false, fakens.Behaviour{Drop: true})
	cfg.Transport = h.carry(transport.NewUDP(transport.Config{Timeout: 5 * time.Second}))

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(100*time.Millisecond, cancel)
	tr, _ := newResolver(t, h, cfg).Resolve(ctx, "www.test", "A")
	if tr == nil {
		t.Fatal("got no trace, want one drawn up to the interruption")
	}

	for step := range tr.Steps() {
		if step.Kind == trace.KindTimeout {
			t.Errorf("got a timeout at %s, want the interruption named", step.Server.Name)
		}
		if step.Kind == trace.KindError && step.Err == "interrupted before the server answered" {
			return
		}
	}
	t.Errorf("no hop says it was interrupted: %s", format(steps(tr)))
}
