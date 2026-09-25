package resolver_test

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/roothints"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// The synthetic internet these tests resolve against. Every nameserver is glued
// inside the zone it serves, so the walk only ever follows in-bailiwick glue.
const (
	rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   ns.com.
ns.com.             IN A    192.0.2.2
co.uk.              IN NS   ns.co.uk.
ns.co.uk.           IN A    192.0.2.4
`

	comZone = `
@       IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns
ns      IN A    192.0.2.2
example IN NS   ns.example
ns.example IN A 192.0.2.3
`

	exampleZone = `
@     IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@     IN NS   ns
ns    IN A    192.0.2.3
www   IN A    192.0.2.10
www   IN AAAA 2001:db8::1
mail  IN MX   10 mx
text  IN TXT  "hello"
`

	coUKZone = `
@           IN SOA ns hostmaster 1 7200 3600 1209600 3600
@           IN NS  ns
ns          IN A   192.0.2.4
www.example IN A   192.0.2.20
`
)

func TestResolve(t *testing.T) {
	res := newResolver(t, internet(t), resolver.Config{})

	tr, err := res.Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(tr.Warnings) != 0 {
		t.Errorf("got warnings %q, want none", tr.Warnings)
	}
	if tr.Question != (trace.Question{Name: "www.example.com.", Type: "A", Class: "IN"}) {
		t.Errorf("got question %+v, want www.example.com. A IN", tr.Question)
	}
	if tr.Elapsed <= 0 {
		t.Error("got no elapsed time, want one")
	}

	want := []struct {
		zone   string
		kind   trace.StepKind
		server string
	}{
		{zone: ".", kind: trace.KindReferral, server: "192.0.2.1"},
		{zone: "com.", kind: trace.KindReferral, server: "192.0.2.2"},
		{zone: "example.com.", kind: trace.KindAnswer, server: "192.0.2.3"},
	}
	steps := steps(tr)
	if len(steps) != len(want) {
		t.Fatalf("got %d steps, want %d: %s", len(steps), len(want), format(steps))
	}
	for i, step := range steps {
		if step.Zone != want[i].zone || step.Kind != want[i].kind {
			t.Errorf("step %d: got %s %s, want %s %s", i, step.Zone, step.Kind, want[i].zone, want[i].kind)
		}
		if got := step.Server.IP.String(); got != want[i].server {
			t.Errorf("step %d: got server %s, want %s", i, got, want[i].server)
		}
		if step.Rcode != "NOERROR" {
			t.Errorf("step %d: got rcode %s, want NOERROR", i, step.Rcode)
		}
		if step.Proto != "udp" || step.RTT <= 0 {
			t.Errorf("step %d: got %s in %v, want a udp hop with an rtt", i, step.Proto, step.RTT)
		}
	}

	// The referrals carry the delegation the next hop was taken from.
	if zone := steps[0].Delegation.Zone; zone != "com." {
		t.Errorf("got a delegation to %s, want com.", zone)
	}
	if glue := steps[1].Delegation.Glue["ns.example.com."]; len(glue) != 1 || glue[0].String() != "192.0.2.3" {
		t.Errorf("got glue %v for ns.example.com., want 192.0.2.3", glue)
	}
	if !steps[2].Flags.AA {
		t.Error("got no AA bit on the answer, want one")
	}

	result := tr.Result()
	if result != steps[2] {
		t.Fatalf("got result %+v, want the answering step", result)
	}
	if len(result.Records) != 1 || result.Records[0].Data != "192.0.2.10" {
		t.Errorf("got records %+v, want one A of 192.0.2.10", result.Records)
	}
	if got := result.Records[0]; got.Name != "www.example.com." || got.Type != "A" || got.TTL != 3600 {
		t.Errorf("got record %+v, want www.example.com. 3600 A", got)
	}
}

// TestResolveStepped watches a walk the way a live drawing does: one call per
// hop, from the goroutine building the trace, with the whole tree readable
// inside the call. Nothing here is guarded, which is the point: under -race, a
// hop announced from anywhere else would be caught.
func TestResolveStepped(t *testing.T) {
	var (
		counted []int
		mu      sync.Mutex
		seen    []netip.Addr
	)
	cfg := resolver.Config{
		All: true, // so that the hops asked in parallel are covered too
		Stepped: func(tr *trace.Trace) {
			counted = append(counted, len(steps(tr)))
		},
		Discovered: func(addr netip.Addr) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, addr)
		},
	}

	res := newResolver(t, internet(t), cfg)
	tr, err := res.Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(counted) == 0 {
		t.Fatal("got no hops announced, want one per step")
	}
	for i, count := range counted {
		if count != i+1 {
			t.Fatalf("announcement %d: got %d steps, want %d", i, count, i+1)
		}
	}
	if got, want := counted[len(counted)-1], len(steps(tr)); got != want {
		t.Errorf("got %d steps announced in all, want the %d the trace ended with", got, want)
	}
	if len(seen) == 0 {
		t.Error("got no servers announced, want the ones the walk asked")
	}
}

// TestResolveAsking covers the hook a live drawing waits on: a query is
// announced before it goes out and finished when it comes back, so that
// nothing is left in flight by the end of a walk.
func TestResolveAsking(t *testing.T) {
	var (
		mu     sync.Mutex
		asked  int
		flight int
	)
	cfg := resolver.Config{
		All: true, // so that several are in flight at once
		Asking: func(zone string, _ trace.Server) func() {
			mu.Lock()
			defer mu.Unlock()
			if zone == "" {
				t.Error("got a query about no zone, want the one being asked about")
			}
			asked, flight = asked+1, flight+1
			return func() {
				mu.Lock()
				defer mu.Unlock()
				flight--
			}
		},
	}

	res := newResolver(t, internet(t), cfg)
	if _, err := res.Resolve(t.Context(), "www.example.com", "A"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if asked == 0 {
		t.Fatal("got no queries announced, want one per query sent")
	}
	if flight != 0 {
		t.Errorf("got %d queries still in flight, want every one of them finished", flight)
	}
}

// TestResolveSkippedZoneCut covers a zone cut that label counting would miss:
// the root refers straight to co.uk., two labels down.
func TestResolveSkippedZoneCut(t *testing.T) {
	res := newResolver(t, internet(t), resolver.Config{})

	tr, err := res.Resolve(t.Context(), "www.example.co.uk", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	steps := steps(tr)
	if len(steps) != 2 {
		t.Fatalf("got %d steps, want 2: %s", len(steps), format(steps))
	}
	if steps[0].Kind != trace.KindReferral || steps[0].Delegation.Zone != "co.uk." {
		t.Fatalf("got %s to %+v, want a referral to co.uk.", steps[0].Kind, steps[0].Delegation)
	}
	if steps[1].Zone != "co.uk." || steps[1].Kind != trace.KindAnswer {
		t.Errorf("got %s %s, want an answer from co.uk.", steps[1].Zone, steps[1].Kind)
	}
}

// TestResolveLameThenSuccess walks past a server that refuses the zone it was
// delegated, the most common real-world finding.
func TestResolveLameThenSuccess(t *testing.T) {
	const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   lame.com.
com.                IN NS   ns.com.
lame.com.           IN A    192.0.2.5
ns.com.             IN A    192.0.2.2
`

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{
		Name: "lame.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.5",
		Behaviour: fakens.Behaviour{Refuse: true},
	})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3"})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{}).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	steps := steps(tr)
	if len(steps) != 4 {
		t.Fatalf("got %d steps, want 4: %s", len(steps), format(steps))
	}
	if steps[1].Kind != trace.KindLame || steps[1].Rcode != "REFUSED" {
		t.Errorf("got %s %s from the lame server, want a lame REFUSED", steps[1].Kind, steps[1].Rcode)
	}
	if steps[1].Zone != "com." || steps[2].Zone != "com." {
		t.Errorf("got zones %s and %s, want both servers tried for com.", steps[1].Zone, steps[2].Zone)
	}
	if steps[2].Kind != trace.KindReferral {
		t.Errorf("got %s from the second server, want it to refer on", steps[2].Kind)
	}
	if tr.Result() == nil || tr.Result().Kind != trace.KindAnswer {
		t.Errorf("got result %+v, want the answer the second server led to", tr.Result())
	}
}

// TestResolveReferralLoop covers a delegation whose glue points back at the
// server that handed it out, which would otherwise be chased forever.
func TestResolveReferralLoop(t *testing.T) {
	const comZone = `
@          IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@          IN NS   ns
ns         IN A    192.0.2.2
example    IN NS   ns.example
ns.example IN A    192.0.2.2
`

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{}).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	steps := steps(tr)
	if len(steps) != 3 {
		t.Fatalf("got %d steps, want 3: %s", len(steps), format(steps))
	}
	// Asked again as the example.com. server, it can only repeat the referral it
	// already gave, which is not a step downwards.
	last := steps[len(steps)-1]
	if last.Zone != "example.com." || last.Kind != trace.KindLame {
		t.Errorf("got %s %s, want the repeated referral to read as lame", last.Zone, last.Kind)
	}
	if len(tr.Warnings) != 1 {
		t.Fatalf("got warnings %q, want one about example.com.", tr.Warnings)
	}
}

// TestResolveOutOfBailiwickGlue covers the poisoning guard: a server may vouch
// for names at or below the zone it serves and no further, so an address it
// volunteers for somebody else's zone is dropped and the name found elsewhere.
func TestResolveOutOfBailiwickGlue(t *testing.T) {
	const comZone = `
@               IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@               IN NS   ns
ns              IN A    192.0.2.2
example         IN NS   ns.outside.net.
ns.outside.net. IN A    192.0.2.3
`

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{
		Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2",
		Behaviour: fakens.Behaviour{OutOfBailiwickGlue: true},
	})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{}).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	referral := steps(tr)[1]
	if referral.Kind != trace.KindReferral || referral.Zone != "com." {
		t.Fatalf("got %s at %s, want the referral from com.: %s", referral.Kind, referral.Zone, format(steps(tr)))
	}
	if len(referral.Delegation.Glue) != 0 {
		t.Errorf("got glue %v, want the address com. had no business giving dropped", referral.Delegation.Glue)
	}
	if got := referral.Delegation.OutOfBailiwick; len(got) != 1 || got[0] != "ns.outside.net." {
		t.Errorf("got out-of-bailiwick %v, want ns.outside.net.", got)
	}

	// The name is chased on its own instead, as a branch of the referral.
	var side *trace.Step
	for _, child := range referral.Children {
		if child.Kind == trace.KindZone {
			side = child
		}
	}
	if side == nil {
		t.Fatalf("got no side resolution under the referral, want one for ns.outside.net.")
	}
	if len(side.Notes) != 1 || side.Notes[0] != "resolving ns.outside.net." {
		t.Errorf("got notes %q, want the branch to say what it is resolving", side.Notes)
	}
}

// TestResolveSiblingGlue covers the other side of the same rule: the root is
// entitled to hand out the addresses of the gTLD servers, and a walk that threw
// them away would ask the root about every one of them.
func TestResolveSiblingGlue(t *testing.T) {
	const rootZone = `
@                   IN SOA  a.root-servers.net. hostmaster 1 7200 3600 1209600 3600
@                   IN NS   a.root-servers.net.
a.root-servers.net. IN A    192.0.2.1
com.                IN NS   a.gtld-servers.net.
a.gtld-servers.net. IN A    192.0.2.2
`

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1",
		Behaviour: fakens.Behaviour{OutOfBailiwickGlue: true},
	})
	hierarchy.Add(fakens.Config{Name: "a.gtld-servers.net.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3"})

	tr, err := newResolver(t, harness{hierarchy, root}, resolver.Config{}).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if glue := steps(tr)[0].Delegation.Glue["a.gtld-servers.net."]; len(glue) != 1 {
		t.Fatalf("got glue %v for a.gtld-servers.net., want the root's own", glue)
	}
	if answer := tr.Result(); answer == nil || answer.Kind != trace.KindAnswer {
		t.Fatalf("got %+v, want the walk to go straight down: %s", answer, format(steps(tr)))
	}
	for _, step := range steps(tr) {
		if step.Kind == trace.KindZone {
			t.Errorf("got a walk of its own for %q, want the root's glue taken at its word", step.Notes)
		}
	}
}

func TestResolveKinds(t *testing.T) {
	tests := map[string]struct {
		name    string
		qtype   string
		kind    trace.StepKind
		records []string
	}{
		"a":        {name: "www.example.com", qtype: "A", kind: trace.KindAnswer, records: []string{"192.0.2.10"}},
		"aaaa":     {name: "www.example.com", qtype: "AAAA", kind: trace.KindAnswer, records: []string{"2001:db8::1"}},
		"mx":       {name: "mail.example.com", qtype: "MX", kind: trace.KindAnswer, records: []string{"10 mx.example.com."}},
		"txt":      {name: "text.example.com", qtype: "TXT", kind: trace.KindAnswer, records: []string{`"hello"`}},
		"ns":       {name: "example.com", qtype: "NS", kind: trace.KindAnswer, records: []string{"ns.example.com."}},
		"nodata":   {name: "www.example.com", qtype: "TXT", kind: trace.KindNoData},
		"nxdomain": {name: "nope.example.com", qtype: "A", kind: trace.KindNXDomain},
	}

	res := newResolver(t, internet(t), resolver.Config{})
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tr, err := res.Resolve(t.Context(), test.name, test.qtype)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			result := tr.Result()
			if result == nil {
				t.Fatalf("got no result, want a %s: %s", test.kind, format(steps(tr)))
			}
			if result.Kind != test.kind {
				t.Errorf("got %s, want %s", result.Kind, test.kind)
			}
			if len(result.Records) != len(test.records) {
				t.Fatalf("got records %+v, want %d", result.Records, len(test.records))
			}
			for i, record := range result.Records {
				if record.Data != test.records[i] {
					t.Errorf("got record %q, want %q", record.Data, test.records[i])
				}
			}
		})
	}
}

func TestResolveBudget(t *testing.T) {
	tests := map[string]struct {
		budget resolver.Budget
		steps  int
		reason string
	}{
		"queries": {budget: resolver.Budget{MaxQueries: 2}, steps: 3, reason: "gave up after 2 queries"},
		"depth":   {budget: resolver.Budget{MaxDepth: 2}, steps: 3, reason: "gave up after 2 zone cuts"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			res := newResolver(t, internet(t), resolver.Config{Budget: test.budget})

			tr, err := res.Resolve(t.Context(), "www.example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			steps := steps(tr)
			if len(steps) != test.steps {
				t.Fatalf("got %d steps, want %d: %s", len(steps), test.steps, format(steps))
			}
			last := steps[len(steps)-1]
			if last.Kind != trace.KindError || last.Err != test.reason {
				t.Errorf("got %s %q, want an error step saying %q", last.Kind, last.Err, test.reason)
			}
			if tr.Result() != nil {
				t.Errorf("got result %+v, want none", tr.Result())
			}
		})
	}
}

func TestResolveUnreachable(t *testing.T) {
	// A root server nothing stands behind: the address is never mapped to a
	// listening socket.
	hierarchy := fakens.NewHierarchy(t)
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})

	res, err := resolver.New(resolver.Config{
		Transport: hierarchy.Transport(transport.NewUDP(transport.Config{Timeout: 100 * time.Millisecond})),
		Roots:     []trace.Server{{Name: "dead.root.", IP: netip.MustParseAddr("192.0.2.99"), Port: 53}},
	})
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}

	tr, err := res.Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	steps := steps(tr)
	if len(steps) != 1 {
		t.Fatalf("got %d steps, want 1: %s", len(steps), format(steps))
	}
	switch steps[0].Kind {
	case trace.KindTimeout, trace.KindError:
	default:
		t.Errorf("got %s, want the hop to read as unreachable", steps[0].Kind)
	}
	if steps[0].Err == "" {
		t.Error("got no error on the step, want the reason")
	}
	if len(tr.Warnings) != 1 {
		t.Errorf("got warnings %q, want one about the root", tr.Warnings)
	}
}

func TestNew(t *testing.T) {
	roots := []trace.Server{{Name: "a.root-servers.net.", IP: netip.MustParseAddr("192.0.2.1"), Port: 53}}
	if _, err := resolver.New(resolver.Config{Roots: roots}); err == nil {
		t.Error("got no error without a transport, want one")
	}
	if _, err := resolver.New(resolver.Config{Transport: transport.NewUDP(transport.Config{})}); err == nil {
		t.Error("got no error without root servers, want one")
	}
}

func TestResolveBadQuestion(t *testing.T) {
	res := newResolver(t, internet(t), resolver.Config{})

	if _, err := res.Resolve(t.Context(), "www.example.com", "NOPE"); err == nil {
		t.Error("got no error for an unknown type, want one")
	}
	// A label may hold any octet, but not more than 63 of them.
	if _, err := res.Resolve(t.Context(), strings.Repeat("a", 64)+".example.com", "A"); err == nil {
		t.Error("got no error for a malformed name, want one")
	}
}

func TestRootServers(t *testing.T) {
	hints, err := roothints.Default()
	if err != nil {
		t.Fatalf("roothints.Default: %v", err)
	}

	servers := resolver.RootServers(hints)
	if len(servers) != 26 {
		t.Fatalf("got %d servers, want an IPv4 and an IPv6 one for each of the 13 roots", len(servers))
	}
	// The hints carry no port: the transport says where to knock, so that
	// --port and the encrypted transports reach the roots as well.
	if first := servers[0]; first.Name != "a.root-servers.net." || first.Port != 0 || first.IP.String() != "198.41.0.4" {
		t.Errorf("got %+v first, want a.root-servers.net. at 198.41.0.4 with no port of its own", first)
	}
}

// harness is a hierarchy and the server a walk starts from.
type harness struct {
	hierarchy *fakens.Hierarchy
	root      *fakens.Server
}

// internet builds the shared synthetic internet: root, com., example.com. and
// co.uk., each on its own server.
func internet(tb testing.TB) harness {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1"})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2"})
	hierarchy.Add(fakens.Config{Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3"})
	hierarchy.Add(fakens.Config{Name: "ns.co.uk.", Origin: "co.uk.", Zone: coUKZone, Declared: "192.0.2.4"})
	return harness{hierarchy, root}
}

// newResolver fills in whatever the test did not care to set.
func newResolver(tb testing.TB, h harness, cfg resolver.Config) *resolver.Resolver {
	tb.Helper()

	if cfg.Transport == nil {
		cfg.Transport = h.carry(transport.NewUDP(fast))
	}
	if len(cfg.Roots) == 0 {
		cfg.Roots = []trace.Server{h.root.Nameserver()}
	}

	res, err := resolver.New(cfg)
	if err != nil {
		tb.Fatalf("resolver.New: %v", err)
	}
	return res
}

// carry wraps a transport so that it reaches the servers of the hierarchy.
func (h harness) carry(inner transport.Transport) transport.Transport {
	return h.hierarchy.Transport(inner)
}

// fast keeps the failure cases from sitting on the default timeout.
var fast = transport.Config{Timeout: 500 * time.Millisecond}

// steps is every query of a trace, in the order it was made.
func steps(tr *trace.Trace) []*trace.Step {
	var steps []*trace.Step
	for step := range tr.Steps() {
		if step.Kind != trace.KindZone {
			steps = append(steps, step)
		}
	}
	return steps
}

func format(steps []*trace.Step) string {
	out := ""
	for _, step := range steps {
		out += "\n\t" + step.Zone + " " + string(step.Kind) + " " + step.Rcode + " " + step.Err
	}
	return out
}
