package resolver_test

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/internal/resolver"
	"github.com/rafaeljusto/dnstree/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/internal/trace"
	"github.com/rafaeljusto/dnstree/internal/transport"
)

// signedAs builds the three signed zones, each proving its gaps the way denial
// says, with the leaf zone free to misbehave.
func signedAs(tb testing.TB, denial fakens.Denial, leaf fakens.Behaviour) (harness, resolver.Config) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1",
		DNSSEC: true, Denial: denial})
	hierarchy.Add(fakens.Config{
		Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2",
		DNSSEC: true, Denial: denial})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: exampleZone, Declared: "192.0.2.3",
		DNSSEC: true, Denial: denial, Behaviour: leaf})
	return harness{hierarchy, root}, resolver.Config{DNSSEC: true, Anchors: root.Anchors(tb)}
}

// everyDenial runs one case against each shape a zone signs its gaps in.
func everyDenial(t *testing.T, run func(*testing.T, fakens.Denial)) {
	t.Helper()
	for name, denial := range map[string]fakens.Denial{
		"opt-out NSEC3": fakens.DenialNSEC3OptOut,
		"NSEC3":         fakens.DenialNSEC3,
		"NSEC":          fakens.DenialNSEC,
	} {
		t.Run(name, func(t *testing.T) { run(t, denial) })
	}
}

// TestNXDomainIsProved covers a name the zone does not hold. The zone signs the
// gap the name falls in, so an answer with nothing in it is as checkable as one
// with records.
func TestNXDomainIsProved(t *testing.T) {
	everyDenial(t, func(t *testing.T, denial fakens.Denial) {
		h, cfg := signedAs(t, denial, fakens.Behaviour{})

		tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "nothing.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		answer := tr.Result()
		if answer == nil || answer.Kind != trace.KindNXDomain {
			t.Fatalf("got %+v, want NXDOMAIN: %s", answer, format(steps(tr)))
		}
		if want := nameErrorVerdict(denial); answer.DNSSEC == nil || answer.DNSSEC.State != want {
			t.Fatalf("got %+v, want %s", answer.DNSSEC, want)
		}
	})
}

// nameErrorVerdict is what a sound NXDOMAIN is worth. An opt-out range may hide
// an unsigned delegation holding the name, so it proves only that the name is
// not signed.
func nameErrorVerdict(denial fakens.Denial) trace.DNSSECState {
	if denial == fakens.DenialNSEC3OptOut {
		return trace.Insecure
	}
	return trace.Secure
}

// TestNoDataIsProved covers a name that is there with nothing of the type asked
// for, which the zone proves by naming the types it does hold.
func TestNoDataIsProved(t *testing.T) {
	everyDenial(t, func(t *testing.T, denial fakens.Denial) {
		h, cfg := signedAs(t, denial, fakens.Behaviour{})

		tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "MX")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		answer := tr.Result()
		if answer == nil || answer.Kind != trace.KindNoData {
			t.Fatalf("got %+v, want NODATA: %s", answer, format(steps(tr)))
		}
		if answer.DNSSEC == nil || answer.DNSSEC.State != trace.Secure {
			t.Fatalf("got %+v, want the missing type proved", answer.DNSSEC)
		}
	})
}

// TestUnprovedNXDomain covers a signed zone answering NXDOMAIN with nothing to
// back it. An empty answer is the cheapest thing to forge, so one the zone did
// not sign for is not an answer at all.
func TestUnprovedNXDomain(t *testing.T) {
	everyDenial(t, func(t *testing.T, denial fakens.Denial) {
		h, cfg := signedAs(t, denial, fakens.Behaviour{NoDenial: true})

		tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "nothing.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		answer := tr.Result()
		if answer == nil || answer.DNSSEC == nil {
			t.Fatalf("got %+v, want a verdict: %s", answer, format(steps(tr)))
		}
		if answer.DNSSEC.State == trace.Secure {
			t.Fatalf("got secure (%s), want an unproved absence refused", answer.DNSSEC.Reason)
		}
		if answer.DNSSEC.State != trace.Bogus {
			t.Errorf("got %s, want bogus", answer.DNSSEC.State)
		}
	})
}

// TestUnprovedNoData is the same for a type the zone will not account for.
func TestUnprovedNoData(t *testing.T) {
	everyDenial(t, func(t *testing.T, denial fakens.Denial) {
		h, cfg := signedAs(t, denial, fakens.Behaviour{NoDenial: true})

		tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "MX")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		answer := tr.Result()
		if answer == nil || answer.DNSSEC == nil {
			t.Fatalf("got %+v, want a verdict: %s", answer, format(steps(tr)))
		}
		if answer.DNSSEC.State == trace.Secure {
			t.Fatalf("got secure (%s), want an unproved NODATA refused", answer.DNSSEC.Reason)
		}
	})
}

// TestDeniedNameThatIsThere covers a server stripping the records out of an
// answer and calling the name absent. The gap the zone signed does not hold a
// name the zone holds, so the lie has nothing to stand on.
func TestDeniedNameThatIsThere(t *testing.T) {
	everyDenial(t, func(t *testing.T, denial fakens.Denial) {
		h, cfg := signedAs(t, denial, fakens.Behaviour{})
		cfg.Transport = tamper{h.carry(transport.NewUDP(fast)), func(req, resp *dns.Msg) {
			if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
				return
			}
			if _, qtype := dnsutil.Question(req); qtype != dns.TypeA {
				return
			}
			resp.Answer = nil
			resp.Rcode = dns.RcodeNameError
		}}

		tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		answer := tr.Result()
		if answer == nil || answer.DNSSEC == nil {
			t.Fatalf("got %+v, want a verdict: %s", answer, format(steps(tr)))
		}
		if answer.DNSSEC.State == trace.Secure {
			t.Fatalf("got secure (%s), want a name denied that the zone holds refused",
				answer.DNSSEC.Reason)
		}
	})
}

// TestHiddenCutDeniesAcrossIt covers an empty answer arriving across a zone cut
// no referral crossed. A registry serving its own domains from the machines of
// its ccTLD answers for the child without referring to it, and an answer with no
// records has none to name the zone that signed them — so the denial has to name
// it instead, or the chain checks the child's proof against the parent's keys
// and calls a sound zone bogus.
func TestHiddenCutDeniesAcrossIt(t *testing.T) {
	everyDenial(t, func(t *testing.T, denial fakens.Denial) {
		for what, test := range map[string]struct {
			question [2]string
			want     trace.DNSSECState
		}{
			"a name it does not hold":  {[2]string{"nothing.hosted.com", "A"}, nameErrorVerdict(denial)},
			"a type the name has none": {[2]string{"www.hosted.com", "MX"}, trace.Secure},
		} {
			question := test.question
			t.Run(what, func(t *testing.T) {
				h, cfg := signedAs(t, denial, fakens.Behaviour{})
				// The same declared address as ns.com., so the walk never learns
				// there is a cut here except from the signatures.
				h.hierarchy.Add(fakens.Config{
					Name: "ns.com.", Origin: "hosted.com.", Zone: hostedZone, Declared: "192.0.2.2",
					DNSSEC: true, Denial: denial,
				})

				tr, err := newResolver(t, h, cfg).Resolve(t.Context(), question[0], question[1])
				if err != nil {
					t.Fatalf("Resolve: %v", err)
				}
				answer := tr.Result()
				if answer == nil || answer.DNSSEC == nil {
					t.Fatalf("got %+v, want a verdict: %s", answer, format(steps(tr)))
				}
				if answer.DNSSEC.State != test.want {
					t.Fatalf("got %+v, want %s from the child's keys: %s",
						answer.DNSSEC, test.want, format(steps(tr)))
				}
			})
		}
	})
}
