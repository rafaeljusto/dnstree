package resolver_test

import (
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// The mail tests resolve against com., with example.com. and two providers its
// mail may go to: mailhost.com., signed, and plain.com., not.
const (
	mailComZone = `
@           IN SOA ns hostmaster 1 7200 3600 1209600 3600
@           IN NS  ns
ns          IN A   192.0.2.2
example     IN NS  ns.example
ns.example  IN A   192.0.2.3
mailhost    IN NS  ns.mailhost
ns.mailhost IN A   192.0.2.5
plain       IN NS  ns.plain
ns.plain    IN A   192.0.2.6
`

	tlsaData = "e41cc7633029afdba53744d7e5fc31ef507e592de9dfb33557bf3b9a79239446"

	mailExampleZone = `
@             IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@             IN NS   ns
ns            IN A    192.0.2.3
mx            IN A    192.0.2.25
_25._tcp.mx   IN TLSA 3 1 1 ` + tlsaData + `
solo          IN A    192.0.2.30
alias         IN CNAME @
`

	mailhostZone = `
@             IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@             IN NS   ns
ns            IN A    192.0.2.5
mx            IN A    192.0.2.26
_25._tcp.mx   IN TLSA 3 1 1 ` + tlsaData + `
pkix          IN A    192.0.2.27
_25._tcp.pkix IN TLSA 1 0 1 ` + tlsaData + `
bare          IN A    192.0.2.28
mx3           IN A    192.0.2.32
_25._tcp.mx3  IN CNAME _25._tcp.mx.plain.com.
`

	plainZone = `
@             IN SOA  ns hostmaster 1 7200 3600 1209600 3600
@             IN NS   ns
ns            IN A    192.0.2.6
mx            IN A    192.0.2.29
_25._tcp.mx   IN TLSA 3 1 1 ` + tlsaData + `
`
)

// mailed builds the root, com., example.com. serving mailExampleZone and
// extra, mailhost.com. with behaviour, and plain.com., unsigned. signed signs
// all but plain.com.
func mailed(tb testing.TB, extra string, behaviour fakens.Behaviour, signed bool) (harness, resolver.Config) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: signed,
	})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: mailComZone, Declared: "192.0.2.2", DNSSEC: signed})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: mailExampleZone + extra, Declared: "192.0.2.3",
		DNSSEC: signed, Denial: fakens.DenialNSEC3,
	})
	hierarchy.Add(fakens.Config{
		Name: "ns.mailhost.com.", Origin: "mailhost.com.", Zone: mailhostZone, Declared: "192.0.2.5",
		DNSSEC: signed, Denial: fakens.DenialNSEC3, Behaviour: behaviour,
	})
	hierarchy.Add(fakens.Config{Name: "ns.plain.com.", Origin: "plain.com.", Zone: plainZone, Declared: "192.0.2.6"})

	h := harness{hierarchy, root}
	cfg := resolver.Config{Mail: true}
	if signed {
		cfg.DNSSEC, cfg.Anchors = true, root.Anchors(tb)
	}
	return h, cfg
}

// hostStates are the hosts as names and what DANE does for each.
func hostStates(m *trace.Mail) []string {
	var states []string
	for _, host := range m.Hosts {
		states = append(states, host.Name+" "+string(host.DANE))
	}
	return states
}

func TestMailDANE(t *testing.T) {
	for name, tt := range map[string]struct {
		extra     string
		behaviour fakens.Behaviour
		qname     string

		hosts    []string
		null     bool
		implicit bool
		alias    string
		tlsa     string // the TLSA lookup of the first host, where it matters
		warning  string // a part of a warning that has to be there
	}{
		"a host in a signed zone with a usable TLSA set is covered": {
			extra: `@ IN MX 10 mx`,
			qname: "example.com", hosts: []string{"mx.example.com. dane"},
		},
		"a backup MX in an unsigned zone leaves DANE covering one host of two": {
			extra: `@ IN MX 10 mx
@ IN MX 20 mx.plain.com.`,
			qname: "example.com", hosts: []string{"mx.example.com. dane", "mx.plain.com. insecure"},
			warning: "DANE covers 1 of the 2 MX hosts",
		},
		"hosts of one preference are drawn by name": {
			extra: `@ IN MX 10 mx.mailhost.com.
@ IN MX 10 mx`,
			qname: "example.com", hosts: []string{"mx.example.com. dane", "mx.mailhost.com. dane"},
		},
		"a TLSA lookup the server fails makes the host unreachable to a DANE sender": {
			extra: `@ IN MX 10 mx.mailhost.com.`, behaviour: fakens.Behaviour{ServFailType: dns.TypeTLSA},
			qname: "example.com", hosts: []string{"mx.mailhost.com. failed"},
			warning: "treats mx.mailhost.com. as unreachable",
		},
		"a provider whose signatures do not verify makes its host unreachable to a DANE sender": {
			extra: `@ IN MX 10 mx.mailhost.com.`, behaviour: fakens.Behaviour{BadSignature: true},
			qname: "example.com", hosts: []string{"mx.mailhost.com. failed"},
			warning: "treats mx.mailhost.com. as unreachable",
		},
		"a TLSA set of PKIX usages alone is one no mail sender may use": {
			extra: `@ IN MX 10 pkix.mailhost.com.`,
			qname: "example.com", hosts: []string{"pkix.mailhost.com. unusable"},
		},
		"a signed zone that proves there is no TLSA set leaves DANE out": {
			extra: `@ IN MX 10 bare.mailhost.com.`,
			qname: "example.com", hosts: []string{"bare.mailhost.com. none"},
		},
		"a null MX takes no mail": {
			extra: `@ IN MX 0 .`,
			qname: "example.com", null: true,
		},
		"no MX set makes the name its own host": {
			qname: "solo.example.com", hosts: []string{"solo.example.com. none"}, implicit: true,
		},
		"an MX set reached through an alias is the target's": {
			extra: `@ IN MX 10 mx`,
			qname: "alias.example.com", hosts: []string{"mx.example.com. dane"}, alias: "example.com.",
		},
		"an address where a host name belongs is not DANE's": {
			extra: `@ IN MX 10 192.0.2.99.`,
			qname: "example.com", hosts: []string{"192.0.2.99. literal"},
		},
		"a host that does not exist has nowhere to deliver": {
			extra: `@ IN MX 10 gone
@ IN MX 20 mx`,
			qname: "example.com", hosts: []string{"gone.example.com. unreachable", "mx.example.com. dane"},
		},
		"a TLSA set an alias leads into an unsigned zone is ignored": {
			extra: `@ IN MX 10 mx2
mx2 IN A 192.0.2.31
_25._tcp.mx2 IN CNAME _25._tcp.mx.plain.com.`,
			qname: "example.com", hosts: []string{"mx2.example.com. insecure"},
			tlsa: "_25._tcp.mx2.example.com.", warning: "has a TLSA set nothing signed",
		},
		"a host that is a signed alias is looked for under its target first": {
			extra: `@ IN MX 10 relay
relay IN CNAME mx.mailhost.com.`,
			qname: "example.com", hosts: []string{"relay.example.com. dane"}, tlsa: "_25._tcp.mx.mailhost.com.",
		},
		"keys the zone will not hand over leave its host unchecked rather than failed": {
			extra: `@ IN MX 10 mx.mailhost.com.`, behaviour: fakens.Behaviour{NoDNSKEY: true},
			qname: "example.com", hosts: []string{"mx.mailhost.com. indeterminate"},
		},
		"a TLSA lookup that fails beside a covered host is not one to publish TLSA for": {
			extra: `@ IN MX 10 mx
@ IN MX 20 mx.mailhost.com.`, behaviour: fakens.Behaviour{ServFailType: dns.TypeTLSA},
			qname: "example.com", hosts: []string{"mx.example.com. dane", "mx.mailhost.com. failed"},
			warning: "treats mx.mailhost.com. as unreachable",
		},
		"a signed alias whose target's TLSA set is unsigned is looked for under its own name": {
			extra: `@ IN MX 10 relay
relay IN CNAME mx3.mailhost.com.
_25._tcp.relay IN TLSA 3 1 1 ` + tlsaData,
			qname: "example.com", hosts: []string{"relay.example.com. dane"}, tlsa: "_25._tcp.relay.example.com.",
		},
		"a signed alias whose target has no TLSA set is looked for under its own name": {
			extra: `@ IN MX 10 relay
relay IN CNAME bare.mailhost.com.
_25._tcp.relay IN TLSA 3 1 1 ` + tlsaData,
			qname: "example.com", hosts: []string{"relay.example.com. dane"}, tlsa: "_25._tcp.relay.example.com.",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, cfg := mailed(t, tt.extra, tt.behaviour, true)

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), tt.qname, "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			m := tr.Mail
			if m == nil {
				t.Fatal("got no mail path, want one")
			}
			if got := hostStates(m); !slices.Equal(got, tt.hosts) {
				t.Errorf("got hosts %q, want %q (%s)", got, tt.hosts, m.Stopped)
			}
			if m.Null != tt.null || m.Implicit != tt.implicit {
				t.Errorf("got null %v and implicit %v, want %v and %v", m.Null, m.Implicit, tt.null, tt.implicit)
			}
			if m.MX.Alias != tt.alias {
				t.Errorf("got the MX set at %q, want %q", m.MX.Alias, tt.alias)
			}
			if tt.tlsa != "" && (len(m.Hosts) == 0 || m.Hosts[0].TLSA == nil || m.Hosts[0].TLSA.Name != tt.tlsa) {
				t.Errorf("got the TLSA lookup %+v, want it at %s", m.Hosts[0].TLSA, tt.tlsa)
			}

			warned := slices.ContainsFunc(tr.Warnings, func(w string) bool { return tt.warning != "" && strings.Contains(w, tt.warning) })
			if tt.warning != "" && !warned {
				t.Errorf("got warnings %q, want one saying %q", tr.Warnings, tt.warning)
			}
			if tt.warning == "" && slices.ContainsFunc(tr.Warnings, mailWarning) {
				t.Errorf("got warnings %q, want none about the mail path", tr.Warnings)
			}
			if slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "unverified") }) &&
				slices.Contains(tt.hosts, "mx.mailhost.com. failed") {
				t.Errorf("got warnings %q, want none asking for TLSA a sender skips the host for", tr.Warnings)
			}

			for step := range tr.Mainline() {
				if step.Asked.Type == "MX" || step.Asked.Type == "TLSA" || step.Asked.Type == "TXT" {
					t.Errorf("got the %s of %s on the walk itself, want it drawn as an aside", step.Asked.Type, step.Asked.Name)
				}
			}
			if result := tr.Result(); result == nil || result.Asked.Type != "A" {
				t.Errorf("got the result %+v, want the walk's own answer", result)
			}
		})
	}
}

// mailWarning reports whether a warning is one the mail check gives.
func mailWarning(warning string) bool {
	for _, part := range []string{"DANE", "TLSA", "MX", "policy at", "mail check"} {
		if strings.Contains(warning, part) {
			return true
		}
	}
	return false
}

func TestMailPolicies(t *testing.T) {
	for name, tt := range map[string]struct {
		extra string
		qname string

		mtaSTS, tlsRPT, dmarc trace.PolicyFound
		dmarcAt               string
		warning               string
	}{
		"policies published at the name are read": {
			extra: `_mta-sts IN TXT "v=STSv1; id=20240101T000000"
_smtp._tls IN TXT "v=TLSRPTv1; " "rua=mailto:tls@example.com"
_dmarc IN TXT "v=DMARC1; p=reject"
_mta-sts IN TXT "something else"`,
			qname:  "example.com",
			mtaSTS: trace.PolicyPublished, tlsRPT: trace.PolicyPublished, dmarc: trace.PolicyPublished,
			dmarcAt: "_dmarc.example.com.",
		},
		"nothing published is none of them": {
			qname:  "example.com",
			mtaSTS: trace.PolicyNone, tlsRPT: trace.PolicyNone, dmarc: trace.PolicyNone,
			dmarcAt: "_dmarc.example.com.",
		},
		"two MTA-STS records are none to a sender": {
			extra: `_mta-sts IN TXT "v=STSv1; id=1"
_mta-sts IN TXT "v=STSv1; id=2"`,
			qname:  "example.com",
			mtaSTS: trace.PolicyInvalid, tlsRPT: trace.PolicyNone, dmarc: trace.PolicyNone,
			dmarcAt: "_dmarc.example.com.", warning: "the policy at _mta-sts.example.com.",
		},
		"an MTA-STS record with no id is none to a sender": {
			extra:  `_mta-sts IN TXT "v=STSv1;"`,
			qname:  "example.com",
			mtaSTS: trace.PolicyInvalid, tlsRPT: trace.PolicyNone, dmarc: trace.PolicyNone,
			dmarcAt: "_dmarc.example.com.", warning: "the policy at _mta-sts.example.com.",
		},
		"a name with no DMARC policy goes by its organisational domain's": {
			extra:  `_dmarc IN TXT "v=DMARC1; p=quarantine"`,
			qname:  "solo.example.com",
			mtaSTS: trace.PolicyNone, tlsRPT: trace.PolicyNone, dmarc: trace.PolicyPublished,
			dmarcAt: "_dmarc.example.com.",
		},
		"a DMARC record with no p that says where reports go reads as p=none": {
			extra:  `_dmarc IN TXT "v=DMARC1; rua=mailto:d@example.com"`,
			qname:  "example.com",
			mtaSTS: trace.PolicyNone, tlsRPT: trace.PolicyNone, dmarc: trace.PolicyPublished,
			dmarcAt: "_dmarc.example.com.",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, cfg := mailed(t, `@ IN MX 10 mx
`+tt.extra, fakens.Behaviour{}, false)

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), tt.qname, "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			m := tr.Mail
			if m == nil || m.MTASTS == nil || m.TLSRPT == nil || m.DMARC == nil {
				t.Fatalf("got %+v, want every policy looked up", m)
			}
			for _, p := range []struct {
				name      string
				got, want trace.PolicyFound
			}{{"mta-sts", m.MTASTS.Found, tt.mtaSTS}, {"tls-rpt", m.TLSRPT.Found, tt.tlsRPT}, {"dmarc", m.DMARC.Found, tt.dmarc}} {
				if p.got != p.want {
					t.Errorf("got %s %s, want %s", p.name, p.got, p.want)
				}
			}
			if m.DMARC.Name != tt.dmarcAt {
				t.Errorf("got DMARC at %s, want %s", m.DMARC.Name, tt.dmarcAt)
			}
			warned := slices.ContainsFunc(tr.Warnings, func(w string) bool { return tt.warning != "" && strings.Contains(w, tt.warning) })
			if tt.warning != "" && !warned {
				t.Errorf("got warnings %q, want one saying %q", tr.Warnings, tt.warning)
			}
		})
	}
}

// TestMailDMARCSubdomain covers a policy found at the organisational domain,
// whose sp is what applies to the name below it (RFC 7489 6.3).
func TestMailDMARCSubdomain(t *testing.T) {
	h, cfg := mailed(t, `_dmarc IN TXT "v=DMARC1; p=reject; sp=none"`, fakens.Behaviour{}, false)

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "solo.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := tr.Mail.DMARCPolicy(); got != "none" {
		t.Errorf("got the policy %q applying to solo.example.com., want its sp, none", got)
	}
}

// TestMailBogusMX covers an MX set that does not validate: a sender that
// validates has no hosts to try, so neither has the check.
func TestMailBogusMX(t *testing.T) {
	h, cfg := mailed(t, ``, fakens.Behaviour{BadSignature: true}, true)

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "mailhost.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.Contains(tr.Mail.Stopped, "does not validate") || len(tr.Mail.Hosts) > 0 {
		t.Errorf("got %+v, want it stopped with no hosts", tr.Mail)
	}
	if !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "holds all mail") }) {
		t.Errorf("got warnings %q, want one saying the mail is held", tr.Warnings)
	}
}

// TestMailBudgetSigned covers every budget a signed check can run out on: the
// run's own budget is never the zone's fault, so no host fails for it and no
// warning blames a server.
func TestMailBudgetSigned(t *testing.T) {
	for budget := 4; budget <= 24; budget++ {
		h, cfg := mailed(t, `@ IN MX 10 mx.mailhost.com.`, fakens.Behaviour{}, true)
		cfg.Budget.MaxQueries = budget

		tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "example.com", "A")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		for _, host := range tr.Mail.Hosts {
			if host.DANE == trace.DANEFailed || host.DANE == "" {
				t.Errorf("with %d queries got %s %q (%s), want no failure the budget made", budget, host.Name, host.DANE, host.Why)
			}
			if strings.Contains(host.Why, "budget") && !tr.Mail.Cut {
				t.Errorf("with %d queries got %s cut short (%s), want the check marked cut", budget, host.Name, host.Why)
			}
		}
		for _, p := range []*trace.MailPolicy{tr.Mail.MTASTS, tr.Mail.TLSRPT, tr.Mail.DMARC} {
			if p != nil && p.Found == trace.PolicyFailed {
				t.Errorf("with %d queries got %s failed (%s), want a policy the budget left unasked left out", budget, p.Name, p.Why)
			}
		}
		for _, warning := range tr.Warnings {
			if strings.Contains(warning, "fix the") || strings.Contains(warning, "unreachable") {
				t.Errorf("with %d queries got the warning %q, want none blaming the zone", budget, warning)
			}
		}
	}
}

// TestMailCNAMEBudget covers the alias budget the walk spent before the check,
// which is no fault of the zone's either.
func TestMailCNAMEBudget(t *testing.T) {
	h, cfg := mailed(t, `@ IN MX 10 mx`, fakens.Behaviour{}, false)
	cfg.Budget.MaxCNAME = 1

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "alias.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.Mail.Stopped == "" {
		t.Errorf("got %+v, want it stopped for the budget", tr.Mail)
	}
	for _, warning := range tr.Warnings {
		if strings.Contains(warning, "fix the servers") {
			t.Errorf("got the warning %q, want none blaming the zone", warning)
		}
	}
}

// TestMailPolicyTags covers what is read out of a policy that is there.
func TestMailPolicyTags(t *testing.T) {
	h, cfg := mailed(t, `_mta-sts IN TXT "v=STSv1; id=20240101T000000"
_dmarc IN TXT "v=DMARC1; P=reject; rua=mailto:d@example.com"`, fakens.Behaviour{}, false)

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := tr.Mail.MTASTS.Tag("id"); got != "20240101T000000" {
		t.Errorf("got the MTA-STS id %q, want 20240101T000000", got)
	}
	if got := tr.Mail.DMARC.Tag("p"); got != "reject" {
		t.Errorf("got the DMARC p %q, want reject", got)
	}
}

// TestMailUnchecked covers a check made without --dnssec, which says nothing
// about whether a sender may rely on a TLSA set it found.
func TestMailUnchecked(t *testing.T) {
	h, cfg := mailed(t, `@ IN MX 10 mx`, fakens.Behaviour{}, false)

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := hostStates(tr.Mail), []string{"mx.example.com. unchecked"}; !slices.Equal(got, want) {
		t.Fatalf("got hosts %q, want %q", got, want)
	}
	if records := tr.Mail.Hosts[0].Records; len(records) != 1 || records[0].Data != tlsaData || !records[0].Usable {
		t.Errorf("got the TLSA records %+v, want the one the zone has", records)
	}
	if dane, _ := tr.Mail.Covered(); dane != 0 {
		t.Errorf("got %d hosts covered, want none claimed without --dnssec", dane)
	}
}

// TestMailBudget covers a check the budget cuts short, which says so rather
// than leaving out what it never asked.
func TestMailBudget(t *testing.T) {
	h, cfg := mailed(t, `@ IN MX 10 mx`, fakens.Behaviour{}, false)
	cfg.Budget.MaxQueries = 5 // the walk takes three

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.Mail == nil || tr.Mail.Stopped == "" {
		t.Fatalf("got %+v, want it stopped for the budget", tr.Mail)
	}
	if !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "ran out of budget") }) {
		t.Errorf("got warnings %q, want one saying the budget ran out", tr.Warnings)
	}
}

// TestMailAll covers --all, which is about the question: the lookups the mail
// check makes ask one server of a zone, as a sender's resolver does.
func TestMailAll(t *testing.T) {
	h, cfg := mailed(t, `@ IN MX 10 mx`, fakens.Behaviour{}, false)
	cfg.All = true

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := hostStates(tr.Mail), []string{"mx.example.com. unchecked"}; !slices.Equal(got, want) {
		t.Errorf("got hosts %q, want %q", got, want)
	}
}

// TestMailNotByDefault covers the cost: nothing is asked unless it is asked for.
func TestMailNotByDefault(t *testing.T) {
	h, cfg := mailed(t, `@ IN MX 10 mx`, fakens.Behaviour{}, false)
	cfg.Mail = false

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.Mail != nil {
		t.Errorf("got %+v, want no mail path", tr.Mail)
	}
	for step := range tr.Steps() {
		if step.Asked.Type == "MX" || step.Asked.Type == "TLSA" {
			t.Errorf("got the %s of %s asked, want nothing more than the walk", step.Asked.Type, step.Asked.Name)
		}
	}
}
