package resolver_test

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/resolver"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// caaZone is example.com. with whatever CAA a case gives it appended.
const caaZone = `
@        IN SOA   ns hostmaster 1 7200 3600 1209600 3600
@        IN NS    ns
ns       IN A     192.0.2.3
www      IN A     192.0.2.10
shop.eu  IN A     192.0.2.11
alias    IN CNAME www
`

// authorised builds root, com. and example.com., the last serving caaZone and
// extra, all signed or none of them. example.com. signs its gaps without
// opt-out, as a zone with no delegations of its own does, since the climb
// asks of an empty non-terminal.
func authorised(tb testing.TB, extra string, behaviour fakens.Behaviour, signed bool) (harness, resolver.Config) {
	tb.Helper()

	hierarchy := fakens.NewHierarchy(tb)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: signed,
	})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2", DNSSEC: signed})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: caaZone + extra, Declared: "192.0.2.3",
		DNSSEC: signed, Denial: fakens.DenialNSEC3, Behaviour: behaviour,
	})

	h := harness{hierarchy, root}
	cfg := resolver.Config{CAA: true}
	if signed {
		cfg.DNSSEC, cfg.Anchors = true, root.Anchors(tb)
	}
	return h, cfg
}

// climbed is the climb as names and what each came to.
func climbed(caa *trace.CAA) []string {
	var asked []string
	for _, lookup := range caa.Asked {
		text := lookup.Name + " " + string(lookup.Found)
		if lookup.Alias != "" {
			text += " at " + lookup.Alias
		}
		asked = append(asked, text)
	}
	return asked
}

func TestCAA(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		extra     string
		behaviour fakens.Behaviour
		qname     string

		asked     []string
		owner     string
		issue     []string // nil when any authority may
		wildcard  []string
		refused   bool
		undecided bool
	}{
		"a set at the name decides it": {
			extra: `www IN CAA 0 issue "letsencrypt.org"`,
			qname: "www.example.com",
			asked: []string{"www.example.com. set"}, owner: "www.example.com.",
			issue: []string{"letsencrypt.org"}, wildcard: []string{"letsencrypt.org"},
		},
		"a set two labels up decides once the climb gets there": {
			extra: `@ IN CAA 0 issue "letsencrypt.org; validationmethods=dns-01"
@ IN CAA 0 issuewild ";"
@ IN CAA 0 iodef "mailto:security@example.com"`,
			qname: "shop.eu.example.com",
			asked: []string{"shop.eu.example.com. none", "eu.example.com. none", "example.com. set"},
			owner: "example.com.", issue: []string{"letsencrypt.org"}, wildcard: []string{},
		},
		"no set anywhere leaves it to any authority": {
			qname: "www.example.com",
			asked: []string{"www.example.com. none", "example.com. none", "com. none"},
		},
		"an alias is looked up at its target": {
			extra: `www IN CAA 0 issue "digicert.com"`,
			qname: "alias.example.com",
			asked: []string{"alias.example.com. set at www.example.com."}, owner: "alias.example.com.",
			issue: []string{"digicert.com"}, wildcard: []string{"digicert.com"},
		},
		"the climb goes on from an alias, not from its target": {
			extra: `@ IN CAA 0 issue "letsencrypt.org"`,
			qname: "alias.example.com",
			asked: []string{"alias.example.com. none at www.example.com.", "example.com. set"}, owner: "example.com.",
			issue: []string{"letsencrypt.org"}, wildcard: []string{"letsencrypt.org"},
		},
		"a set with no issue property restricts nobody": {
			extra: `www IN CAA 0 iodef "mailto:security@example.com"`,
			qname: "www.example.com",
			asked: []string{"www.example.com. set"}, owner: "www.example.com.",
		},
		"an issue naming no domain lets nobody issue": {
			extra: `www IN CAA 0 issue ";"`,
			qname: "www.example.com",
			asked: []string{"www.example.com. set"}, owner: "www.example.com.",
			issue: []string{}, wildcard: []string{},
		},
		"a critical property nobody knows makes every authority refuse": {
			extra: `www IN CAA 0 issue "letsencrypt.org"
www IN CAA 128 tbs "unknown"`,
			qname: "www.example.com",
			asked: []string{"www.example.com. set"}, owner: "www.example.com.",
			issue: []string{"letsencrypt.org"}, wildcard: []string{"letsencrypt.org"}, refused: true,
		},
		"a critical property whose tag is no valid one makes every authority refuse": {
			extra: `www IN CAA 0 issue "letsencrypt.org"
www IN CAA 128 tbs\; "unknown"`,
			qname: "www.example.com",
			asked: []string{"www.example.com. set"}, owner: "www.example.com.",
			issue: []string{"letsencrypt.org"}, wildcard: []string{"letsencrypt.org"}, refused: true,
		},
		"a server that fails the lookup in an unsigned zone leaves it undecided": {
			extra:     `@ IN CAA 0 issue "letsencrypt.org"`,
			behaviour: fakens.Behaviour{ServFailType: dns.TypeCAA},
			qname:     "www.example.com",
			asked:     []string{"www.example.com. failed"}, undecided: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, cfg := authorised(t, tt.extra, tt.behaviour, false)

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), tt.qname, "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if tr.Result() == nil {
				t.Fatalf("got no answer: %s", format(steps(tr)))
			}
			caa := tr.CAA
			if caa == nil {
				t.Fatal("got no CAA, want the climb")
			}

			if got := climbed(caa); !slices.Equal(got, tt.asked) {
				t.Errorf("got the climb %q, want %q", got, tt.asked)
			}
			if caa.Owner != tt.owner {
				t.Errorf("got %q deciding, want %q", caa.Owner, tt.owner)
			}
			checkIssuers(t, "issue", caa.Issue, tt.issue)
			checkIssuers(t, "issuewild", caa.Wildcard, tt.wildcard)
			if refused := caa.Refused != ""; refused != tt.refused {
				t.Errorf("got refused %q, want refused %v", caa.Refused, tt.refused)
			}
			if undecided := caa.Undecided != ""; undecided != tt.undecided {
				t.Errorf("got undecided %q, want undecided %v", caa.Undecided, tt.undecided)
			}
			if (tt.refused || tt.undecided) && len(tr.Warnings) == 0 {
				t.Error("got no warning, want one saying why an authority refuses")
			}

			for step := range tr.Mainline() {
				if step.Asked.Type == "CAA" {
					t.Errorf("got the CAA of %s on the walk itself, want it drawn as an aside", step.Asked.Name)
				}
			}
			if result := tr.Result(); result.Asked.Type != "A" {
				t.Errorf("got the result asking %s, want the walk's own answer", result.Asked.Type)
			}
		})
	}
}

func checkIssuers(tb testing.TB, what string, got *trace.Issuers, want []string) {
	tb.Helper()
	switch {
	case want == nil && got != nil:
		tb.Errorf("got %s restricted to %q, want any authority", what, got.CAs)
	case want != nil && got == nil:
		tb.Errorf("got %s open to any authority, want %q", what, want)
	case want != nil && !slices.Equal(got.CAs, want):
		tb.Errorf("got %s %q, want %q", what, got.CAs, want)
	}
}

// TestCAADNSSEC covers the verdict on the climb: an empty answer on the way up
// counts only once its denial is proved, and every answer is checked against
// the keys of the zone it came from, even after the walk went below it.
func TestCAADNSSEC(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		extra     string
		behaviour fakens.Behaviour
		qname     string
		want      trace.DNSSECState
	}{
		"a signed set reached by proving the names below it empty": {
			qname: "shop.eu.example.com", want: trace.Secure,
		},
		"a signed set the codec alone would put out of order": {
			extra: `@ IN CAA 0 issue "pki.goog"
@ IN CAA 0 issue "certainly.com"`,
			qname: "www.example.com", want: trace.Secure,
		},
		"a zone whose signatures do not verify": {
			behaviour: fakens.Behaviour{BadSignature: true},
			qname:     "www.example.com", want: trace.Bogus,
		},
	} {
		t.Run(name, func(t *testing.T) {
			extra := cmp.Or(tt.extra, `@ IN CAA 0 issue "letsencrypt.org"`)
			h, cfg := authorised(t, extra, tt.behaviour, true)

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), tt.qname, "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if tr.CAA == nil || tr.CAA.DNSSEC == nil {
				t.Fatalf("got %+v, want a verdict over the climb", tr.CAA)
			}
			if got := tr.CAA.DNSSEC.State; got != tt.want {
				t.Errorf("got %s (%s), want %s", got, tr.CAA.DNSSEC.Reason, tt.want)
			}
			for _, lookup := range tr.CAA.Asked {
				if lookup.Found == trace.CAAFailed {
					t.Errorf("got %s failed: %s", lookup.Name, lookup.Err)
				}
			}
		})
	}
}

// TestCAAFailedSigned covers a lookup that fails in a zone with a chain of trust
// behind it, which no authority may take as leave to issue.
func TestCAAFailedSigned(t *testing.T) {
	t.Parallel()

	h, cfg := authorised(t, `@ IN CAA 0 issue "letsencrypt.org"`, fakens.Behaviour{ServFailType: dns.TypeCAA}, true)

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.CAA == nil || tr.CAA.Refused == "" || tr.CAA.Undecided != "" {
		t.Fatalf("got %+v, want every authority refusing", tr.CAA)
	}
	if !slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "every authority has to refuse") }) {
		t.Errorf("got warnings %q, want one saying every authority refuses", tr.Warnings)
	}
}

// TestCAABudget covers a climb cut short: the budget is the run's, not an
// authority's, so the lookup it stops leaves who may issue undecided.
func TestCAABudget(t *testing.T) {
	t.Parallel()

	h, cfg := authorised(t, `@ IN CAA 0 issue "letsencrypt.org"`, fakens.Behaviour{}, false)
	cfg.Budget.MaxQueries = 4 // the walk takes three

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := []string{"www.example.com. none", "example.com. failed"}
	if got := climbed(tr.CAA); !slices.Equal(got, want) {
		t.Fatalf("got the climb %q, want %q", got, want)
	}
	if tr.CAA.Refused != "" || !strings.Contains(tr.CAA.Undecided, "gave up after 4 queries") {
		t.Errorf("got refused %q and undecided %q, want it undecided for the budget", tr.CAA.Refused, tr.CAA.Undecided)
	}
}

// TestCAABudgetSpentBefore covers a budget the walk ran out before the climb:
// the CNAME chain used it up, so it cannot be why a later lookup failed.
func TestCAABudgetSpentBefore(t *testing.T) {
	t.Parallel()

	var chain strings.Builder
	for i := range resolver.DefaultMaxCNAME + 2 {
		fmt.Fprintf(&chain, "c%d IN CNAME c%d\n", i, i+1)
	}
	h, cfg := authorised(t, chain.String(), fakens.Behaviour{ServFailType: dns.TypeCAA}, true)

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "c0.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.CAA == nil || tr.CAA.Refused == "" || tr.CAA.Undecided != "" {
		t.Errorf("got %+v, want the signed zone's failure making every authority refuse", tr.CAA)
	}
}

// TestCAAUnenteredZone covers a climb referred below every zone the walk
// entered: the chain of the zone that referred says nothing of the child's,
// so an unsigned child that never answered leaves it undecided.
func TestCAAUnenteredZone(t *testing.T) {
	t.Parallel()

	hierarchy := fakens.NewHierarchy(t)
	root := hierarchy.Add(fakens.Config{
		Name: "a.root-servers.net.", Origin: ".", Zone: rootZone, Declared: "192.0.2.1", DNSSEC: true,
	})
	hierarchy.Add(fakens.Config{Name: "ns.com.", Origin: "com.", Zone: comZone, Declared: "192.0.2.2", DNSSEC: true})
	hierarchy.Add(fakens.Config{
		Name: "ns.example.com.", Origin: "example.com.", Zone: caaZone, Declared: "192.0.2.3",
		Behaviour: fakens.Behaviour{Drop: true},
	})
	cfg := resolver.Config{CAA: true, DNSSEC: true, Anchors: root.Anchors(t)}

	tr, err := newResolver(t, harness{hierarchy, root}, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.CAA == nil || tr.CAA.Refused != "" || tr.CAA.Undecided == "" {
		t.Fatalf("got %+v, want it undecided", tr.CAA)
	}
	if slices.ContainsFunc(tr.Warnings, func(w string) bool { return strings.Contains(w, "servers of com.") }) {
		t.Errorf("got warnings %q, want none blaming com.", tr.Warnings)
	}
}

// TestCAANotByDefault covers the cost: nothing is asked unless it is asked for.
func TestCAANotByDefault(t *testing.T) {
	t.Parallel()

	h, cfg := authorised(t, `@ IN CAA 0 issue "letsencrypt.org"`, fakens.Behaviour{}, false)
	cfg.CAA = false

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if tr.CAA != nil {
		t.Errorf("got %+v, want no CAA", tr.CAA)
	}
	for step := range tr.Steps() {
		if step.Asked.Type == "CAA" {
			t.Errorf("got a CAA query of %s, want none", step.Server.Name)
		}
	}
}

// TestCAAHiddenCut covers a climb through zones no referral pointed at. The
// server of com. serves hosted.com. too, so its answers are signed with keys
// the walk only learns by crossing the cut, and checked against com.'s they
// would all come out bogus.
func TestCAAHiddenCut(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		hosted string
		qname  string
		asked  []string
	}{
		"an answer across the cut": {
			hosted: hostedZone + `@ IN CAA 0 issue "letsencrypt.org"`,
			qname:  "www.hosted.com",
			asked:  []string{"www.hosted.com. none", "hosted.com. set"},
		},
		"a referral across the cut": {
			hosted: delegatingZone + `@ IN CAA 0 issue "letsencrypt.org"`,
			qname:  "www.sub.hosted.com",
			asked:  []string{"www.sub.hosted.com. none", "sub.hosted.com. none", "hosted.com. set"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, cfg := signed(t, fakens.Behaviour{}, fakens.Behaviour{}, fakens.Behaviour{})
			h.hierarchy.Add(fakens.Config{
				Name: "ns.com.", Origin: "hosted.com.", Zone: tt.hosted, Declared: "192.0.2.2", DNSSEC: true,
			})
			h.hierarchy.Add(fakens.Config{
				Name: "ns.sub.hosted.com.", Origin: "sub.hosted.com.", Zone: subZone, Declared: "192.0.2.4", DNSSEC: true,
			})
			cfg.CAA = true

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), tt.qname, "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got := climbed(tr.CAA); !slices.Equal(got, tt.asked) {
				t.Fatalf("got the climb %q, want %q", got, tt.asked)
			}
			if status := tr.CAA.DNSSEC; status == nil || status.State != trace.Secure {
				t.Errorf("got %+v, want the climb secure", status)
			}
		})
	}
}

// TestCAAValueRoundTrip covers the value read back from the text the walk
// keeps of the record: it stays escaped, the way the codec hands text rdata
// over, neither unescaped nor escaped twice, and the authority is read from
// before the parameters.
func TestCAAValueRoundTrip(t *testing.T) {
	t.Parallel()

	h, cfg := authorised(t, `www IN CAA 0 issue "LetsEncrypt.org; accounturi=https://x/\"q\"\\\200"`, fakens.Behaviour{}, false)

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(tr.CAA.Records) != 1 {
		t.Fatalf("got %+v, want the one property", tr.CAA.Records)
	}
	if got, want := tr.CAA.Records[0].Value, `LetsEncrypt.org; accounturi=https://x/\"q\"\\\200`; got != want {
		t.Errorf("got value %q, want %q", got, want)
	}
	checkIssuers(t, "issue", tr.CAA.Issue, []string{"letsencrypt.org"})
}
