package rdap_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/rdap"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// registry is an RDAP service for test. and a bootstrap file that names it,
// answering each domain from a table; a domain not in it is a 404.
type registry struct {
	server  *httptest.Server
	answers map[string]func(w http.ResponseWriter, r *http.Request)
	asked   atomic.Int32
}

func newRegistry(t *testing.T, answers map[string]func(w http.ResponseWriter, r *http.Request)) *registry {
	t.Helper()
	reg := &registry{answers: answers}
	mux := http.NewServeMux()
	mux.HandleFunc("/dns.json", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"version":"1.0","services":[
			[["test","example"],["http://plain.invalid/","%[1]s/rdap/"]],
			[["co.test"],["%[1]s/rdap"]]]}`, reg.server.URL)
	})
	mux.HandleFunc("/rdap/domain/{name}", func(w http.ResponseWriter, r *http.Request) {
		reg.asked.Add(1)
		answer, ok := reg.answers[r.PathValue("name")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		answer(w, r)
	})
	mux.HandleFunc("/plain", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://plain.invalid/", http.StatusFound)
	})
	reg.server = httptest.NewTLSServer(mux)
	t.Cleanup(reg.server.Close)
	return reg
}

func (r *registry) client() *rdap.Client {
	return rdap.New(r.server.Client(), r.server.URL+"/dns.json", nil)
}

func body(text string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, text)
	}
}

const exampleTest = `{
	"objectClassName": "domain",
	"ldhName": "EXAMPLE.TEST",
	"status": ["client transfer prohibited", "Active"],
	"events": [
		{"eventAction": "registration", "eventDate": "2001-02-03T04:05:06Z"},
		{"eventAction": "expiration", "eventDate": "2026-11-02T00:00:00.000Z"},
		{"eventAction": "last update of RDAP database", "eventDate": "2026-10-06T00:00:00Z"}
	],
	"nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}, {"ldhName": "ns2.example.net."}],
	"secureDNS": {"delegationSigned": true, "dsData": [{"keyTag": 31589}, {"keyTag": "7"}]}
}`

// walk is a trace of name whose walk test. referred to the zone given, with
// the nameservers given, or one NXDOMAIN at test. where the zone is empty.
func walk(name, zone string, ns []string, dnssec *trace.DNSSECStatus) *trace.Trace {
	tld := &trace.Step{Zone: "test.", Kind: trace.KindNXDomain}
	if zone != "" {
		tld = &trace.Step{Zone: "test.", Kind: trace.KindReferral, DNSSEC: dnssec,
			Delegation: &trace.Delegation{Zone: zone, NS: ns, DSPresent: dnssec != nil && dnssec.State == trace.Secure},
			Children:   []*trace.Step{{Zone: zone, Kind: trace.KindAnswer}}}
	}
	return &trace.Trace{
		Question: trace.Question{Name: name, Type: "A", Class: "IN"},
		Started:  time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC),
		Root: &trace.Step{Zone: ".", Kind: trace.KindReferral,
			Delegation: &trace.Delegation{Zone: "test."}, Children: []*trace.Step{tld}},
	}
}

func TestCheck(t *testing.T) {
	secure := &trace.DNSSECStatus{State: trace.Secure, DS: []trace.DS{{Tag: 31589}, {Tag: 7}}}
	tests := map[string]struct {
		answers map[string]func(w http.ResponseWriter, r *http.Request)
		tr      *trace.Trace
		want    trace.Registration
	}{
		"a registration that agrees with the referral": {
			answers: map[string]func(http.ResponseWriter, *http.Request){"example.test": body(exampleTest)},
			tr:      walk("www.example.test.", "example.test.", []string{"ns1.example.net.", "NS2.example.net."}, secure),
			want: trace.Registration{Domain: "example.test.", State: trace.Registered, Parent: "test.",
				Registered: time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC), Expires: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
				Status: []string{"client transfer prohibited", "active"},
				NS:     []string{"ns1.example.net.", "ns2.example.net."}, DS: []uint16{31589, 7}, Signed: true, DSChecked: true},
		},
		"a registry that holds other nameservers and keys": {
			answers: map[string]func(http.ResponseWriter, *http.Request){"example.test": body(exampleTest)},
			tr: walk("example.test.", "example.test.", []string{"ns1.example.net.", "ns3.example.org."},
				&trace.DNSSECStatus{State: trace.Secure, DS: []trace.DS{{Tag: 31589}, {Tag: 9}}}),
			want: trace.Registration{Domain: "example.test.", State: trace.Registered, Parent: "test.",
				Registered: time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC), Expires: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
				Status: []string{"client transfer prohibited", "active"},
				NS:     []string{"ns1.example.net.", "ns2.example.net."}, DS: []uint16{31589, 7}, Signed: true,
				NSOnlyRegistry: []string{"ns2.example.net."}, NSOnlyParent: []string{"ns3.example.org."},
				DSChecked: true, DSOnlyRegistry: []uint16{7}, DSOnlyParent: []uint16{9}},
		},
		"a signed registration under a parent that published no DS": {
			answers: map[string]func(http.ResponseWriter, *http.Request){"example.test": body(exampleTest)},
			tr: walk("example.test.", "example.test.", []string{"ns1.example.net.", "ns2.example.net."},
				&trace.DNSSECStatus{State: trace.Insecure}),
			want: trace.Registration{Domain: "example.test.", State: trace.Registered, Parent: "test.",
				Registered: time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC), Expires: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
				Status: []string{"client transfer prohibited", "active"},
				NS:     []string{"ns1.example.net.", "ns2.example.net."}, DS: []uint16{31589, 7}, Signed: true,
				DSChecked: true, DSDiffer: true},
		},
		"a walk that did not follow the chain compares no DS": {
			answers: map[string]func(http.ResponseWriter, *http.Request){"example.test": body(exampleTest)},
			tr:      walk("example.test.", "example.test.", []string{"ns1.example.net.", "ns2.example.net."}, nil),
			want: trace.Registration{Domain: "example.test.", State: trace.Registered, Parent: "test.",
				Registered: time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC), Expires: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
				Status: []string{"client transfer prohibited", "active"},
				NS:     []string{"ns1.example.net.", "ns2.example.net."}, DS: []uint16{31589, 7}, Signed: true},
		},
		"a name the TLD said does not exist is asked about below it": {
			tr:   walk("www.gone.test.", "", nil, nil),
			want: trace.Registration{Domain: "gone.test.", State: trace.Unregistered, Why: "the registry holds no registration for gone.test."},
		},
		"a name the TLD said does not exist, and the registry holds": {
			answers: map[string]func(http.ResponseWriter, *http.Request){"held.test": body(`{"status":["serverHold"]}`)},
			tr:      walk("held.test.", "", nil, nil),
			want:    trace.Registration{Domain: "held.test.", State: trace.Registered, Status: []string{"server hold"}},
		},
		"a cut that is nobody's registration is looked below": {
			answers: map[string]func(http.ResponseWriter, *http.Request){"example.co.test": body(`{"status":["active"]}`)},
			tr:      walk("www.example.co.test.", "co.test.", []string{"ns.co.test."}, nil),
			want:    trace.Registration{Domain: "example.co.test.", State: trace.Registered, Status: []string{"active"}},
		},
		"a TLD with no service": {
			tr:   walk("www.example.nowhere.", "", nil, nil),
			want: trace.Registration{Domain: "example.nowhere.", State: trace.Unpublished, Why: "the registry of nowhere. publishes no rdap service"},
		},
		"a top-level domain": {
			tr:   walk("test.", "", nil, nil),
			want: trace.Registration{Domain: "test.", State: trace.Unpublished, Why: "a top-level domain is nobody's registration"},
		},
		"a registry that fails": {
			answers: map[string]func(http.ResponseWriter, *http.Request){"example.test": func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "down", http.StatusServiceUnavailable)
			}},
			tr:   walk("example.test.", "example.test.", nil, nil),
			want: trace.Registration{Domain: "example.test.", State: trace.Unreached},
		},
		"a registry that redirects off https": {
			answers: map[string]func(http.ResponseWriter, *http.Request){"example.test": func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://example.invalid/domain/example.test", http.StatusFound)
			}},
			tr:   walk("example.test.", "example.test.", nil, nil),
			want: trace.Registration{Domain: "example.test.", State: trace.Unreached},
		},
		"a registry that answers without end": {
			answers: map[string]func(http.ResponseWriter, *http.Request){"example.test": body(`{"status":["` + strings.Repeat("a", 2<<20) + `"]}`)},
			tr:      walk("example.test.", "example.test.", nil, nil),
			want:    trace.Registration{Domain: "example.test.", State: trace.Unreached},
		},
		"a registry that answers with something else": {
			answers: map[string]func(http.ResponseWriter, *http.Request){"example.test": body(`<html>`)},
			tr:      walk("example.test.", "example.test.", nil, nil),
			want:    trace.Registration{Domain: "example.test.", State: trace.Unreached},
		},
		"a name no registry holds": {
			tr:   walk("www.ex_ample.test.", "ex_ample.test.", nil, nil),
			want: trace.Registration{Domain: "ex_ample.test.", State: trace.Unregistered, Why: "no registry holds a name written like this one"},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			reg := newRegistry(t, test.answers)
			got := reg.client().Check(t.Context(), test.tr)
			if got == nil {
				t.Fatal("got nothing")
			}
			if got.Why != "" && test.want.State == trace.Unreached {
				test.want.Why = got.Why // what failed is said by net/http
			}
			got.Server = ""
			if !same(*got, test.want) {
				t.Errorf("got\n%+v\nwant\n%+v", *got, test.want)
			}
		})
	}
}

func same(a, b trace.Registration) bool {
	return a.Domain == b.Domain && a.State == b.State && a.Why == b.Why && a.Parent == b.Parent &&
		a.Registered.Equal(b.Registered) && a.Expires.Equal(b.Expires) && a.Signed == b.Signed &&
		slices.Equal(a.Status, b.Status) && slices.Equal(a.NS, b.NS) && slices.Equal(a.DS, b.DS) &&
		slices.Equal(a.NSOnlyRegistry, b.NSOnlyRegistry) && slices.Equal(a.NSOnlyParent, b.NSOnlyParent) &&
		a.DSChecked == b.DSChecked && a.DSDiffer == b.DSDiffer &&
		slices.Equal(a.DSOnlyRegistry, b.DSOnlyRegistry) && slices.Equal(a.DSOnlyParent, b.DSOnlyParent)
}

// TestCheckSaysWhatFailed covers the two ways the lookup comes back empty,
// which have to read differently: one is worth fixing, the other waiting for.
func TestCheckSaysWhatFailed(t *testing.T) {
	t.Run("a registry that does not answer in time", func(t *testing.T) {
		stop := make(chan struct{})
		defer close(stop)
		reg := newRegistry(t, map[string]func(http.ResponseWriter, *http.Request){
			"example.test": func(http.ResponseWriter, *http.Request) { <-stop },
		})
		client := reg.client()
		<-client.Prepare(t.Context())

		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		got := client.Check(ctx, walk("example.test.", "example.test.", nil, nil))
		if got.State != trace.Unreached || got.Why != "the registry did not answer in time" {
			t.Errorf("got %s: %q", got.State, got.Why)
		}
	})

	t.Run("a bootstrap file nobody serves", func(t *testing.T) {
		server := httptest.NewTLSServer(http.NotFoundHandler())
		defer server.Close()
		got := rdap.New(server.Client(), server.URL+"/dns.json", nil).Check(t.Context(), walk("example.test.", "example.test.", nil, nil))
		if got.State != trace.Unreached || got.Why != "could not read iana's rdap bootstrap file: it is not there" {
			t.Errorf("got %s: %q", got.State, got.Why)
		}
	})
}

// TestCheckAsksOnce covers --watch and a file of names: the registry is asked
// about a domain once, however many walks reach it.
func TestCheckAsksOnce(t *testing.T) {
	reg := newRegistry(t, map[string]func(http.ResponseWriter, *http.Request){"example.test": body(exampleTest)})
	client := reg.client()
	for range 3 {
		got := client.Check(t.Context(), walk("www.example.test.", "example.test.", []string{"ns1.example.net."}, nil))
		if got.State != trace.Registered || !slices.Equal(got.NSOnlyRegistry, []string{"ns2.example.net."}) {
			t.Fatalf("got %+v", got)
		}
	}
	if asked := reg.asked.Load(); asked != 1 {
		t.Errorf("the registry was asked %d times, want 1", asked)
	}
}
