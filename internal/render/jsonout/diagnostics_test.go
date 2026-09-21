package jsonout_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/internal/trace"
)

// render encodes a trace and reads it back as plain maps, which is how anything
// consuming this output sees it.
func render(t *testing.T, tr *trace.Trace) map[string]any {
	t.Helper()

	var out bytes.Buffer
	if err := jsonout.Render(&out, tr); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return document
}

func TestRenderDiagnostics(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "svc.test.", Type: "HTTPS", Class: "IN"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone:  "test.",
			Kind:  trace.KindAnswer,
			Rcode: "NOERROR",
			Extended: []trace.ExtendedError{
				{Code: 15, Reason: "Blocked", Text: "on the list"},
				{Code: 3, Reason: "Stale Answer"},
			},
			Subnet: &trace.Subnet{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Scope: 24},
			Records: []trace.RR{{
				Name: "svc.test.", TTL: 300, Type: "HTTPS",
				Data:    `1 . alpn="h2,h3" ech="AEX+DQBBAAA="`,
				Service: &trace.Service{Priority: 1, ALPN: []string{"h2", "h3"}, ECH: true},
			}},
		}}},
	}

	document := render(t, tr)
	if version, _ := document["schema_version"].(float64); int(version) != jsonout.SchemaVersion {
		t.Fatalf("got schema_version %v, want %d", document["schema_version"], jsonout.SchemaVersion)
	}

	root, _ := document["root"].(map[string]any)
	children, _ := root["children"].([]any)
	if len(children) != 1 {
		t.Fatalf("got %d children, want the one hop", len(children))
	}
	step, _ := children[0].(map[string]any)

	extended, _ := step["extended"].([]any)
	if len(extended) != 2 {
		t.Fatalf("got %d extended errors, want 2", len(extended))
	}

	// withheld saves every reader from carrying the list of which codes mean
	// somebody decided the answer.
	blocked, _ := extended[0].(map[string]any)
	if blocked["code"].(float64) != 15 || blocked["reason"] != "Blocked" || blocked["text"] != "on the list" {
		t.Errorf("got %+v, want blocked with its text", blocked)
	}
	if blocked["withheld"] != true {
		t.Errorf("got %+v, want it marked withheld", blocked)
	}
	stale, _ := extended[1].(map[string]any)
	if _, ok := stale["withheld"]; ok {
		t.Errorf("got %+v, want no withheld flag on a stale answer", stale)
	}

	subnet, _ := step["subnet"].(map[string]any)
	if subnet["prefix"] != "203.0.113.0/24" || subnet["scope"].(float64) != 24 {
		t.Errorf("got %+v, want the echoed subnet and its scope", subnet)
	}

	records, _ := step["records"].([]any)
	record, _ := records[0].(map[string]any)
	service, _ := record["service"].(map[string]any)
	if service == nil {
		t.Fatalf("got %+v, want the service parameters decoded", record)
	}
	if service["ech"] != true || service["priority"].(float64) != 1 {
		t.Errorf("got %+v, want priority 1 publishing ECH", service)
	}
	if alpn, _ := service["alpn"].([]any); len(alpn) != 2 {
		t.Errorf("got %+v, want both protocols", service["alpn"])
	}
}

func TestRenderResolverComparison(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A", Class: "IN"},
		Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
		Resolver: &trace.Resolver{
			Server:  trace.Server{IP: netip.MustParseAddr("192.168.1.1"), Port: 53},
			Rcode:   "NOERROR",
			Records: []trace.RR{{Name: "www.test.", TTL: 60, Type: "A", Data: "10.4.2.9"}},
			Match:   trace.MatchDiffers,
		},
	}

	resolver, _ := render(t, tr)["resolver"].(map[string]any)
	if resolver["match"] != "differs" {
		t.Errorf("got %+v, want the comparison carried", resolver["match"])
	}
	records, _ := resolver["records"].([]any)
	if len(records) != 1 {
		t.Fatalf("got %d records, want what the resolver answered", len(records))
	}
	if record, _ := records[0].(map[string]any); record["data"] != "10.4.2.9" {
		t.Errorf("got %+v, want the resolver's own answer", record)
	}
}

// TestRenderCarriesTheDenialLifetime covers the one thing a denial has in place
// of records: an answer says how long it may be cached on the records
// themselves, and a name that is not there has none to say it on.
func TestRenderCarriesTheDenialLifetime(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A", Class: "IN"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: "test.", Kind: trace.KindNXDomain, Rcode: "NXDOMAIN",
			SOA: &trace.SOA{Serial: 2024061201, TTL: 3600, Minimum: 900},
		}}},
	}

	root, _ := render(t, tr)["root"].(map[string]any)
	children, _ := root["children"].([]any)
	step, _ := children[0].(map[string]any)

	soa, ok := step["soa"].(map[string]any)
	if !ok {
		t.Fatalf("got %+v, want the SOA the denial came with", step)
	}
	if soa["ttl"] != float64(3600) || soa["minimum"] != float64(900) {
		t.Errorf("got %+v, want both fields the zone can say a lifetime with", soa)
	}
	if soa["serial"] != float64(2024061201) {
		t.Errorf("got %+v, want the copy of the zone the denial came out of", soa)
	}
}

// TestRenderOmitsWhatIsNotThere guards the schema against growing noise: an
// ordinary walk asks for none of this and its output must not carry the keys.
func TestRenderOmitsWhatIsNotThere(t *testing.T) {
	tr := &trace.Trace{
		Question: trace.Question{Name: "www.test.", Type: "A", Class: "IN"},
		Root: &trace.Step{Zone: ".", Kind: trace.KindZone, Children: []*trace.Step{{
			Zone: "test.", Kind: trace.KindAnswer, Rcode: "NOERROR",
			Records: []trace.RR{{Name: "www.test.", TTL: 300, Type: "A", Data: "192.0.2.10"}},
		}}},
	}

	root, _ := render(t, tr)["root"].(map[string]any)
	children, _ := root["children"].([]any)
	step, _ := children[0].(map[string]any)

	for _, key := range []string{"extended", "subnet", "soa", "nsid"} {
		if _, ok := step[key]; ok {
			t.Errorf("got %q on a hop that has none", key)
		}
	}
	records, _ := step["records"].([]any)
	record, _ := records[0].(map[string]any)
	if _, ok := record["service"]; ok {
		t.Error("got service parameters on an A record")
	}
}
