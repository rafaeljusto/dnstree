package jsonout

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// node is as much of a JSON Schema as these tests read.
type node struct {
	Ref        string           `json:"$ref"`
	Type       string           `json:"type"`
	Required   []string         `json:"required"`
	Properties map[string]*node `json:"properties"`
	Enum       []string         `json:"enum"`
	Const      *int             `json:"const"`
	Defs       map[string]*node `json:"$defs"`
}

func schema(tb testing.TB) *node {
	tb.Helper()

	var root node
	if err := json.Unmarshal(schemaDocument, &root); err != nil {
		tb.Fatalf("schema.json is not JSON: %v", err)
	}
	return &root
}

// TestSchemaCoversTheDocument is what lets the schema be written by hand. Every
// field Render can write has to be described, and nothing may be described that
// Render cannot write: a schema that has drifted from the types is worse than
// none, because something reading the output trusts it.
func TestSchemaCoversTheDocument(t *testing.T) {
	root := schema(t)

	described := map[string]map[string]bool{"document": names(root.Properties)}
	for name, def := range root.Defs {
		described[name] = names(def.Properties)
	}

	written := make(map[string]map[string]bool)
	properties(reflect.TypeFor[document](), written)

	for _, name := range slices.Sorted(maps.Keys(written)) {
		fields, ok := described[name]
		if !ok {
			t.Errorf("the document carries a %q and the schema does not describe it", name)
			continue
		}
		for _, field := range slices.Sorted(maps.Keys(written[name])) {
			if !fields[field] {
				t.Errorf("%s.%s is written and the schema does not describe it", name, field)
			}
		}
		for _, field := range slices.Sorted(maps.Keys(fields)) {
			if !written[name][field] {
				t.Errorf("the schema describes %s.%s and nothing writes it", name, field)
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(described)) {
		if _, ok := written[name]; !ok {
			t.Errorf("the schema describes a %q the document does not carry", name)
		}
	}
}

// TestSchemaRefsResolve covers the other way a hand-written schema goes wrong:
// a $ref to a definition that was renamed or never written.
func TestSchemaRefsResolve(t *testing.T) {
	root := schema(t)

	var document any
	if err := json.Unmarshal(schemaDocument, &document); err != nil {
		t.Fatalf("schema.json is not JSON: %v", err)
	}

	for _, ref := range refs(document) {
		name, ok := strings.CutPrefix(ref, "#/$defs/")
		if !ok {
			t.Errorf("got the reference %q, want one into $defs", ref)
			continue
		}
		if _, ok := root.Defs[name]; !ok {
			t.Errorf("got a reference to %q, which the schema does not define", ref)
		}
	}
}

// TestSchemaEnums covers the two sets the schema writes out as closed. The
// kinds of a hop are deliberately not among them: a kind added later is an
// addition, and a schema that called the set closed would turn a document that
// carries a new one into an invalid document.
func TestSchemaEnums(t *testing.T) {
	root := schema(t)

	tests := map[string]struct {
		def, property string
		want          []string
	}{
		"how far the chain of trust got": {
			def: "dnssec", property: "state",
			want: []string{
				string(trace.Secure), string(trace.Insecure),
				string(trace.Bogus), string(trace.Indeterminate),
			},
		},
		"how a resolver's answer stood against the walk's": {
			def: "resolver", property: "match",
			want: []string{string(trace.MatchSame), string(trace.MatchDiffers)},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			def, ok := root.Defs[test.def]
			if !ok {
				t.Fatalf("the schema does not define %q", test.def)
			}
			property, ok := def.Properties[test.property]
			if !ok {
				t.Fatalf("%s does not describe %q", test.def, test.property)
			}
			if !slices.Equal(property.Enum, test.want) {
				t.Errorf("got %v, want %v", property.Enum, test.want)
			}
		})
	}
}

// TestSchemaVersionIsRequired covers the one field something reading the output
// has to be able to count on: without it there is no telling which version of
// the shape is in hand.
func TestSchemaVersionIsRequired(t *testing.T) {
	if root := schema(t); !slices.Contains(root.Required, "schema_version") {
		t.Errorf("got %v, want schema_version among them", root.Required)
	}
}

// TestSchemaVersionIsTheOneWritten ties the schema to the version it describes,
// so that raising SchemaVersion fails here until the schema has been read
// through and brought with it.
func TestSchemaVersionIsTheOneWritten(t *testing.T) {
	version := schema(t).Properties["schema_version"].Const
	if version == nil || *version != SchemaVersion {
		t.Errorf("got %v, want the schema to describe version %d", version, SchemaVersion)
	}
}

// properties records the JSON field names each struct of the document writes,
// under the name the schema knows it by.
func properties(t reflect.Type, found map[string]map[string]bool) {
	t = element(t)
	if t.Kind() != reflect.Struct {
		return
	}

	name := defName(t)
	if _, seen := found[name]; seen {
		return // step holds steps; the walk stops where it comes back round
	}
	fields := make(map[string]bool)
	found[name] = fields

	for field := range t.Fields() {
		tag, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if tag == "" || tag == "-" {
			continue
		}
		fields[tag] = true
		properties(field.Type, found)
	}
}

// element is the type a field comes down to: what a pointer points at, what a
// slice holds, what a map maps to.
func element(t reflect.Type) reflect.Type {
	for {
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			t = t.Elem()
		default:
			return t
		}
	}
}

// defName is the name a type is written under in the schema: its Go name, in
// the snake case the fields themselves are written in.
func defName(t reflect.Type) string {
	var name strings.Builder
	for i, r := range t.Name() {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				name.WriteByte('_')
			}
			r += 'a' - 'A'
		}
		name.WriteRune(r)
	}
	return name.String()
}

// refs is every $ref anywhere in the schema.
func refs(document any) []string {
	var found []string
	switch value := document.(type) {
	case map[string]any:
		for _, key := range slices.Sorted(maps.Keys(value)) {
			if ref, ok := value[key].(string); ok && key == "$ref" {
				found = append(found, ref)
				continue
			}
			found = append(found, refs(value[key])...)
		}
	case []any:
		for _, item := range value {
			found = append(found, refs(item)...)
		}
	}
	return found
}

func names(properties map[string]*node) map[string]bool {
	found := make(map[string]bool, len(properties))
	for name := range properties {
		found[name] = true
	}
	return found
}
