package jsonout_test

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/render/jsonout"
)

// publishedPath is the copy of the schema the pages workflow serves. That
// workflow uploads what is committed and builds nothing, so the schema has to
// be in the tree rather than rendered at deploy time, and a copy in the tree is
// a copy that can go stale.
const publishedPath = "../../../docs/trace.schema.json"

// TestPublishedSchema keeps the served copy and the printed one the same. The
// $id says the schema can be fetched from the page, which is only true while
// what is up there is what the binary writes.
func TestPublishedSchema(t *testing.T) {
	var printed bytes.Buffer
	if err := jsonout.WriteSchema(&printed); err != nil {
		t.Fatalf("WriteSchema: %v", err)
	}

	if *update {
		if err := os.WriteFile(publishedPath, printed.Bytes(), 0o644); err != nil {
			t.Fatalf("writing %s: %v", publishedPath, err)
		}
		return
	}

	published, err := os.ReadFile(publishedPath)
	if err != nil {
		t.Fatalf("%v (run make goldens to write it)", err)
	}
	if !bytes.Equal(published, printed.Bytes()) {
		t.Errorf("%s is not the schema --schema prints, run make goldens",
			publishedPath)
	}
}

// TestPublishedSchemaID covers the half of the $id that can be checked without
// reaching the network: that it names the file the page actually serves. The
// address itself moves only when the site does, and nothing offline can know
// that the site has moved.
func TestPublishedSchemaID(t *testing.T) {
	var printed bytes.Buffer
	if err := jsonout.WriteSchema(&printed); err != nil {
		t.Fatalf("WriteSchema: %v", err)
	}

	var document struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(printed.Bytes(), &document); err != nil {
		t.Fatalf("the schema is not JSON: %v", err)
	}

	id, err := url.Parse(document.ID)
	if err != nil || id.Scheme != "https" || id.Host == "" {
		t.Fatalf("got the id %q, want an absolute https address", document.ID)
	}
	if got, want := path.Base(id.Path), filepath.Base(publishedPath); got != want {
		t.Errorf("the id ends in %q and the page serves %q", got, want)
	}
}
