package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// File writes the flat page and the walk as one HTML document, to be opened
// from the disk with no dnstree and no network. A browser lets a page opened
// that way fetch nothing, so everything it needs is inside it: the stylesheet,
// the walk, and the modules, with walk.js reached through an import map.
func File(w io.Writer, tr *trace.Trace, findings []explain.Finding, opts Options) error {
	page, _, err := build(tr, findings, opts)
	if err != nil {
		return err
	}
	document, err := inline(page)
	if err != nil {
		return err
	}
	_, err = w.Write(document)
	return err
}

// The tags of the served page that File puts something else in place of.
const (
	stylesheetTag = `<link rel="stylesheet" href="app.css">`
	iconsTag      = `<link rel="icon" href="favicon.ico" sizes="32x32">
<link rel="icon" href="mark.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="apple-touch-icon.png">`
	moduleTag = `<script type="module" src="app.js"></script>`
)

func inline(page []byte) ([]byte, error) {
	read := func(name string) []byte {
		body, err := assets.ReadFile("assets/" + name)
		if err != nil {
			panic("web: " + name + " is missing from the binary: " + err.Error())
		}
		return body
	}

	// The walk is text DNS servers wrote, and a </script> in it would end the
	// block. json.Marshal escapes <, > and & already; this keeps it so if the
	// payload is ever built another way.
	var carried bytes.Buffer
	json.HTMLEscape(&carried, page)

	imports, err := json.Marshal(map[string]map[string]string{"imports": {
		"./walk.js": "data:text/javascript;base64," + base64.StdEncoding.EncodeToString(read("walk.js")),
	}})
	if err != nil {
		return nil, fmt.Errorf("web: the page cannot be written: %w", err)
	}

	icon := `<link rel="icon" href="data:image/svg+xml;base64,` + base64.StdEncoding.EncodeToString(read("mark.svg")) + `">`
	scripts := "<script type=\"application/json\" id=\"walk\">" + carried.String() + "</script>\n" +
		"<script type=\"importmap\">" + string(imports) + "</script>\n" +
		"<script type=\"module\">\n" + string(read("app.js")) + "</script>"

	document := read("index.html")
	for _, swap := range []struct{ tag, with string }{
		{stylesheetTag, "<style>\n" + string(read("app.css")) + "</style>"},
		{iconsTag, icon},
		{moduleTag, scripts},
	} {
		if bytes.Count(document, []byte(swap.tag)) != 1 {
			return nil, fmt.Errorf("web: the page no longer holds %q once", swap.tag)
		}
		document = bytes.Replace(document, []byte(swap.tag), []byte(swap.with), 1)
	}
	return document, nil
}
