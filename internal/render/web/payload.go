package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/render/jsonout"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// payload is everything the page reads. The walk itself is carried verbatim as
// the document --format json writes, rather than written out a second way:
// there is one description of what a trace is, and the page draws that.
type payload struct {
	Page     pageInfo        `json:"page"`
	Trace    json.RawMessage `json:"trace"`
	Findings []finding       `json:"findings,omitempty"`
}

// pageInfo is what the page says about itself, which is what made it and when.
// A page kept open while the name moves under it is worth telling apart from
// one just walked.
type pageInfo struct {
	Version   string `json:"version"`
	Generated string `json:"generated"`
}

// finding is one sentence --explain or --diff came to. The topic and the level
// are named rather than numbered, so the page can group and colour them
// without carrying the order the Go constants happen to have.
type finding struct {
	Topic string `json:"topic"`
	Level string `json:"level"`
	Text  string `json:"text"`
}

// build is the payload for one finished walk, and the trace document inside it.
// The two are returned apart because the page reads the first and a script
// pointed at the same server wants the second on its own.
func build(tr *trace.Trace, findings []explain.Finding, opts Options) (page, traceDoc []byte, err error) {
	var document bytes.Buffer
	if err := jsonout.Render(&document, tr); err != nil {
		return nil, nil, fmt.Errorf("web: the trace cannot be written: %w", err)
	}

	// A walk drawn again from a file is dated by when it was made.
	when := opts.Now
	if tr != nil && !tr.Started.IsZero() {
		when = tr.Started
	}
	if when.IsZero() {
		when = time.Now()
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}

	// The encoder ends its document with a newline, which has no business in
	// the middle of another one.
	traceDoc = bytes.TrimRight(document.Bytes(), "\n")

	body := payload{
		Page:  pageInfo{Version: version, Generated: when.Format(time.RFC3339)},
		Trace: traceDoc,
	}
	for _, found := range findings {
		body.Findings = append(body.Findings, finding{
			Topic: found.Topic.String(),
			Level: found.Level.String(),
			Text:  found.Text,
		})
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, nil, fmt.Errorf("web: the page cannot be written: %w", err)
	}
	return encoded, traceDoc, nil
}
