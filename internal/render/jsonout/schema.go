package jsonout

import (
	_ "embed"
	"io"
)

// schemaDocument is the JSON Schema of what [Render] writes. It is written by
// hand rather than reflected out of the types, because what a reader needs from
// it is the prose: which fields are absent in the ordinary case, and what a
// value means. A test holds it against the types, so the prose cannot outlive
// the fields it describes.
//
//go:embed schema.json
var schemaDocument []byte

// WriteSchema writes the JSON Schema of the document [Render] writes. It is
// what --schema prints, so that something reading the output can be held
// against the shape of it without reading this package first.
func WriteSchema(w io.Writer) error {
	_, err := w.Write(schemaDocument)
	return err
}
