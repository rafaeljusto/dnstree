// Package jsonout renders a trace as versioned JSON.
package jsonout

import (
	"encoding/json"
	"io"
	"math"
	"time"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// SchemaVersion changes whenever a field changes meaning or goes away, so that
// something reading this output can tell whether it still understands it.
const SchemaVersion = 1

// Render writes the trace to w as JSON.
func Render(w io.Writer, tr *trace.Trace) error {
	document := document{SchemaVersion: SchemaVersion}
	if tr != nil {
		document.Question = question{Name: tr.Question.Name, Type: tr.Question.Type, Class: tr.Question.Class}
		document.ElapsedMS = milliseconds(tr.Elapsed)
		document.Resolver = convertResolver(tr.Resolver)
		document.Root = convert(tr.Root)
		document.Warnings = tr.Warnings
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

type document struct {
	SchemaVersion int       `json:"schema_version"`
	Question      question  `json:"question"`
	ElapsedMS     float64   `json:"elapsed_ms"`
	Resolver      *resolver `json:"resolver,omitempty"`
	Root          *step     `json:"root,omitempty"`
	Warnings      []string  `json:"warnings,omitempty"`
}

// resolver is the same question put to a recursive server, for whatever reads
// this to set the walk's time against.
type resolver struct {
	Server    *server `json:"server,omitempty"`
	ElapsedMS float64 `json:"elapsed_ms"`
	Rcode     string  `json:"rcode,omitempty"`
	Error     string  `json:"error,omitempty"`
}

type question struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type step struct {
	Zone       string      `json:"zone"`
	Kind       string      `json:"kind"`
	Server     *server     `json:"server,omitempty"`
	Proto      string      `json:"proto,omitempty"`
	RTTMS      float64     `json:"rtt_ms,omitempty"`
	Rcode      string      `json:"rcode,omitempty"`
	Flags      *flags      `json:"flags,omitempty"`
	Records    []record    `json:"records,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
	Aside      bool        `json:"aside,omitempty"`
	Delegation *delegation `json:"delegation,omitempty"`
	DNSSEC     *dnssec     `json:"dnssec,omitempty"`
	Error      string      `json:"error,omitempty"`
	Children   []*step     `json:"children,omitempty"`
}

type server struct {
	Name string `json:"name,omitempty"`
	IP   string `json:"ip,omitempty"`
	Port uint16 `json:"port,omitempty"`
	ASN  *asn   `json:"asn,omitempty"`
}

type asn struct {
	Number      uint32 `json:"number"`
	Prefix      string `json:"prefix,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Registry    string `json:"registry,omitempty"`
	Allocated   string `json:"allocated,omitempty"`
}

// flags carries only the bits that are set, so that reading it back is a
// question of presence rather than of comparing against false.
type flags struct {
	AA   bool `json:"aa,omitempty"`
	TC   bool `json:"tc,omitempty"`
	AD   bool `json:"ad,omitempty"`
	DO   bool `json:"do,omitempty"`
	EDNS bool `json:"edns,omitempty"`
}

type record struct {
	Name string `json:"name"`
	TTL  uint32 `json:"ttl"`
	Type string `json:"type"`
	Data string `json:"data"`
}

type delegation struct {
	Zone           string              `json:"zone"`
	NS             []string            `json:"ns,omitempty"`
	Glue           map[string][]string `json:"glue,omitempty"`
	GlueLess       []string            `json:"glueless,omitempty"`
	OutOfBailiwick []string            `json:"out_of_bailiwick,omitempty"`
	DSPresent      bool                `json:"ds_present,omitempty"`
}

type dnssec struct {
	State     string   `json:"state"`
	Reason    string   `json:"reason,omitempty"`
	KeyTags   []uint16 `json:"key_tags,omitempty"`
	Algorithm string   `json:"algorithm,omitempty"`
	Digest    string   `json:"digest,omitempty"`
}

func convert(from *trace.Step) *step {
	if from == nil {
		return nil
	}

	to := &step{
		Zone:       from.Zone,
		Kind:       string(from.Kind),
		Server:     convertServer(from.Server),
		Proto:      from.Proto,
		RTTMS:      milliseconds(from.RTT),
		Rcode:      from.Rcode,
		Flags:      convertFlags(from.Flags),
		Notes:      from.Notes,
		Aside:      from.Aside,
		Delegation: convertDelegation(from.Delegation),
		DNSSEC:     convertDNSSEC(from.DNSSEC),
		Error:      from.Err,
	}
	for _, rr := range from.Records {
		to.Records = append(to.Records, record{Name: rr.Name, TTL: rr.TTL, Type: rr.Type, Data: rr.Data})
	}
	for _, child := range from.Children {
		to.Children = append(to.Children, convert(child))
	}
	return to
}

func convertResolver(from *trace.Resolver) *resolver {
	if from == nil {
		return nil
	}
	return &resolver{
		Server:    convertServer(from.Server),
		ElapsedMS: milliseconds(from.Elapsed),
		Rcode:     from.Rcode,
		Error:     from.Err,
	}
}

func convertServer(from trace.Server) *server {
	if from.Name == "" && !from.IP.IsValid() {
		return nil
	}

	to := &server{Name: from.Name, Port: from.Port}
	if from.IP.IsValid() {
		to.IP = from.IP.String()
	}
	if from.ASN != nil {
		to.ASN = &asn{
			Number:      from.ASN.Number,
			Prefix:      from.ASN.Prefix,
			CountryCode: from.ASN.CountryCode,
			Registry:    from.ASN.Registry,
			Allocated:   from.ASN.Allocated,
		}
	}
	return to
}

func convertFlags(from trace.Flags) *flags {
	if from == (trace.Flags{}) {
		return nil
	}
	return &flags{AA: from.AA, TC: from.TC, AD: from.AD, DO: from.DO, EDNS: from.EDNS}
}

func convertDelegation(from *trace.Delegation) *delegation {
	if from == nil {
		return nil
	}

	to := &delegation{
		Zone:           from.Zone,
		NS:             from.NS,
		GlueLess:       from.GlueLess,
		OutOfBailiwick: from.OutOfBailiwick,
		DSPresent:      from.DSPresent,
	}
	for name, addrs := range from.Glue {
		if to.Glue == nil {
			to.Glue = make(map[string][]string, len(from.Glue))
		}
		for _, addr := range addrs {
			to.Glue[name] = append(to.Glue[name], addr.String())
		}
	}
	return to
}

func convertDNSSEC(from *trace.DNSSECStatus) *dnssec {
	if from == nil {
		return nil
	}
	return &dnssec{
		State:     string(from.State),
		Reason:    from.Reason,
		KeyTags:   from.KeyTags,
		Algorithm: from.Algorithm,
		Digest:    from.Digest,
	}
}

// milliseconds is how long something took, in the unit a reader expects and
// rounded to the microsecond so that the number stays short.
func milliseconds(d time.Duration) float64 {
	return math.Round(float64(d)/float64(time.Microsecond)) / 1000
}
