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
// Version 2 added the extended errors of RFC 8914, the echoed client subnet,
// the decoded service parameters of an HTTPS or SVCB record, and what the
// resolver answered beside how long it took.
const SchemaVersion = 3

// Render writes the trace to w as JSON.
func Render(w io.Writer, tr *trace.Trace) error {
	document := document{SchemaVersion: SchemaVersion}
	if tr != nil {
		tr = tr.Shown()
		document.Question = question{Name: tr.Question.Name, Type: tr.Question.Type, Class: tr.Question.Class}
		document.ElapsedMS = milliseconds(tr.Elapsed)
		// Kept whole, since the time left on a signature is read against it
		// and a replay has to say what the walk said.
		if !tr.Started.IsZero() {
			document.Started = tr.Started.UTC().Format(time.RFC3339Nano)
		}
		for _, answer := range tr.Resolvers {
			document.Resolvers = append(document.Resolvers, convertResolver(answer))
		}
		document.Root = convert(tr.Root)
		document.Warnings = tr.Warnings
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

type document struct {
	SchemaVersion int         `json:"schema_version"`
	Question      question    `json:"question"`
	ElapsedMS     float64     `json:"elapsed_ms"`
	Started       string      `json:"started,omitempty"`
	Resolvers     []*resolver `json:"resolvers,omitempty"`
	Root          *step       `json:"root,omitempty"`
	Warnings      []string    `json:"warnings,omitempty"`
}

// resolver is the same question put to a recursive server, for whatever reads
// this to set the walk's time against.
type resolver struct {
	Server    *server         `json:"server,omitempty"`
	ElapsedMS float64         `json:"elapsed_ms"`
	Rcode     string          `json:"rcode,omitempty"`
	Error     string          `json:"error,omitempty"`
	Records   []record        `json:"records,omitempty"`
	Extended  []extendedError `json:"extended,omitempty"`
	Subnet    *subnet         `json:"subnet,omitempty"`

	// Match is how this answer stands against the one the walk found: "same",
	// "differs", or absent where there was nothing to compare.
	Match string `json:"match,omitempty"`
}

// extendedError is what a server said about its own answer (RFC 8914). withheld
// marks the codes that mean somebody decided the answer rather than serving it,
// so that a reader need not carry the list of which ones those are.
type extendedError struct {
	Code     uint16 `json:"code"`
	Reason   string `json:"reason,omitempty"`
	Text     string `json:"text,omitempty"`
	Withheld bool   `json:"withheld,omitempty"`
}

// subnet is the client subnet a server echoed. A zero scope is a server saying
// the answer is the same wherever it was asked from.
type subnet struct {
	Prefix string `json:"prefix"`
	Scope  uint8  `json:"scope"`
}

// asked is the question one hop put. The class is the document's own, so it is
// not written out once per step.
type asked struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type question struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type step struct {
	Zone       string          `json:"zone"`
	Kind       string          `json:"kind"`
	Server     *server         `json:"server,omitempty"`
	Asked      *asked          `json:"asked,omitempty"`
	Proto      string          `json:"proto,omitempty"`
	RTTMS      float64         `json:"rtt_ms,omitempty"`
	SizeBytes  int             `json:"size_bytes,omitempty"`
	LimitBytes int             `json:"limit_bytes,omitempty"`
	Tight      bool            `json:"tight,omitempty"`
	Rcode      string          `json:"rcode,omitempty"`
	Flags      *flags          `json:"flags,omitempty"`
	Records    []record        `json:"records,omitempty"`
	Notes      []string        `json:"notes,omitempty"`
	Extended   []extendedError `json:"extended,omitempty"`
	Subnet     *subnet         `json:"subnet,omitempty"`
	SOA        *soa            `json:"soa,omitempty"`
	NSID       string          `json:"nsid,omitempty"`
	Cookie     string          `json:"cookie,omitempty"`
	Aside      bool            `json:"aside,omitempty"`
	Minimised  bool            `json:"minimised,omitempty"`
	Delegation *delegation     `json:"delegation,omitempty"`
	DNSSEC     *dnssec         `json:"dnssec,omitempty"`
	Error      string          `json:"error,omitempty"`
	Children   []*step         `json:"children,omitempty"`
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
	Name    string   `json:"name"`
	TTL     uint32   `json:"ttl"`
	Type    string   `json:"type"`
	Data    string   `json:"data"`
	Service *service `json:"service,omitempty"`
}

// service is an HTTPS or SVCB record decoded. data carries every parameter as
// text; this is the part something reading the output can branch on.
type service struct {
	Priority uint16   `json:"priority"`
	Target   string   `json:"target,omitempty"`
	ALPN     []string `json:"alpn,omitempty"`
	ECH      bool     `json:"ech,omitempty"`
}

type delegation struct {
	Zone           string              `json:"zone"`
	TTL            uint32              `json:"ttl"`
	ZoneTTL        uint32              `json:"zone_ttl,omitempty"`
	NS             []string            `json:"ns,omitempty"`
	Glue           map[string][]string `json:"glue,omitempty"`
	GlueLess       []string            `json:"glueless,omitempty"`
	OutOfBailiwick []string            `json:"out_of_bailiwick,omitempty"`
	DSPresent      bool                `json:"ds_present,omitempty"`
}

type soa struct {
	Serial  uint32 `json:"serial"`
	TTL     uint32 `json:"ttl"`
	Minimum uint32 `json:"minimum"`
}

type dnssec struct {
	State      string      `json:"state"`
	Reason     string      `json:"reason,omitempty"`
	Zone       string      `json:"zone,omitempty"`
	KeyTags    []uint16    `json:"key_tags,omitempty"`
	Algorithm  string      `json:"algorithm,omitempty"`
	Digest     string      `json:"digest,omitempty"`
	Signatures []signature `json:"signatures,omitempty"`
	Signal     *signal     `json:"signal,omitempty"`
}

// signal is what the zone asks its parent to publish, in its CDS and CDNSKEY,
// held against the DS the parent does publish.
type signal struct {
	State     string   `json:"state"`
	Reason    string   `json:"reason,omitempty"`
	Requested []uint16 `json:"requested,omitempty"`
	Held      []uint16 `json:"held,omitempty"`
}

// signature is how long one signature a secure verdict rests on was made to
// last, which is what says whether its signer is still at work.
type signature struct {
	Inception  string `json:"inception"`
	Expiration string `json:"expiration"`
}

func convert(from *trace.Step) *step {
	if from == nil {
		return nil
	}

	to := &step{
		Zone:       from.Zone,
		Kind:       string(from.Kind),
		Server:     convertServer(from.Server),
		Asked:      convertAsked(from.Asked),
		Proto:      from.Proto,
		RTTMS:      milliseconds(from.RTT),
		SizeBytes:  from.Size,
		LimitBytes: from.Limit,
		Tight:      from.Tight(),
		Rcode:      from.Rcode,
		Flags:      convertFlags(from.Flags),
		Notes:      from.Notes,
		Extended:   convertExtended(from.Extended),
		Subnet:     convertSubnet(from.Subnet),
		SOA:        convertSOA(from.SOA),
		NSID:       from.NSID,
		Cookie:     string(from.Cookie),
		Aside:      from.Aside,
		Minimised:  from.Minimised,
		Delegation: convertDelegation(from.Delegation),
		DNSSEC:     convertDNSSEC(from.DNSSEC),
		Error:      from.Err,
	}
	to.Records = convertRecords(from.Records)
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
		Records:   convertRecords(from.Records),
		Extended:  convertExtended(from.Extended),
		Subnet:    convertSubnet(from.Subnet),
		Match:     string(from.Match),
	}
}

func convertRecords(from []trace.RR) []record {
	var records []record
	for _, rr := range from {
		converted := record{Name: rr.Name, TTL: rr.TTL, Type: rr.Type, Data: rr.Data}
		if rr.Service != nil {
			converted.Service = &service{
				Priority: rr.Service.Priority,
				Target:   rr.Service.Target,
				ALPN:     rr.Service.ALPN,
				ECH:      rr.Service.ECH,
			}
		}
		records = append(records, converted)
	}
	return records
}

func convertExtended(from []trace.ExtendedError) []extendedError {
	var extended []extendedError
	for _, ede := range from {
		// Escaped as String escapes it, and whole: \DDD is at most four bytes
		// for each one, so the limit is never reached.
		text := trace.Printable(ede.Text, 4*len(ede.Text))
		extended = append(extended, extendedError{
			Code:     ede.Code,
			Reason:   ede.Reason,
			Text:     text,
			Withheld: ede.Withheld(),
		})
	}
	return extended
}

func convertSubnet(from *trace.Subnet) *subnet {
	if from == nil {
		return nil
	}
	return &subnet{Prefix: from.Prefix.String(), Scope: from.Scope}
}

func convertAsked(from trace.Question) *asked {
	if from.Name == "" && from.Type == "" {
		return nil
	}
	return &asked{Name: from.Name, Type: from.Type}
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

func convertSOA(from *trace.SOA) *soa {
	if from == nil {
		return nil
	}
	return &soa{Serial: from.Serial, TTL: from.TTL, Minimum: from.Minimum}
}

func convertDelegation(from *trace.Delegation) *delegation {
	if from == nil {
		return nil
	}

	to := &delegation{
		Zone:           from.Zone,
		TTL:            from.TTL,
		ZoneTTL:        from.ZoneTTL,
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
	to := &dnssec{
		State:     string(from.State),
		Reason:    from.Reason,
		Zone:      from.Zone,
		KeyTags:   from.KeyTags,
		Algorithm: from.Algorithm,
		Digest:    from.Digest,
	}
	if from.Signal != nil {
		to.Signal = &signal{State: string(from.Signal.State), Reason: from.Signal.Reason,
			Requested: from.Signal.Requested, Held: from.Signal.Held}
	}
	for _, lifetime := range from.Signatures {
		to.Signatures = append(to.Signatures, signature{
			Inception:  timestamp(lifetime.Inception),
			Expiration: timestamp(lifetime.Expiration),
		})
	}
	return to
}

// timestamp is a moment as RFC 3339 writes it, in UTC and to the second, which
// is as fine as a signature's lifetime is kept. The zero time is no moment.
func timestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// milliseconds is how long something took, in the unit a reader expects and
// rounded to the microsecond so that the number stays short.
func milliseconds(d time.Duration) float64 {
	return math.Round(float64(d)/float64(time.Microsecond)) / 1000
}
