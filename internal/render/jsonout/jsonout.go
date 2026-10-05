// Package jsonout renders a trace as versioned JSON.
package jsonout

import (
	"encoding/json"
	"io"
	"math"
	"net/netip"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// SchemaVersion changes whenever a field changes meaning or goes away, so that
// something reading this output can tell whether it still understands it.
// Version 2 added the extended errors of RFC 8914, the echoed client subnet,
// the decoded service parameters of an HTTPS or SVCB record, and what the
// resolver answered beside how long it took. Version 4 escapes the text of an
// extended error, which version 3 wrote as the octets the server sent.
const SchemaVersion = 4

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
		document.Root = convert(tr.Root, tr.Timed)
		document.Warnings = tr.Warnings
		document.Without = tr.Without
		if tr.Trial != nil {
			document.Trial = &trial{Zone: tr.Trial.Zone, NS: tr.Trial.NS, Addrs: addrStrings(tr.Trial.Addrs)}
		}
		document.CAA = convertCAA(tr.CAA)
		document.SPF = convertSPF(tr.SPF)
		if tr.Report != nil {
			document.Report = &report{Agent: tr.Report.Agent, Name: tr.Report.Name, Code: tr.Report.Code,
				Rcode: tr.Report.Rcode, Error: tr.Report.Err}
		}
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
	Without       []string    `json:"without,omitempty"`
	CAA           *caa        `json:"caa,omitempty"`
	SPF           *spf        `json:"spf,omitempty"`
	Report        *report     `json:"report,omitempty"`
	Trial         *trial      `json:"trial,omitempty"`
}

// trial is the delegation --try-ns put in place of a zone's real one.
type trial struct {
	Zone  string              `json:"zone"`
	NS    []string            `json:"ns"`
	Addrs map[string][]string `json:"addrs,omitempty"`
}

// report is the failure report --report sent to the agent the zone named (RFC
// 9567).
type report struct {
	Agent string `json:"agent"`
	Name  string `json:"name,omitempty"`
	Code  uint16 `json:"code"`
	Rcode string `json:"rcode,omitempty"`
	Error string `json:"error,omitempty"`
}

// caa is who may issue certificates for the name (RFC 8659), and the climb from
// the name up that found the set deciding it.
type caa struct {
	Asked   []caaLookup `json:"asked"`
	Owner   string      `json:"owner,omitempty"`
	Records []caaRecord `json:"records,omitempty"`

	// Issue and Wildcard are absent where any authority may issue, and name
	// no authority where none may.
	Issue    *issuers `json:"issue,omitempty"`
	Wildcard *issuers `json:"wildcard,omitempty"`

	Refused   string  `json:"refused,omitempty"`
	Undecided string  `json:"undecided,omitempty"`
	DNSSEC    *dnssec `json:"dnssec,omitempty"`
}

type caaLookup struct {
	Name  string `json:"name"`
	Found string `json:"found"`
	Alias string `json:"alias,omitempty"`
	Error string `json:"error,omitempty"`
}

type caaRecord struct {
	Critical bool   `json:"critical,omitempty"`
	Tag      string `json:"tag"`
	Value    string `json:"value"`
	Known    bool   `json:"known"`
}

type issuers struct {
	CAs []string `json:"cas"`
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

	// Kept is what its TTL says of its copy: "longer" than the zone allows,
	// "stale", or absent where it says nothing either way.
	Kept string `json:"kept,omitempty"`

	DDR *discovery `json:"ddr,omitempty"`
}

// discovery is what the resolver said of its encrypted selves (RFC 9462), none
// of it verified.
type discovery struct {
	Rcode      string       `json:"rcode,omitempty"`
	Error      string       `json:"error,omitempty"`
	Designated []designated `json:"designated,omitempty"`
}

type designated struct {
	Priority  uint16   `json:"priority"`
	Target    string   `json:"target"`
	Protocols []string `json:"protocols,omitempty"`
	ALPN      []string `json:"alpn,omitempty"`
	Port      uint16   `json:"port,omitempty"`
	DoHPath   string   `json:"dohpath,omitempty"`
	Hints     []string `json:"hints,omitempty"`
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
	StartMS    *float64        `json:"start_ms,omitempty"`
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
	ReportTo   string          `json:"report_to,omitempty"`
	Aside      bool            `json:"aside,omitempty"`
	Minimised  bool            `json:"minimised,omitempty"`
	Compact    bool            `json:"compact,omitempty"`
	Delegation *delegation     `json:"delegation,omitempty"`
	DNSSEC     *dnssec         `json:"dnssec,omitempty"`
	Dangling   *dangling       `json:"dangling,omitempty"`
	Probe      *probe          `json:"probe,omitempty"`
	EDNS       *edns           `json:"edns,omitempty"`
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
	ZoneAddrs      map[string][]string `json:"zone_addrs,omitempty"`
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
	NSEC3      *nsec3      `json:"nsec3,omitempty"`
	Keys       []key       `json:"keys,omitempty"`
	DS         []ds        `json:"ds,omitempty"`
}

// key is one zone key of a secure zone's DNSKEY set.
type key struct {
	Tag       uint16 `json:"tag"`
	Algorithm string `json:"algorithm"`
	SEP       bool   `json:"sep,omitempty"`
	Revoked   bool   `json:"revoked,omitempty"`
	Bits      int    `json:"bits,omitempty"`
	Pointed   bool   `json:"pointed,omitempty"`
	Signs     bool   `json:"signs,omitempty"`
}

// ds is one DS record the parent of a secure zone publishes for it.
type ds struct {
	Tag       uint16 `json:"tag"`
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	Match     string `json:"match"`
}

// probe is a nameserver asked for what it should keep from strangers.
type probe struct {
	Kind  string `json:"kind"`
	State string `json:"state"`
}

func convertProbe(from *trace.Probe) *probe {
	if from == nil {
		return nil
	}
	return &probe{Kind: string(from.Kind), State: string(from.State)}
}

// edns is a nameserver asked in one of the shapes RFC 8906 tests.
type edns struct {
	Kind  string `json:"kind"`
	State string `json:"state"`
	Fault string `json:"fault,omitempty"`
}

func convertEDNS(from *trace.EDNSTest) *edns {
	if from == nil {
		return nil
	}
	return &edns{Kind: string(from.Kind), State: string(from.State), Fault: string(from.Fault)}
}

// dangling is a name left pointing at something that is not there.
type dangling struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Target  string `json:"target,omitempty"`
	Missing string `json:"missing,omitempty"`
	Zone    string `json:"zone,omitempty"`
}

// nsec3 is how the zone that denied something hashes its names.
type nsec3 struct {
	Zone       string `json:"zone"`
	Iterations uint16 `json:"iterations"`
	Salt       string `json:"salt,omitempty"`
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

func convert(from *trace.Step, timed bool) *step {
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
		ReportTo:   from.ReportTo,
		Aside:      from.Aside,
		Minimised:  from.Minimised,
		Compact:    from.Compact,
		Delegation: convertDelegation(from.Delegation),
		DNSSEC:     convertDNSSEC(from.DNSSEC),
		Dangling:   convertDangling(from.Dangling),
		Probe:      convertProbe(from.Probe),
		EDNS:       convertEDNS(from.EDNS),
		Error:      from.Err,
	}
	// Written wherever it is known, a start of zero included: the first query
	// goes out as the walk begins, and absent has to mean a walk that kept none.
	if timed && from.Queried() {
		to.StartMS = new(milliseconds(from.Start))
	}
	to.Records = convertRecords(from.Records)
	for _, child := range from.Children {
		to.Children = append(to.Children, convert(child, timed))
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
		Kept:      string(from.Kept),
		DDR:       convertDiscovery(from.DDR),
	}
}

func convertCAA(from *trace.CAA) *caa {
	if from == nil {
		return nil
	}
	to := &caa{
		Asked:     []caaLookup{},
		Owner:     from.Owner,
		Issue:     convertIssuers(from.Issue),
		Wildcard:  convertIssuers(from.Wildcard),
		Refused:   from.Refused,
		Undecided: from.Undecided,
		DNSSEC:    convertDNSSEC(from.DNSSEC),
	}
	for _, lookup := range from.Asked {
		to.Asked = append(to.Asked, caaLookup{Name: lookup.Name, Found: string(lookup.Found), Alias: lookup.Alias, Error: lookup.Err})
	}
	for _, record := range from.Records {
		to.Records = append(to.Records, caaRecord{Critical: record.Critical, Tag: record.Tag, Value: record.Value, Known: record.Known})
	}
	return to
}

func convertIssuers(from *trace.Issuers) *issuers {
	if from == nil {
		return nil
	}
	return &issuers{CAs: append([]string{}, from.CAs...)}
}

func convertDiscovery(from *trace.Discovery) *discovery {
	if from == nil {
		return nil
	}
	to := &discovery{Rcode: from.Rcode, Error: from.Err}
	for _, offer := range from.Designated {
		converted := designated{
			Priority: offer.Priority, Target: offer.Target,
			Protocols: offer.Protocols, ALPN: offer.ALPN,
			Port: offer.Port, DoHPath: offer.DoHPath,
		}
		for _, hint := range offer.Hints {
			converted.Hints = append(converted.Hints, hint.String())
		}
		to.Designated = append(to.Designated, converted)
	}
	return to
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
	to.Glue = addrStrings(from.Glue)
	to.ZoneAddrs = addrStrings(from.ZoneAddrs)
	return to
}

// addrStrings is a map of names to addresses as text, nil where it is empty.
func addrStrings(from map[string][]netip.Addr) map[string][]string {
	var to map[string][]string
	for name, addrs := range from {
		if to == nil {
			to = make(map[string][]string, len(from))
		}
		to[name] = []string{}
		for _, addr := range addrs {
			to[name] = append(to[name], addr.String())
		}
	}
	return to
}

func convertDangling(from *trace.Dangling) *dangling {
	if from == nil {
		return nil
	}
	return &dangling{Kind: string(from.Kind), Name: from.Name, Target: from.Target, Missing: from.Missing, Zone: from.Zone}
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
	if from.NSEC3 != nil {
		to.NSEC3 = &nsec3{Zone: from.NSEC3.Zone, Iterations: from.NSEC3.Iterations, Salt: from.NSEC3.Salt}
	}
	for _, k := range from.Keys {
		to.Keys = append(to.Keys, key{Tag: k.Tag, Algorithm: k.Algorithm, SEP: k.SEP, Revoked: k.Revoked,
			Bits: k.Bits, Pointed: k.Pointed, Signs: k.Signs})
	}
	for _, d := range from.DS {
		to.DS = append(to.DS, ds{Tag: d.Tag, Algorithm: d.Algorithm, Digest: d.Digest, Match: string(d.Match)})
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
