package jsonout

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

// ErrVersion is a document of another schema_version, which has had a field
// change meaning or go away since, and cannot be read as this one.
var ErrVersion = errors.New("jsonout: the document is of another schema version")

// Read is the way back from [Render]: a trace as --format json wrote it, to be
// drawn again. What it gives back is the copy that was fit to draw, so its names
// are already escaped and drawing them escapes nothing twice.
//
// The document may have come from anywhere, so what the verdicts and the exit
// code are read from — a kind, a chain of trust — has to be one this build
// knows, and anything that is not is refused rather than guessed at.
func Read(r io.Reader) (*trace.Trace, error) {
	var doc document
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("jsonout: not a trace: %w", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: it is version %d, and this build reads %d",
			ErrVersion, doc.SchemaVersion, SchemaVersion)
	}

	tr := &trace.Trace{
		Question: trace.Question{Name: doc.Question.Name, Type: doc.Question.Type, Class: doc.Question.Class},
		Elapsed:  duration(doc.ElapsedMS),
		Warnings: doc.Warnings,
	}
	var err error
	if tr.Started, err = moment(doc.Started); err != nil {
		return nil, fmt.Errorf("jsonout: started: %w", err)
	}
	for _, from := range doc.Resolvers {
		answer, err := readResolver(from)
		if err != nil {
			return nil, err
		}
		tr.Resolvers = append(tr.Resolvers, answer)
	}
	if tr.Root, err = readStep(doc.Root); err != nil {
		return nil, err
	}
	return tr, nil
}

func readStep(from *step) (*trace.Step, error) {
	if from == nil {
		return nil, nil
	}

	kind := trace.StepKind(from.Kind)
	switch kind {
	case trace.KindZone, trace.KindReferral, trace.KindAnswer, trace.KindCNAME, trace.KindNoData,
		trace.KindNXDomain, trace.KindLame, trace.KindFiltered, trace.KindTimeout, trace.KindError, trace.KindSkipped:
	default:
		return nil, fmt.Errorf("jsonout: %q is not a kind of step", from.Kind)
	}

	to := &trace.Step{
		Zone:      from.Zone,
		Proto:     from.Proto,
		RTT:       duration(from.RTTMS),
		Size:      from.SizeBytes,
		Limit:     from.LimitBytes,
		Rcode:     from.Rcode,
		Kind:      kind,
		Records:   readRecords(from.Records),
		Notes:     from.Notes,
		Extended:  readExtended(from.Extended),
		NSID:      from.NSID,
		Aside:     from.Aside,
		Minimised: from.Minimised,
		Err:       from.Error,
	}
	if from.Asked != nil {
		to.Asked = trace.Question{Name: from.Asked.Name, Type: from.Asked.Type}
	}
	if from.Flags != nil {
		to.Flags = trace.Flags{AA: from.Flags.AA, TC: from.Flags.TC, AD: from.Flags.AD, DO: from.Flags.DO, EDNS: from.Flags.EDNS}
	}
	if from.SOA != nil {
		to.SOA = &trace.SOA{Serial: from.SOA.Serial, TTL: from.SOA.TTL, Minimum: from.SOA.Minimum}
	}

	var err error
	if to.Server, err = readServer(from.Server); err != nil {
		return nil, err
	}
	if to.Subnet, err = readSubnet(from.Subnet); err != nil {
		return nil, err
	}
	if to.Delegation, err = readDelegation(from.Delegation); err != nil {
		return nil, err
	}
	if to.DNSSEC, err = readDNSSEC(from.DNSSEC); err != nil {
		return nil, err
	}
	for _, child := range from.Children {
		read, err := readStep(child)
		if err != nil {
			return nil, err
		}
		if read != nil {
			to.Children = append(to.Children, read)
		}
	}
	return to, nil
}

func readResolver(from *resolver) (*trace.Resolver, error) {
	if from == nil {
		return nil, errors.New("jsonout: a resolver with nothing in it")
	}
	match := trace.Match(from.Match)
	switch match {
	case "", trace.MatchSame, trace.MatchDiffers:
	default:
		return nil, fmt.Errorf("jsonout: %q is not how a resolver's answer can match", from.Match)
	}

	to := &trace.Resolver{
		Elapsed:  duration(from.ElapsedMS),
		Rcode:    from.Rcode,
		Err:      from.Error,
		Records:  readRecords(from.Records),
		Extended: readExtended(from.Extended),
		Match:    match,
	}
	var err error
	if to.Server, err = readServer(from.Server); err != nil {
		return nil, err
	}
	if to.Subnet, err = readSubnet(from.Subnet); err != nil {
		return nil, err
	}
	return to, nil
}

func readServer(from *server) (trace.Server, error) {
	if from == nil {
		return trace.Server{}, nil
	}
	to := trace.Server{Name: from.Name, Port: from.Port}
	if from.IP != "" {
		ip, err := netip.ParseAddr(from.IP)
		if err != nil {
			return trace.Server{}, fmt.Errorf("jsonout: server %q: %w", from.IP, err)
		}
		to.IP = ip
	}
	if from.ASN != nil {
		to.ASN = &trace.ASNInfo{
			Number:      from.ASN.Number,
			Prefix:      from.ASN.Prefix,
			CountryCode: from.ASN.CountryCode,
			Registry:    from.ASN.Registry,
			Allocated:   from.ASN.Allocated,
		}
	}
	return to, nil
}

func readSubnet(from *subnet) (*trace.Subnet, error) {
	if from == nil {
		return nil, nil
	}
	prefix, err := netip.ParsePrefix(from.Prefix)
	if err != nil {
		return nil, fmt.Errorf("jsonout: subnet %q: %w", from.Prefix, err)
	}
	return &trace.Subnet{Prefix: prefix, Scope: from.Scope}, nil
}

func readRecords(from []record) []trace.RR {
	var records []trace.RR
	for _, rr := range from {
		read := trace.RR{Name: rr.Name, TTL: rr.TTL, Type: rr.Type, Data: rr.Data}
		if rr.Service != nil {
			read.Service = &trace.Service{
				Priority: rr.Service.Priority,
				Target:   rr.Service.Target,
				ALPN:     rr.Service.ALPN,
				ECH:      rr.Service.ECH,
			}
		}
		records = append(records, read)
	}
	return records
}

// readExtended takes the escaping off EXTRA-TEXT: it is kept as the server sent
// it and escaped where it is drawn, so reading it back escaped would escape
// every backslash in it twice.
func readExtended(from []extendedError) []trace.ExtendedError {
	var extended []trace.ExtendedError
	for _, ede := range from {
		extended = append(extended, trace.ExtendedError{Code: ede.Code, Reason: ede.Reason, Text: unescape(ede.Text)})
	}
	return extended
}

func readDelegation(from *delegation) (*trace.Delegation, error) {
	if from == nil {
		return nil, nil
	}
	to := &trace.Delegation{
		Zone:           from.Zone,
		TTL:            from.TTL,
		NS:             from.NS,
		GlueLess:       from.GlueLess,
		OutOfBailiwick: from.OutOfBailiwick,
		DSPresent:      from.DSPresent,
	}
	for name, addrs := range from.Glue {
		if to.Glue == nil {
			to.Glue = make(map[string][]netip.Addr, len(from.Glue))
		}
		for _, addr := range addrs {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				return nil, fmt.Errorf("jsonout: glue for %s: %w", name, err)
			}
			to.Glue[name] = append(to.Glue[name], ip)
		}
	}
	return to, nil
}

func readDNSSEC(from *dnssec) (*trace.DNSSECStatus, error) {
	if from == nil {
		return nil, nil
	}
	state := trace.DNSSECState(from.State)
	switch state {
	case trace.Secure, trace.Insecure, trace.Bogus, trace.Indeterminate:
	default:
		return nil, fmt.Errorf("jsonout: %q is not how far a chain of trust can get", from.State)
	}
	to := &trace.DNSSECStatus{
		State:     state,
		Reason:    from.Reason,
		Zone:      from.Zone,
		KeyTags:   from.KeyTags,
		Algorithm: from.Algorithm,
		Digest:    from.Digest,
	}
	for _, signed := range from.Signatures {
		inception, err := moment(signed.Inception)
		if err != nil {
			return nil, fmt.Errorf("jsonout: inception: %w", err)
		}
		expiration, err := moment(signed.Expiration)
		if err != nil {
			return nil, fmt.Errorf("jsonout: expiration: %w", err)
		}
		to.Signatures = append(to.Signatures, trace.Lifetime{Inception: inception, Expiration: expiration})
	}
	return to, nil
}

// duration is the way back from milliseconds, which were kept to the
// microsecond.
func duration(ms float64) time.Duration {
	return time.Duration(ms*1000) * time.Microsecond
}

// moment reads an RFC 3339 time, with or without a fraction of a second.
func moment(text string) (time.Time, error) {
	if text == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, text)
}

// unescape undoes [trace.Printable]: \DDD is the byte it stands for and \\ a
// backslash. Anything else is left as it stands, since it was never escaped.
func unescape(text string) string {
	if !strings.Contains(text, `\`) {
		return text
	}
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] != '\\' || i+1 == len(text) {
			b.WriteByte(text[i])
			continue
		}
		if text[i+1] == '\\' {
			b.WriteByte('\\')
			i++
			continue
		}
		if i+3 < len(text) {
			if code, err := strconv.ParseUint(text[i+1:i+4], 10, 8); err == nil {
				b.WriteByte(byte(code))
				i += 3
				continue
			}
		}
		b.WriteByte(text[i])
	}
	return b.String()
}
