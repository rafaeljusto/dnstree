package jsonout

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
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
	limited := &io.LimitedReader{R: r, N: maxDocument + 1}
	decoder := json.NewDecoder(limited)
	err := decoder.Decode(&doc)
	if limited.N == 0 {
		return nil, fmt.Errorf("jsonout: not a trace: it is larger than %d MiB", maxDocument>>20)
	}
	if err != nil {
		return nil, fmt.Errorf("jsonout: not a trace: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("jsonout: not a trace: something follows it after it ends")
	}
	if doc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: it is version %d, and this build reads %d",
			ErrVersion, doc.SchemaVersion, SchemaVersion)
	}

	tr := &trace.Trace{
		Question: trace.Question{Name: doc.Question.Name, Type: doc.Question.Type, Class: doc.Question.Class},
		Warnings: doc.Warnings,
		Without:  doc.Without,
	}
	if tr.Elapsed, err = duration("elapsed_ms", doc.ElapsedMS); err != nil {
		return nil, err
	}
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
	if tr.Root, err = readStep(doc.Root, 0); err != nil {
		return nil, err
	}
	tr.Timed = timed(doc.Root)
	if doc.Trial != nil {
		tr.Trial = &trace.Trial{Zone: doc.Trial.Zone, NS: doc.Trial.NS}
		if tr.Trial.Addrs, err = readAddrs("trial", doc.Trial.Addrs); err != nil {
			return nil, err
		}
	}
	if doc.Report != nil {
		tr.Report = &trace.Report{Agent: doc.Report.Agent, Name: doc.Report.Name, Code: doc.Report.Code,
			Rcode: doc.Report.Rcode, Err: doc.Report.Error}
	}
	if tr.CAA, err = readCAA(doc.CAA); err != nil {
		return nil, err
	}
	return tr, nil
}

// readCAA reads the climb back. --expect caa: is a verdict read from it, so
// what each lookup came to has to be one this build knows.
func readCAA(from *caa) (*trace.CAA, error) {
	if from == nil {
		return nil, nil
	}
	to := &trace.CAA{
		Owner:     from.Owner,
		Issue:     readIssuers(from.Issue),
		Wildcard:  readIssuers(from.Wildcard),
		Refused:   from.Refused,
		Undecided: from.Undecided,
	}
	for _, lookup := range from.Asked {
		found := trace.CAAFound(lookup.Found)
		switch found {
		case trace.CAANone, trace.CAASet, trace.CAAFailed:
		default:
			return nil, fmt.Errorf("jsonout: %q is not what a CAA lookup can come to", lookup.Found)
		}
		to.Asked = append(to.Asked, trace.CAALookup{Name: lookup.Name, Found: found, Alias: lookup.Alias, Err: lookup.Error})
	}
	for _, record := range from.Records {
		to.Records = append(to.Records, trace.CAARecord{Critical: record.Critical, Tag: record.Tag, Value: record.Value, Known: record.Known})
	}
	var err error
	if to.DNSSEC, err = readDNSSEC(from.DNSSEC); err != nil {
		return nil, err
	}
	return to, nil
}

func readIssuers(from *issuers) *trace.Issuers {
	if from == nil {
		return nil
	}
	return &trace.Issuers{CAs: append([]string{}, from.CAs...)}
}

// A trace is far smaller and shallower than these, whatever the budgets were
// raised to. Past them a file only costs memory, and drawing a deep one costs
// its depth again on every line.
const (
	maxDocument = 64 << 20
	maxNesting  = 1024
	maxDuration = 365 * 24 * time.Hour
)

func readStep(from *step, depth int) (*trace.Step, error) {
	if from == nil {
		return nil, nil
	}
	if depth > maxNesting {
		return nil, fmt.Errorf("jsonout: steps nested deeper than %d, which no walk goes", maxNesting)
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
		Size:      from.SizeBytes,
		Limit:     from.LimitBytes,
		Rcode:     from.Rcode,
		Kind:      kind,
		Records:   readRecords(from.Records),
		Notes:     from.Notes,
		Extended:  readExtended(from.Extended),
		NSID:      from.NSID,
		Cookie:    trace.CookieState(from.Cookie),
		ReportTo:  from.ReportTo,
		Aside:     from.Aside,
		Minimised: from.Minimised,
		Compact:   from.Compact,
		Err:       from.Error,
	}
	var err error
	if to.RTT, err = duration("rtt_ms", from.RTTMS); err != nil {
		return nil, err
	}
	if from.StartMS != nil {
		if to.Start, err = duration("start_ms", *from.StartMS); err != nil {
			return nil, err
		}
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
	switch to.Cookie {
	case "", trace.CookieSupported, trace.CookieAbsent, trace.CookieMismatch, trace.CookieMalformed, trace.CookieRejected:
	default:
		return nil, fmt.Errorf("jsonout: %q is not a way to answer a cookie", from.Cookie)
	}

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
	if to.Dangling, err = readDangling(from.Dangling); err != nil {
		return nil, err
	}
	if to.Probe, err = readProbe(from.Probe); err != nil {
		return nil, err
	}
	if to.EDNS, err = readEDNS(from.EDNS); err != nil {
		return nil, err
	}
	for _, child := range from.Children {
		read, err := readStep(child, depth+1)
		if err != nil {
			return nil, err
		}
		if read != nil {
			to.Children = append(to.Children, read)
		}
	}
	return to, nil
}

// timed reports whether the walk says when its steps started. A walk saved
// before it did carries no start on any of them.
func timed(from *step) bool {
	if from == nil {
		return false
	}
	if from.StartMS != nil {
		return true
	}
	for _, child := range from.Children {
		if timed(child) {
			return true
		}
	}
	return false
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
	kept := trace.Kept(from.Kept)
	switch kept {
	case "", trace.KeptLonger, trace.KeptStale:
	default:
		return nil, fmt.Errorf("jsonout: %q is not what a resolver's TTL can say", from.Kept)
	}

	to := &trace.Resolver{
		Rcode:    from.Rcode,
		Err:      from.Error,
		Records:  readRecords(from.Records),
		Extended: readExtended(from.Extended),
		Match:    match,
		Kept:     kept,
	}
	var err error
	if to.Elapsed, err = duration("elapsed_ms", from.ElapsedMS); err != nil {
		return nil, err
	}
	if to.Server, err = readServer(from.Server); err != nil {
		return nil, err
	}
	if to.Subnet, err = readSubnet(from.Subnet); err != nil {
		return nil, err
	}
	if to.DDR, err = readDiscovery(from.DDR); err != nil {
		return nil, err
	}
	return to, nil
}

func readDiscovery(from *discovery) (*trace.Discovery, error) {
	if from == nil {
		return nil, nil
	}
	to := &trace.Discovery{Rcode: from.Rcode, Err: from.Error}
	for _, offer := range from.Designated {
		read := trace.Designated{
			Priority: offer.Priority, Target: offer.Target,
			Protocols: offer.Protocols, ALPN: offer.ALPN,
			Port: offer.Port, DoHPath: offer.DoHPath,
		}
		for _, hint := range offer.Hints {
			addr, err := netip.ParseAddr(hint)
			if err != nil {
				return nil, fmt.Errorf("jsonout: %q is not an address a designated resolver can be at", hint)
			}
			read.Hints = append(read.Hints, addr)
		}
		to.Designated = append(to.Designated, read)
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

func readProbe(from *probe) (*trace.Probe, error) {
	if from == nil {
		return nil, nil
	}
	kind, state := trace.ProbeKind(from.Kind), trace.ProbeState(from.State)
	switch kind {
	case trace.ProbeTransfer, trace.ProbeRecursion:
	default:
		return nil, fmt.Errorf("jsonout: %q is not something a nameserver can be asked for", from.Kind)
	}
	switch state {
	case trace.ProbeOpen, trace.ProbeClosed, trace.ProbeUnchecked:
	default:
		return nil, fmt.Errorf("jsonout: %q is not what can come of asking a nameserver", from.State)
	}
	return &trace.Probe{Kind: kind, State: state}, nil
}

func readEDNS(from *edns) (*trace.EDNSTest, error) {
	if from == nil {
		return nil, nil
	}
	test := &trace.EDNSTest{
		Kind: trace.EDNSKind(from.Kind), State: trace.EDNSState(from.State), Fault: trace.EDNSFault(from.Fault),
	}
	switch test.Kind {
	case trace.EDNSPlain, trace.EDNSVersion, trace.EDNSOption, trace.EDNSFlag:
	default:
		return nil, fmt.Errorf("jsonout: %q is not a shape a nameserver is asked in", from.Kind)
	}
	switch test.State {
	case trace.EDNSOK, trace.EDNSUnchecked:
		if test.Fault != "" {
			return nil, fmt.Errorf("jsonout: an edns test that is %s cannot have a fault", from.State)
		}
	case trace.EDNSBroken:
		switch test.Fault {
		case trace.EDNSSilent, trace.EDNSRcode, trace.EDNSNoOPT, trace.EDNSBadVers, trace.EDNSNoSOA, trace.EDNSEchoed, trace.EDNSAnswer:
		default:
			return nil, fmt.Errorf("jsonout: %q is not what an edns test can get wrong", from.Fault)
		}
	default:
		return nil, fmt.Errorf("jsonout: %q is not what can come of an edns test", from.State)
	}
	return test, nil
}

func readDangling(from *dangling) (*trace.Dangling, error) {
	if from == nil {
		return nil, nil
	}
	kind := trace.DanglingKind(from.Kind)
	switch kind {
	case trace.DanglingNameserver, trace.DanglingAlias, trace.DanglingLame:
	default:
		return nil, fmt.Errorf("jsonout: %q is not a way to be left dangling", from.Kind)
	}
	return &trace.Dangling{Kind: kind, Name: from.Name, Target: from.Target, Missing: from.Missing, Zone: from.Zone}, nil
}

func readDelegation(from *delegation) (*trace.Delegation, error) {
	if from == nil {
		return nil, nil
	}
	to := &trace.Delegation{
		Zone:           from.Zone,
		TTL:            from.TTL,
		ZoneTTL:        from.ZoneTTL,
		NS:             from.NS,
		GlueLess:       from.GlueLess,
		OutOfBailiwick: from.OutOfBailiwick,
		DSPresent:      from.DSPresent,
	}
	var err error
	if to.Glue, err = readAddrs("glue", from.Glue); err != nil {
		return nil, err
	}
	if to.ZoneAddrs, err = readAddrs("zone_addrs", from.ZoneAddrs); err != nil {
		return nil, err
	}
	return to, nil
}

// readAddrs reads a map of names to addresses, nil where it is empty.
func readAddrs(field string, from map[string][]string) (map[string][]netip.Addr, error) {
	var to map[string][]netip.Addr
	for name, addrs := range from {
		if to == nil {
			to = make(map[string][]netip.Addr, len(from))
		}
		to[name] = []netip.Addr{}
		for _, addr := range addrs {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				return nil, fmt.Errorf("jsonout: %s for %s: %w", field, name, err)
			}
			to[name] = append(to[name], ip)
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
	if from.Signal != nil {
		state := trace.SignalState(from.Signal.State)
		switch state {
		case trace.SignalNone, trace.SignalMatch, trace.SignalPending, trace.SignalDelete,
			trace.SignalInconsistent, trace.SignalUnchecked:
		default:
			return nil, fmt.Errorf("jsonout: %q is not what a zone's request of its parent can come to", from.Signal.State)
		}
		to.Signal = &trace.Signal{State: state, Reason: from.Signal.Reason,
			Requested: from.Signal.Requested, Held: from.Signal.Held}
	}
	if from.NSEC3 != nil {
		to.NSEC3 = &trace.NSEC3{Zone: from.NSEC3.Zone, Iterations: from.NSEC3.Iterations, Salt: from.NSEC3.Salt}
	}
	for _, k := range from.Keys {
		to.Keys = append(to.Keys, trace.Key{Tag: k.Tag, Algorithm: k.Algorithm, SEP: k.SEP, Revoked: k.Revoked,
			Bits: k.Bits, Pointed: k.Pointed, Signs: k.Signs})
	}
	for _, d := range from.DS {
		match := trace.DSMatch(d.Match)
		switch match {
		case trace.DSMatched, trace.DSUnmatched, trace.DSUnchecked:
		default:
			return nil, fmt.Errorf("jsonout: %q is not what a DS can come to against the keys", d.Match)
		}
		to.DS = append(to.DS, trace.DS{Tag: d.Tag, Algorithm: d.Algorithm, Digest: d.Digest, Match: match})
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
// microsecond. It rounds, since 1.001 is a hair under 1001 microseconds once it
// is a float. A time no walk takes is refused while it is still a float, since
// one past the range of a Duration converts to whatever the platform makes of it.
func duration(field string, ms float64) (time.Duration, error) {
	if ms < 0 || ms > float64(maxDuration/time.Millisecond) {
		return 0, fmt.Errorf("jsonout: %s is %g, and no walk takes less than nothing or more than a year", field, ms)
	}
	return time.Duration(math.Round(ms*1000)) * time.Microsecond, nil
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
