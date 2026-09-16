// Package resolver walks the delegation chain from the root down to the
// authoritative servers, classifying every response and recording each hop in
// the trace.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/internal/roothints"
	"github.com/rafaeljusto/dnstree/internal/trace"
	"github.com/rafaeljusto/dnstree/internal/transport"
)

const (
	// DefaultPort is where nameservers listen.
	DefaultPort = 53

	// maxParallel bounds the fanout of All: quick enough to be worth it, few
	// enough to stay polite to one zone's servers.
	maxParallel = 4

	// maxSideResolution is how deep nameserver names may be chased before the
	// walk gives up on them.
	maxSideResolution = 2
)

// Config is how a resolution is run.
type Config struct {
	// Transport carries every query. Required.
	Transport transport.Transport

	// TCP fetches an answer that came back truncated. Nil leaves the TC bit
	// alone, and the hop keeps whatever fitted in the datagram.
	TCP transport.Transport

	// Roots is where a walk starts, usually RootServers(roothints.Default()).
	// Required.
	Roots []trace.Server

	// UDPSize advertises an EDNS0 buffer, zero asks without EDNS0.
	UDPSize uint16

	// DNSSEC sets the DO bit, so that servers include their signatures.
	DNSSEC bool

	// All asks every nameserver of a zone instead of stopping at the first one
	// that answers. The walk still follows a single path down.
	All bool

	// Family restricts the walk to IPv4 (4) or IPv6 (6) servers. Zero uses
	// whatever a delegation offers.
	Family int

	// CheckNS asks the zone it ends in for its own NS RRset and warns when that
	// does not match what the parent delegated. It costs one more query.
	CheckNS bool

	Budget Budget
}

// Resolver answers queries by walking the delegation chain itself, never
// asking a recursive server.
type Resolver struct {
	cfg Config
}

// New checks a configuration and returns the resolver for it.
func New(cfg Config) (*Resolver, error) {
	if cfg.Transport == nil {
		return nil, errors.New("resolver: no transport to query with")
	}
	if len(cfg.Roots) == 0 {
		return nil, errors.New("resolver: no root servers to start from")
	}
	switch cfg.Family {
	case 0, 4, 6:
	default:
		return nil, fmt.Errorf("resolver: address family %d is neither 4 nor 6", cfg.Family)
	}
	return &Resolver{cfg: cfg}, nil
}

// RootServers turns root hints into the servers a walk starts from.
func RootServers(hints *roothints.Hints) []trace.Server {
	var servers []trace.Server
	for _, hint := range hints.Servers {
		for _, addr := range hint.Addrs {
			servers = append(servers, trace.Server{Name: hint.Name, IP: addr, Port: DefaultPort})
		}
	}
	return servers
}

// Resolve follows the delegation chain for name and qtype. The trace it returns
// holds everything that was learned, including the failures; an error means the
// question itself could not be asked.
func (r *Resolver) Resolve(ctx context.Context, name, qtype string) (*trace.Trace, error) {
	qname := dnsutil.Fqdn(name)
	if !dnsutil.IsName(qname) {
		return nil, fmt.Errorf("resolver: %q is not a domain name", name)
	}
	qtype = strings.ToUpper(qtype)
	rrtype, ok := dns.StringToType[qtype]
	if !ok {
		return nil, fmt.Errorf("resolver: unknown query type %q", qtype)
	}

	run := &run{
		cfg:      r.cfg,
		counters: newCounters(r.cfg.Budget),
		chased:   map[string]bool{qname: true},
		trace: &trace.Trace{
			Question: trace.Question{Name: qname, Type: qtype, Class: "IN"},
			Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
		},
	}

	start := time.Now()
	run.walk(ctx, qname, rrtype, run.trace.Root, 0)
	run.trace.Elapsed = time.Since(start)
	return run.trace, nil
}

// run is the state of one resolution.
type run struct {
	cfg      Config
	trace    *trace.Trace
	counters *counters

	// chased are the names a CNAME has already pointed at, so that a chain
	// cannot bite its own tail.
	chased map[string]bool

	// mu guards the warnings, which the fanout writes to from several goroutines.
	mu sync.Mutex
}

// walk follows referrals down from the root, one zone at a time, until
// something answers or the way down runs out. Every step it makes hangs under
// parent. side is how deep this walk is nested inside the resolution of a
// nameserver's name.
func (r *run) walk(ctx context.Context, qname string, qtype uint16, parent *trace.Step, side int) *trace.Step {
	zone, servers := ".", r.cfg.Roots

	for depth := 0; ; depth++ {
		if depth >= r.counters.max.MaxDepth {
			return r.fail(parent, zone, fmt.Sprintf("gave up after %d zone cuts", r.counters.max.MaxDepth))
		}

		step := r.queryZone(ctx, zone, servers, parent, qname, qtype)
		switch {
		case step == nil:
			r.warnf("no server answered for %s", zone)
			return nil
		case step.Kind == trace.KindCNAME && qtype != dns.TypeCNAME:
			return r.chaseCNAME(ctx, step, qname, qtype, side)
		case step.Kind != trace.KindReferral:
			if side == 0 {
				r.checkNS(ctx, step, parent)
			}
			return step
		}

		next := r.nextServers(ctx, step, side)
		if len(next) == 0 {
			r.warnf("the delegation to %s came with no usable address", step.Delegation.Zone)
			return step
		}
		zone, servers, parent = step.Delegation.Zone, next, step
	}
}

// queryZone asks the servers of one zone. By default it stops at the first that
// is any use and shows the rest as unqueried; with All it asks every one of
// them. It returns nil when none of them was any use.
func (r *run) queryZone(ctx context.Context, zone string, servers []trace.Server, parent *trace.Step, qname string, qtype uint16) *trace.Step {
	var usable []trace.Server
	for _, server := range dedupe(servers) {
		// A server of the wrong family is shown rather than hidden: a zone
		// reachable over one protocol only is worth seeing.
		if r.cfg.Family != 0 && family(server.IP) != r.cfg.Family {
			skipped := skipped(zone, server)
			skipped.Notes = []string{fmt.Sprintf("no IPv%d address", r.cfg.Family)}
			parent.Children = append(parent.Children, skipped)
			continue
		}
		usable = append(usable, server)
	}

	if r.cfg.All {
		return r.queryAll(ctx, zone, usable, parent, qname, qtype)
	}
	return r.queryFirst(ctx, zone, usable, parent, qname, qtype)
}

// queryFirst is the default strategy: ask until one of them answers.
func (r *run) queryFirst(ctx context.Context, zone string, servers []trace.Server, parent *trace.Step, qname string, qtype uint16) *trace.Step {
	for i, server := range servers {
		if err := r.counters.query(); err != nil {
			return r.fail(parent, zone, err.Error())
		}

		step := r.query(ctx, zone, server, qname, qtype)
		parent.Children = append(parent.Children, step)
		switch step.Kind {
		case trace.KindLame, trace.KindTimeout, trace.KindError:
			continue
		}

		for _, rest := range servers[i+1:] {
			parent.Children = append(parent.Children, skipped(zone, rest))
		}
		return step
	}
	return nil
}

// queryAll asks every server at once, a few at a time, and keeps them in the
// order they were delegated so that the tree stays the same between runs.
func (r *run) queryAll(ctx context.Context, zone string, servers []trace.Server, parent *trace.Step, qname string, qtype uint16) *trace.Step {
	var budget error
	for i := range servers {
		if err := r.counters.query(); err != nil {
			servers, budget = servers[:i], err
			break
		}
	}

	steps := make([]*trace.Step, len(servers))
	limit := make(chan struct{}, maxParallel)
	var wait sync.WaitGroup
	for i, server := range servers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			steps[i] = r.query(ctx, zone, server, qname, qtype)
		}()
	}
	wait.Wait()

	parent.Children = append(parent.Children, steps...)
	if budget != nil {
		r.fail(parent, zone, budget.Error())
	}

	for _, step := range steps {
		switch step.Kind {
		case trace.KindLame, trace.KindTimeout, trace.KindError:
			continue
		}
		return step
	}
	return nil
}

// query is one hop: a single question to a single server, including whatever it
// took to get a whole answer out of it.
func (r *run) query(ctx context.Context, zone string, server trace.Server, qname string, qtype uint16) *trace.Step {
	step := &trace.Step{Zone: zone, Server: server, Proto: r.cfg.Transport.Proto()}

	udpSize := r.cfg.UDPSize
	resp, err := r.exchange(ctx, step, r.cfg.Transport, qname, qtype, udpSize)
	if err != nil {
		step.Kind, step.Err = trace.KindError, err.Error()
		if transport.IsTimeout(err) {
			step.Kind = trace.KindTimeout
		}
		return step
	}

	// A server that cannot parse EDNS0 gets the question again without it.
	if udpSize > 0 && (resp.Rcode == dns.RcodeFormatError || resp.Rcode == dns.RcodeNotImplemented) {
		udpSize = 0
		if retry, err := r.exchange(ctx, step, r.cfg.Transport, qname, qtype, udpSize); err == nil {
			resp = retry
			step.Notes = append(step.Notes, "retried without EDNS0")
		}
	}

	// An answer that did not fit has to be fetched again over TCP.
	if resp.Truncated && r.cfg.TCP != nil && step.Proto != r.cfg.TCP.Proto() {
		if retry, err := r.exchange(ctx, step, r.cfg.TCP, qname, qtype, udpSize); err == nil {
			step.Notes = append(step.Notes, "truncated over "+step.Proto)
			step.Proto = r.cfg.TCP.Proto()
			resp = retry
		}
	}

	step.Rcode = dnsutil.RcodeToString(resp.Rcode)
	step.Flags = trace.Flags{
		AA:   resp.Authoritative,
		TC:   resp.Truncated,
		AD:   resp.AuthenticatedData,
		DO:   resp.Security,
		EDNS: resp.UDPSize > 0,
	}
	step.Kind, step.Delegation = classify(resp, zone, qname, qtype)

	switch step.Kind {
	case trace.KindAnswer, trace.KindCNAME:
		step.Records = records(resp.Answer)
	}
	return step
}

// exchange sends one message and adds what it cost to the step.
func (r *run) exchange(ctx context.Context, step *trace.Step, carrier transport.Transport, qname string, qtype uint16, udpSize uint16) (*dns.Msg, error) {
	req, err := transport.NewQuery(qname, qtype, udpSize, r.cfg.DNSSEC)
	if err != nil {
		return nil, err
	}

	resp, rtt, err := carrier.Exchange(ctx, req, netip.AddrPortFrom(step.Server.IP, step.Server.Port), step.Server.Name)
	step.RTT += rtt
	return resp, err
}

// nextServers is where the walk goes after a referral: the glue when there is
// any, and otherwise the addresses of the nameservers named outside the zone,
// resolved on their own.
func (r *run) nextServers(ctx context.Context, step *trace.Step, side int) []trace.Server {
	delegation := step.Delegation

	if len(delegation.GlueLess) > 0 {
		r.warnf("%s delegates to %s inside the zone, with no glue to reach them",
			delegation.Zone, strings.Join(delegation.GlueLess, ", "))
	}
	if servers := glueServers(delegation); len(servers) > 0 {
		return servers
	}
	if len(delegation.OutOfBailiwick) == 0 {
		return nil
	}
	if side >= maxSideResolution {
		r.warnf("the nameservers of %s are named too far away to keep chasing", delegation.Zone)
		return nil
	}

	rrtype, typeName := uint16(dns.TypeA), "A"
	if r.cfg.Family == 6 {
		rrtype, typeName = dns.TypeAAAA, "AAAA"
	}

	var servers []trace.Server
	for _, name := range delegation.OutOfBailiwick {
		root := &trace.Step{Zone: ".", Kind: trace.KindZone, Aside: true,
			Notes: []string{"resolving " + name}}
		step.Children = append(step.Children, root)

		result := r.walk(ctx, name, rrtype, root, side+1)
		if result == nil {
			continue
		}
		for _, record := range result.Records {
			if record.Type != typeName {
				continue
			}
			// The model keeps rdata as text, and an address is its own text.
			if addr, err := netip.ParseAddr(record.Data); err == nil {
				servers = append(servers, trace.Server{Name: name, IP: addr, Port: DefaultPort})
			}
		}
		if len(servers) > 0 {
			return servers // one nameserver we can reach is enough to go on
		}
	}
	return servers
}

// chaseCNAME starts again from the root for the name the alias points at, as a
// branch under the answer that gave it.
func (r *run) chaseCNAME(ctx context.Context, step *trace.Step, qname string, qtype uint16, side int) *trace.Step {
	target := cnameTarget(step.Records, qname)
	if target == "" {
		r.warnf("%s is an alias for a name the answer did not carry", qname)
		return step
	}
	if r.chased[target] {
		r.warnf("the alias chain for %s comes back to %s", qname, target)
		return step
	}
	if err := r.counters.cname(); err != nil {
		return r.fail(step, step.Zone, err.Error())
	}
	r.chased[target] = true

	root := &trace.Step{Zone: ".", Kind: trace.KindZone, Notes: []string{"resolving " + target}}
	step.Children = append(step.Children, root)
	return r.walk(ctx, target, qtype, root, side)
}

// checkNS asks the zone that answered for its own NS RRset and warns when it
// disagrees with what the parent delegated. Only the parent's view is visible
// from above, so the two drift apart unnoticed.
func (r *run) checkNS(ctx context.Context, answer *trace.Step, parent *trace.Step) {
	if !r.cfg.CheckNS || parent.Delegation == nil {
		return
	}
	delegated := parent.Delegation
	if err := r.counters.query(); err != nil {
		return
	}

	step := r.query(ctx, delegated.Zone, answer.Server, delegated.Zone, dns.TypeNS)
	step.Aside = true
	step.Notes = append(step.Notes, "parent/child NS check")
	answer.Children = append(answer.Children, step)

	child := make([]string, 0, len(step.Records))
	for _, record := range step.Records {
		if record.Type == "NS" {
			child = append(child, record.Data)
		}
	}
	step.Records = nil // the comparison is the point, not the records

	if len(child) == 0 {
		r.warnf("%s did not return its own NS records", delegated.Zone)
		return
	}
	if missing := missing(delegated.NS, child); len(missing) > 0 {
		r.warnf("%s delegates to %s, which the zone itself does not list",
			delegated.Zone, strings.Join(missing, ", "))
	}
	if extra := missing(child, delegated.NS); len(extra) > 0 {
		r.warnf("%s lists %s, which the delegation does not carry",
			delegated.Zone, strings.Join(extra, ", "))
	}
}

// fail records why the walk stopped and returns the step that says so.
func (r *run) fail(parent *trace.Step, zone, reason string) *trace.Step {
	step := &trace.Step{Zone: zone, Kind: trace.KindError, Err: reason}
	parent.Children = append(parent.Children, step)
	return step
}

func (r *run) warnf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trace.Warnings = append(r.trace.Warnings, fmt.Sprintf(format, args...))
}

// cnameTarget is what the alias for qname points at.
func cnameTarget(records []trace.RR, qname string) string {
	for _, record := range records {
		if record.Type == "CNAME" && dns.EqualName(record.Name, qname) {
			return dnsutil.Fqdn(record.Data)
		}
	}
	return ""
}

// missing are the names of a that b does not carry, compared the way DNS
// compares names.
func missing(a, b []string) []string {
	var missing []string
	for _, name := range a {
		found := false
		for _, other := range b {
			if dns.EqualName(name, other) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, name)
		}
	}
	return missing
}

func skipped(zone string, server trace.Server) *trace.Step {
	return &trace.Step{Zone: zone, Server: server, Kind: trace.KindSkipped}
}

func family(addr netip.Addr) int {
	if addr.Is4() {
		return 4
	}
	return 6
}

// glueServers is the next hop: every glued address of the delegation, in the
// order the nameservers were listed.
func glueServers(delegation *trace.Delegation) []trace.Server {
	var servers []trace.Server
	for _, name := range delegation.NS {
		for _, addr := range delegation.Glue[name] {
			servers = append(servers, trace.Server{Name: name, IP: addr, Port: DefaultPort})
		}
	}
	return servers
}

// dedupe drops the addresses that would be queried twice, which happens as soon
// as two nameserver names resolve to the same address.
func dedupe(servers []trace.Server) []trace.Server {
	seen := make(map[netip.AddrPort]bool, len(servers))
	unique := servers[:0:0]
	for _, server := range servers {
		addr := netip.AddrPortFrom(server.IP, server.Port)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		unique = append(unique, server)
	}
	return unique
}

// records flattens a section to the text the renderers work with.
func records(rrs []dns.RR) []trace.RR {
	var records []trace.RR
	for _, rr := range rrs {
		records = append(records, trace.RR{
			Name: rr.Header().Name,
			TTL:  rr.Header().TTL,
			Type: dnsutil.TypeToString(dns.RRToType(rr)),
			Data: fmt.Sprint(rr.Data()),
		})
	}
	return records
}
