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
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/internal/roothints"
	"github.com/rafaeljusto/dnstree/internal/trace"
	"github.com/rafaeljusto/dnstree/internal/transport"
)

// DefaultPort is where nameservers listen.
const DefaultPort = 53

// Config is how a resolution is run.
type Config struct {
	// Transport carries every query. Required.
	Transport transport.Transport

	// Roots is where the walk starts, usually RootServers(roothints.Default()).
	// Required.
	Roots []trace.Server

	// UDPSize advertises an EDNS0 buffer, zero asks without EDNS0.
	UDPSize uint16

	// DNSSEC sets the DO bit, so that servers include their signatures.
	DNSSEC bool

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
		qname:    qname,
		qtype:    rrtype,
		counters: newCounters(r.cfg.Budget),
		trace: &trace.Trace{
			Question: trace.Question{Name: qname, Type: qtype, Class: "IN"},
			Root:     &trace.Step{Zone: ".", Kind: trace.KindZone},
		},
	}

	start := time.Now()
	run.walk(ctx)
	run.trace.Elapsed = time.Since(start)
	return run.trace, nil
}

// run is the state of one resolution.
type run struct {
	cfg      Config
	trace    *trace.Trace
	counters *counters
	qname    string
	qtype    uint16
}

// walk follows referrals down, one zone at a time, until something answers or
// the way down runs out.
func (r *run) walk(ctx context.Context) {
	zone, servers, parent := ".", r.cfg.Roots, r.trace.Root

	for {
		if err := r.counters.descend(); err != nil {
			parent.Children = append(parent.Children, &trace.Step{Zone: zone, Kind: trace.KindError, Err: err.Error()})
			return
		}

		step := r.queryZone(ctx, zone, servers, parent)
		if step == nil {
			r.warnf("no server answered for %s", zone)
			return
		}
		if step.Kind != trace.KindReferral {
			return
		}

		next := glueServers(step.Delegation)
		if len(next) == 0 {
			r.warnf("the delegation to %s came with no usable address", step.Delegation.Zone)
			return
		}
		zone, servers, parent = step.Delegation.Zone, next, step
	}
}

// queryZone asks the servers of one zone in order and stops at the first that
// answers or refers, which is the first-reachable strategy. Every attempt, lame
// or not, is recorded under parent. It returns nil when none of them was any
// use.
func (r *run) queryZone(ctx context.Context, zone string, servers []trace.Server, parent *trace.Step) *trace.Step {
	for _, server := range dedupe(servers) {
		if err := r.counters.query(); err != nil {
			step := &trace.Step{Zone: zone, Kind: trace.KindError, Err: err.Error()}
			parent.Children = append(parent.Children, step)
			return step
		}

		step := r.query(ctx, zone, server)
		parent.Children = append(parent.Children, step)

		switch step.Kind {
		case trace.KindLame, trace.KindTimeout, trace.KindError:
			continue
		}
		return step
	}
	return nil
}

// query is one hop: a single question to a single server.
func (r *run) query(ctx context.Context, zone string, server trace.Server) *trace.Step {
	step := &trace.Step{Zone: zone, Server: server, Proto: r.cfg.Transport.Proto()}

	req, err := transport.NewQuery(r.qname, r.qtype, r.cfg.UDPSize, r.cfg.DNSSEC)
	if err != nil {
		step.Kind, step.Err = trace.KindError, err.Error()
		return step
	}

	resp, rtt, err := r.cfg.Transport.Exchange(ctx, req, netip.AddrPortFrom(server.IP, server.Port), server.Name)
	step.RTT = rtt
	if err != nil {
		step.Kind, step.Err = trace.KindError, err.Error()
		if transport.IsTimeout(err) {
			step.Kind = trace.KindTimeout
		}
		return step
	}

	step.Rcode = dnsutil.RcodeToString(resp.Rcode)
	step.Flags = trace.Flags{
		AA:   resp.Authoritative,
		TC:   resp.Truncated,
		AD:   resp.AuthenticatedData,
		DO:   resp.Security,
		EDNS: resp.UDPSize > 0,
	}
	step.Kind, step.Delegation = classify(resp, zone, r.qname, r.qtype)

	switch step.Kind {
	case trace.KindAnswer, trace.KindCNAME:
		step.Records = records(resp.Answer)
	}
	return step
}

func (r *run) warnf(format string, args ...any) {
	r.trace.Warnings = append(r.trace.Warnings, fmt.Sprintf(format, args...))
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
