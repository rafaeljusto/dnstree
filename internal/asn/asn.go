// Package asn annotates server addresses with their origin AS, looked up in the
// Team Cymru DNS zones. The lookups are best effort: a trace is worth reading
// without them, so nothing here ever fails a resolution.
package asn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rafaeljusto/dnstree/internal/trace"
)

const (
	// The zones Team Cymru answers origin questions in.
	zoneIPv4 = "origin.asn.cymru.com."
	zoneIPv6 = "origin6.asn.cymru.com."

	// maxParallel bounds the lookups, which all go to the same service.
	maxParallel = 8
)

// Lookup fetches the TXT records of a name. It is the seam tests answer through
// and, by default, the system resolver: the Cymru zones need a recursive server,
// which is exactly what the host already has.
type Lookup func(ctx context.Context, name string) ([]string, error)

// Resolver looks up origin AS numbers, remembering every address it has seen so
// that a nameserver appearing at several hops is asked about once.
type Resolver struct {
	lookup Lookup
	log    *slog.Logger
	limit  chan struct{}
	wait   sync.WaitGroup

	mu      sync.Mutex
	started map[netip.Addr]bool
	cached  map[netip.Addr]*trace.ASNInfo
	failure error
}

// New returns a resolver. A nil lookup uses the host's own resolver, and a nil
// log keeps quiet.
func New(lookup Lookup, log *slog.Logger) *Resolver {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Resolver{
		lookup:  lookup,
		log:     log,
		limit:   make(chan struct{}, maxParallel),
		started: make(map[netip.Addr]bool),
		cached:  make(map[netip.Addr]*trace.ASNInfo),
	}
}

// Start begins looking an address up, unless it has been asked about already.
// Calling it while a walk is still going is the whole point: the lookups then
// happen behind the walk instead of after it, where every one of them is time
// somebody waits for.
func (r *Resolver) Start(ctx context.Context, addr netip.Addr) {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return
	}

	r.mu.Lock()
	if r.started[addr] {
		r.mu.Unlock()
		return
	}
	r.started[addr] = true
	r.mu.Unlock()

	r.wait.Go(func() {
		r.limit <- struct{}{}
		defer func() { <-r.limit }()

		// Logged on the way in as well as out: a lookup that never comes back
		// is exactly the one worth seeing.
		r.log.Debug("asking for an origin AS", "address", addr)

		started := time.Now()
		info, err := r.Lookup(ctx, addr)
		r.log.Debug("looked up an origin AS",
			"address", addr, "took", time.Since(started), "found", info != nil, "error", err)

		if err != nil {
			r.mu.Lock()
			defer r.mu.Unlock()
			// One address nobody can answer for says nothing about the next.
			if r.failure == nil {
				r.failure = err
			}
		}
	})
}

// Annotate fills in the origin AS of every server a trace actually asked, and
// waits for the lookups still in flight — but only as long as ctx allows. The
// trace is already complete: this is metadata, and nobody should wait long for
// it. An address nothing can be found for is simply left without one; it is
// only when none of them can be found that the trace is told, since that means
// the lookups themselves are not working.
func (r *Resolver) Annotate(ctx context.Context, tr *trace.Trace) {
	if tr == nil {
		return
	}

	asked := 0
	for step := range tr.Steps() {
		if queried(step) {
			r.Start(ctx, step.Server.IP)
			asked++
		}
	}
	if asked == 0 {
		return
	}

	done := make(chan struct{})
	go func() {
		r.wait.Wait()
		close(done)
	}()

	waited := time.Now()
	var abandoned bool
	select {
	case <-done:
	case <-ctx.Done():
		abandoned = true // the stragglers are not worth the wait
	}
	r.log.Debug("waited for the origin AS lookups",
		"took", time.Since(waited), "abandoned", abandoned)

	r.mu.Lock()
	defer r.mu.Unlock()

	found := 0
	for step := range tr.Steps() {
		if info := r.cached[step.Server.IP.Unmap()]; info != nil {
			step.Server.ASN = info
			found++
		}
	}
	// Saying nothing would leave a reader wondering where the AS numbers went.
	switch {
	case found > 0:
	case r.failure != nil:
		tr.Warnings = append(tr.Warnings,
			"the origin AS lookups did not get through ("+reason(r.failure)+"); --no-asn skips them")
	case abandoned:
		tr.Warnings = append(tr.Warnings,
			"the origin AS lookups did not answer in time; --no-asn skips them")
	}
}

// queried reports whether a step is a hop the walk really made. A server it
// only listed as an alternative was never spoken to, and is not worth asking a
// second service about.
func queried(step *trace.Step) bool {
	switch step.Kind {
	case trace.KindZone, trace.KindSkipped:
		return false
	}
	return step.Server.IP.IsValid()
}

// reason is the short form of a lookup failure. The whole chain carries the
// query name twice over, and a reader can act on none of it: what they need is
// which resolver failed them, and how.
func reason(err error) string {
	var failure *net.DNSError
	if errors.As(err, &failure) && failure.Err != "" {
		return failure.Err
	}
	return err.Error()
}

// Lookup returns the origin AS of one address, from the cache when it can.
func (r *Resolver) Lookup(ctx context.Context, addr netip.Addr) (*trace.ASNInfo, error) {
	addr = addr.Unmap()

	r.mu.Lock()
	cached, seen := r.cached[addr]
	r.mu.Unlock()
	if seen {
		return cached, nil
	}

	name, err := queryName(addr)
	if err != nil {
		return nil, err
	}
	records, err := r.lookup(ctx, name)
	if err != nil {
		// An address nothing announces has no record, which is an answer
		// rather than a failure.
		var notFound *net.DNSError
		if !errors.As(err, &notFound) || !notFound.IsNotFound {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}

	info := parse(records)
	r.mu.Lock()
	r.cached[addr] = info // a miss is worth remembering too
	r.mu.Unlock()
	return info, nil
}

// queryName is the name that carries the origin of an address: the address
// backwards, a label at a time for IPv4 and a nibble at a time for IPv6.
func queryName(addr netip.Addr) (string, error) {
	addr = addr.Unmap()
	switch {
	case !addr.IsValid():
		return "", fmt.Errorf("asn: %s is not an address", addr)
	case addr.Is4():
		octets := addr.As4()
		labels := make([]string, 0, len(octets))
		for i := len(octets) - 1; i >= 0; i-- {
			labels = append(labels, strconv.Itoa(int(octets[i])))
		}
		return strings.Join(labels, ".") + "." + zoneIPv4, nil
	default:
		octets := addr.As16()
		const hex = "0123456789abcdef"
		nibbles := make([]string, 0, 2*len(octets))
		for i := len(octets) - 1; i >= 0; i-- {
			nibbles = append(nibbles,
				string(hex[octets[i]&0x0f]),
				string(hex[octets[i]>>4]))
		}
		return strings.Join(nibbles, ".") + "." + zoneIPv6, nil
	}
}

// parse reads the records Cymru answers with, which look like
//
//	15169 | 8.8.8.0/24 | US | arin | 1992-12-01
//
// An address inside more than one announced prefix gets a record for each, and
// the most specific of them is the one that says who really answers for it.
func parse(records []string) *trace.ASNInfo {
	var (
		best   *trace.ASNInfo
		length = -1
	)
	for _, record := range records {
		info := parseRecord(record)
		if info == nil {
			continue
		}
		if bits := prefixLength(info.Prefix); bits > length {
			best, length = info, bits
		}
	}
	return best
}

func parseRecord(record string) *trace.ASNInfo {
	fields := strings.Split(record, "|")
	if len(fields) < 2 {
		return nil
	}
	for i, field := range fields {
		fields[i] = strings.TrimSpace(field)
	}

	// The first field holds every AS announcing the prefix, space separated.
	origins := strings.Fields(fields[0])
	if len(origins) == 0 {
		return nil
	}
	number, err := strconv.ParseUint(origins[0], 10, 32)
	if err != nil {
		return nil
	}

	info := &trace.ASNInfo{Number: uint32(number), Prefix: fields[1]}
	for i, field := range []*string{&info.CountryCode, &info.Registry, &info.Allocated} {
		if len(fields) > i+2 {
			*field = fields[i+2]
		}
	}
	return info
}

// prefixLength is how specific a prefix is, or -1 when it is not one at all.
func prefixLength(prefix string) int {
	parsed, err := netip.ParsePrefix(prefix)
	if err != nil {
		return -1
	}
	return parsed.Bits()
}
