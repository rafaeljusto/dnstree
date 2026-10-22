package resolver

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// confirm looks up the addresses of every name the PTR set the walk ended on
// gives, in the family of the address the question stands for, to see which
// of them point back to it: forward-confirmed reverse DNS. Every lookup is a
// walk of its own, drawn as an aside under under.
func (r *run) confirm(ctx context.Context, under, end *trace.Step) {
	addr, qtype := r.cfg.Confirm, dns.TypeA
	if addr.Is6() {
		qtype = dns.TypeAAAA
	}

	r.aside, r.asideStopped = true, false
	defer func() { r.aside = false }()

	c := &trace.Reverse{Addr: addr, PTR: ended(r.trace.Question.Name, r.trace.Root, end)}
	r.trace.Reverse = c
	if !c.PTR.Answered() || end.Minimised {
		return
	}

	seen := map[string]bool{}
	for _, record := range end.Records {
		if record.Type != "PTR" || !dns.EqualName(record.Name, end.Asked.Name) || seen[dnsutil.Canonical(record.Data)] {
			continue
		}
		seen[dnsutil.Canonical(record.Data)] = true
		c.Names = append(c.Names, trace.ReverseName{Name: record.Data})
	}

	for i := range c.Names {
		name := &c.Names[i]
		result, lookup, stopped := r.look(ctx, under, name.Name, qtype, "the reverse check")
		name.Lookup = lookup
		if stopped || !lookup.Answered() {
			continue
		}
		for _, record := range result.Records {
			if record.Type != dnsutil.TypeToString(qtype) || !dns.EqualName(record.Name, result.Asked.Name) {
				continue
			}
			if found, err := netip.ParseAddr(record.Data); err == nil && !slices.Contains(name.Addrs, found) {
				name.Addrs = append(name.Addrs, found)
			}
		}
	}
	c.Cut = r.asideStopped
	r.warnReverse(c, dnsutil.TypeToString(qtype))
}

// warnReverse says what keeps the address from being forward-confirmed.
func (r *run) warnReverse(c *trace.Reverse, qtype string) {
	if c.Cut {
		r.warnf("", "the reverse check of %s ran out of budget before every name was looked up; raise the budget that ran out", c.Addr)
	}
	var elsewhere []string
	for _, name := range c.Names {
		switch {
		case name.Lookup.DNSSEC != nil && name.Lookup.DNSSEC.State == trace.Bogus:
			r.warnf(trace.AreaMail, "the %s set of %s, which the PTR of %s names, does not validate (%s), so a receiver that validates cannot confirm it; fix the signatures of its zone",
				qtype, name.Name, c.Addr, name.Lookup.DNSSEC.Reason)
		case name.Lookup.Err != "" && !c.Cut:
			r.warnf(trace.AreaMail, "the %s lookup of %s, which the PTR of %s names, failed (%s), so a receiver cannot confirm it; fix the servers of its zone",
				qtype, name.Name, c.Addr, name.Lookup.Err)
		case name.Lookup.Err == "" && !name.Back(c.Addr):
			elsewhere = append(elsewhere, name.Name)
		}
	}
	if len(elsewhere) > 0 && !c.Confirmed() {
		r.warnf(trace.AreaMail, "%s, which the PTR of %s names, %s not point back to it, so a mail receiver that checks forward-confirmed reverse DNS distrusts it; give %s the address or point the PTR at a name that has it",
			strings.Join(elsewhere, ", "), c.Addr, verb(elsewhere, "does", "do"), verb(elsewhere, "the name", "a name"))
	}
}
