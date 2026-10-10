package resolver

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/dnssec"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// unowned reads an NXDOMAIN for what is missing and who says so: the name at
// the end of any alias chain the answer carries (RFC 6604), and the zone whose
// SOA made the denial. That is not always the zone the server was asked as — a
// server of a parent and a child answers for the child across the cut — and
// naming the parent would name a registered domain as free. A denial with no
// SOA, or one whose SOA the name is not under, says nothing about whose it is.
//
// Where the answer followed an alias to get there, the alias is named too.
func unowned(resp *dns.Msg, zone, qname string) *trace.Dangling {
	owner, name := "", qname
	for range resp.Answer {
		target := ""
		for _, rr := range resp.Answer {
			if cname, ok := rr.(*dns.CNAME); ok && dns.EqualName(cname.Hdr.Name, name) {
				target = dnsutil.Fqdn(cname.Target)
				break
			}
		}
		if target == "" {
			break
		}
		owner, name = name, target
	}

	for _, rr := range resp.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		denier := soa.Hdr.Name
		if !dnsutil.IsBelow(zone, denier) || !dnsutil.IsBelow(denier, name) || dns.EqualName(denier, name) {
			return nil
		}
		missing := &trace.Dangling{
			Target:  name,
			Missing: ancestor(name, dnsutil.Labels(denier)+1),
			Zone:    denier,
		}
		if owner != "" {
			missing.Kind, missing.Name = trace.DanglingAlias, owner
		}
		return missing
	}
	return nil
}

// denied is what an NXDOMAIN said is missing, with the hop that said so and
// the chain of trust it was checked against, for whoever claims it.
type denied struct {
	missing *trace.Dangling
	hop     *hop
	chain   *dnssec.Chain
}

// claim marks what a step said is missing as something name was left pointing
// at, where it is. A name missing inside home, the zone that name is served
// from, is only the owner's to create, so nobody else can take anything over
// with it.
func (r *run) claim(ctx context.Context, step *trace.Step, d denied, kind trace.DanglingKind, name, home string) {
	missing := d.missing
	if missing == nil || step.Dangling != nil || dnsutil.IsBelow(home, missing.Missing) || !r.vacant(ctx, d) {
		return
	}
	missing.Kind, missing.Name = kind, name
	step.Dangling = missing
}

// vacant reports whether the name directly below the denying zone is missing
// too. An NXDOMAIN says nothing about the names above the one asked: a target
// missing under a name somebody holds is the holder's to create, not a
// stranger's. So that name is asked of the same server, and checked like the
// denial was.
func (r *run) vacant(ctx context.Context, d denied) bool {
	missing := d.missing
	if dns.EqualName(missing.Missing, missing.Target) {
		return true
	}
	if r.counters.query() != nil {
		return false
	}
	asked := d.hop.step
	hop := r.query(ctx, asked.Zone, asked.Server, missing.Missing, dns.TypeNS)
	// The question is dnstree's own, not the run's: a verdict on it costs the
	// claim, never the chain of trust or the exit code.
	hop.step.Aside, hop.step.Apart = true, true
	hop.step.Notes = append(hop.step.Notes, "NS of "+missing.Missing+", to see if it exists")
	r.attach(asked, hop.step)

	if hop.resp == nil || hop.resp.Rcode != dns.RcodeNameError {
		return false
	}
	if d.chain != nil {
		hop.step.DNSSEC = d.chain.Verify(hop.resp.Answer, hop.resp.Ns, hop.resp.Rcode, missing.Missing, dns.TypeNS)
		return hop.step.DNSSEC.State != trace.Bogus
	}
	return true
}

// orphan hands over what a step said is missing, once, to the walk that went
// looking for it: a nameserver's name, or an alias's target. What nobody claims
// is only a name that is not there.
func (r *run) orphan(step *trace.Step) denied {
	d := r.missing[step]
	delete(r.missing, step)
	return d
}

// abandoned marks the zone every one of whose nameservers answered without
// authority for it. That is what a hosting service says of a zone nobody has
// created in it, and at a service where anybody can, whoever does answers for
// the zone. It is said only where every name the parent delegated to was
// asked, and every address of each of them was lame. The hops hang under
// parent, which is the referral itself unless the walk has been minimising.
func abandoned(referred, parent *trace.Step, zone string) {
	delegation := referred.Delegation
	if delegation == nil || len(delegation.NS) == 0 {
		return
	}

	asked := make(map[string]bool)
	for _, step := range parent.Children {
		if step.Aside || !dns.EqualName(step.Zone, zone) {
			continue
		}
		if step.Kind != trace.KindLame {
			return
		}
		asked[dnsutil.Canonical(step.Server.Name)] = true
	}
	for _, name := range delegation.NS {
		if !asked[dnsutil.Canonical(name)] {
			return
		}
	}
	referred.Dangling = &trace.Dangling{Kind: trace.DanglingLame, Name: delegation.Zone}
}

// denial keeps what an NXDOMAIN a walk ended on says is missing, for the walk
// that asked to claim. A denial the chain of trust found forged is nobody's
// word, and one that followed an alias to get there is claimed on the spot.
func (r *run) denial(ctx context.Context, chain *dnssec.Chain, hop *hop, zone, qname string) {
	step := hop.step
	if step.Kind != trace.KindNXDomain || hop.resp == nil {
		return
	}
	if step.DNSSEC != nil && step.DNSSEC.State == trace.Bogus {
		return
	}
	missing := unowned(hop.resp, zone, qname)
	d := denied{missing: missing, hop: hop, chain: chain}
	switch {
	case missing == nil:
	case missing.Kind == trace.DanglingAlias:
		r.claim(ctx, step, d, missing.Kind, missing.Name, zone)
	default:
		r.missing[step] = d
	}
}
