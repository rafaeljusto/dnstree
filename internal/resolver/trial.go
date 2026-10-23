package resolver

import (
	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/dnssec"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// supposedDS is the DS set --try-ds gave, as the chain of trust reads one, nil
// where it gave none.
func supposedDS(trial *trace.Trial) []*dns.DS {
	var set []*dns.DS
	for _, given := range trial.DS {
		ds := &dns.DS{}
		ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest = given.Tag, given.Algorithm, given.DigestType, given.Digest
		set = append(set, ds)
	}
	return set
}

// suppose marks the step whose verdict on zone rests on the DS --try-ds gave,
// once the walk comes to the zone that trial replaces.
func (r *run) suppose(chain *dnssec.Chain, step *trace.Step, zone string) {
	r.tried = true
	if r.supposed == nil || chain == nil {
		return
	}
	step.Notes = append(step.Notes, "DS replaced by --try-ds")
	// A DS is only read where the chain above it held, and the walk is no
	// trial of it otherwise.
	if state := chain.State(); state != trace.Secure {
		r.warnOnceIn(trace.AreaDNSSEC, zone, "the chain of trust was already %s above %s, so the DS --try-ds gave was never checked",
			state, zone)
	}
}

// trialFlags names the flags that made trial.
func trialFlags(trial *trace.Trial) string {
	switch {
	case len(trial.NS) > 0 && len(trial.DS) > 0:
		return "--try-ns and --try-ds"
	case len(trial.DS) > 0:
		return "--try-ds"
	}
	return "--try-ns"
}
