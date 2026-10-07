// Package openmetrics renders a trace as numbers in the OpenMetrics text
// format, for a monitoring system to keep and alert on. It is written once and
// read by a program: a cron job writes it to a file, and node_exporter's
// textfile collector hands it to Prometheus.
package openmetrics

import (
	"bufio"
	"cmp"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Render writes the trace to w as metric families, each labelled with the
// question they are about so that the files of several names can sit side by
// side.
//
// The families are all gauges, a state included as one gauge per value, because
// the textfile collector reads the older Prometheus format and refuses the
// OpenMetrics types it does not know.
func Render(w io.Writer, tr *trace.Trace) error {
	out := bufio.NewWriter(w)
	tr = tr.Shown()
	if tr == nil {
		tr = &trace.Trace{}
	}
	question := []label{{"name", tr.Question.Name}, {"type", tr.Question.Type}}
	m := &metrics{out: out, question: question}

	m.family("dnstree_result", "", "how the walk ended, one of answer, cname, nodata, nxdomain, filtered or none")
	ended := result(tr)
	for _, kind := range []string{"answer", "cname", "nodata", "nxdomain", "filtered", "none"} {
		m.sample("dnstree_result", flag(kind == ended), label{"kind", kind})
	}

	m.family("dnstree_walk_seconds", "seconds", "how long the walk took")
	m.sample("dnstree_walk_seconds", seconds(tr.Elapsed))

	queries, failed := 0, 0
	for step := range tr.Steps() {
		if !step.Queried() {
			continue
		}
		queries++
		if step.Probe != nil && step.Probe.State != trace.ProbeUnchecked {
			continue // a server that refused a probe did its job
		}
		if step.EDNS != nil && step.EDNS.State != trace.EDNSUnchecked {
			continue // dnstree_edns_ok counts a test that went unanswered
		}
		switch step.Kind {
		case trace.KindTimeout, trace.KindError, trace.KindLame:
			failed++
		}
	}
	m.family("dnstree_queries", "", "the queries the walk sent")
	m.sample("dnstree_queries", strconv.Itoa(queries))
	m.family("dnstree_failed_queries", "", "the queries that timed out, failed or reached a lame server")
	m.sample("dnstree_failed_queries", strconv.Itoa(failed))

	m.family("dnstree_hop_seconds", "seconds", "how long each query on the path took, a timeout included")
	// A series is its labels, so a hop that repeats another's is left out: the
	// same server asked the same name twice, which only a loop cut short does.
	seen := map[[4]label]bool{}
	for step := range tr.Mainline() {
		if !step.Queried() {
			continue
		}
		hop := [4]label{
			{"zone", step.Zone},
			{"server", step.Server.Name},
			{"address", address(step.Server)},
			{"asked", step.Asked.Name},
		}
		if !seen[hop] {
			seen[hop] = true
			m.sample("dnstree_hop_seconds", seconds(step.RTT), hop[:]...)
		}
	}

	if step := tr.Chain(); step != nil {
		state := step.DNSSEC.State
		m.family("dnstree_dnssec", "", "how far the chain of trust got, one of secure, insecure, bogus or indeterminate")
		for _, value := range []trace.DNSSECState{trace.Secure, trace.Insecure, trace.Bogus, trace.Indeterminate} {
			m.sample("dnstree_dnssec", flag(value == state), label{"state", string(value)})
		}
	}

	if soonest := tr.Soonest(); soonest != nil {
		if left, ok := tr.Left(soonest.DNSSEC); ok {
			m.family("dnstree_signature_left_seconds", "seconds", "how long the first signature to run out had left when the walk was made")
			m.sample("dnstree_signature_left_seconds", seconds(left))
		}
	}

	if signal := signal(tr); signal != nil {
		m.family("dnstree_cds", "", "what the zone asks its parent to publish, held against the DS it holds")
		for _, value := range []trace.SignalState{
			trace.SignalNone, trace.SignalMatch, trace.SignalPending,
			trace.SignalDelete, trace.SignalInconsistent, trace.SignalUnchecked,
		} {
			m.sample("dnstree_cds", flag(value == signal.State), label{"state", string(value)})
		}
		// A pending request from a zone with no DS is a first one, not a
		// rollover, and whether a parent would take it is a series of its own.
		if boot := signal.Bootstrap; boot != nil {
			m.family("dnstree_bootstrap", "", "whether a parent that bootstraps (RFC 9615) would add the first DS the zone asks for")
			for _, value := range []trace.BootstrapState{trace.BootstrapReady, trace.BootstrapRefused, trace.BootstrapUnchecked} {
				m.sample("dnstree_bootstrap", flag(value == boot.State), label{"state", string(value)})
			}
		}
	}

	// --check-ns asks only the zone the walk ended in, the last to ask.
	var csync *trace.CSYNC
	for _, request := range tr.Requests() {
		csync = cmp.Or(request.CSYNC, csync)
	}
	if csync != nil {
		m.family("dnstree_csync", "", "what the zone's CSYNC (RFC 7477) comes to, held against the delegation")
		for _, value := range []trace.CSYNCState{trace.CSYNCReady, trace.CSYNCManual, trace.CSYNCWaiting, trace.CSYNCUnproven, trace.CSYNCUnchecked} {
			m.sample("dnstree_csync", flag(value == csync.State), label{"state", string(value)})
		}
		m.family("dnstree_csync_changes", "", "how many records of the delegation a parent acting on the CSYNC would add or remove")
		m.sample("dnstree_csync_changes", strconv.Itoa(len(csync.Changes)))
	}

	if caa := tr.CAA; caa != nil {
		state := "open"
		switch {
		case caa.Refused != "":
			state = "refused"
		case caa.Undecided != "":
			state = "undecided"
		case caa.Issue != nil:
			state = "restricted"
		}
		m.family("dnstree_caa", "", "who the CAA set lets issue certificates for the name: restricted to the authorities it names, open to any, refused by every authority, or undecided where a lookup failed")
		for _, value := range []string{"restricted", "open", "refused", "undecided"} {
			m.sample("dnstree_caa", flag(value == state), label{"state", value})
		}
	}

	if spf := tr.SPF; spf != nil {
		m.family("dnstree_spf_lookups", "", "the DNS lookups the name's SPF policy costs a check, which is allowed 10; past them every check is a permerror")
		m.sample("dnstree_spf_lookups", strconv.Itoa(spf.Lookups))
		m.family("dnstree_spf", "", "what an SPF check of mail sent as the name comes to before the sender is known")
		for _, value := range []trace.SPFResult{
			trace.SPFOK, trace.SPFNone, trace.SPFPermError, trace.SPFTempError, trace.SPFUndecided,
		} {
			m.sample("dnstree_spf", flag(value == spf.Result), label{"result", string(value)})
		}
	}

	if mail := tr.Mail; mail != nil {
		dane, hosts := mail.Covered()
		m.family("dnstree_mail_hosts", "", "the MX hosts mail to the name can be delivered to")
		m.sample("dnstree_mail_hosts", strconv.Itoa(hosts))
		// Without --dnssec, or past the budget, nothing was checked, and a
		// count of none would say it had been.
		if !mail.Cut && !slices.ContainsFunc(mail.Hosts, func(h trace.MailHost) bool { return h.DANE == trace.DANEUnchecked }) {
			m.family("dnstree_mail_dane_hosts", "", "the MX hosts a sender that checks DANE authenticates, by a signed TLSA set it can use")
			m.sample("dnstree_mail_dane_hosts", strconv.Itoa(dane))
		}
		// Only --tlsa connects, and a count of none would say it had.
		counted := map[trace.PresentedState]int{}
		for _, host := range mail.Hosts {
			for _, p := range host.Presented {
				counted[p.State]++
			}
		}
		if len(counted) > 0 {
			m.family("dnstree_mail_tlsa_addresses", "", "the MX host addresses --tlsa connected to, by what their certificate came to: match, mismatch where a sender that checks DANE refuses it, or unreached")
			for _, state := range []trace.PresentedState{trace.PresentedMatch, trace.PresentedMismatch, trace.PresentedUnreached} {
				m.sample("dnstree_mail_tlsa_addresses", strconv.Itoa(counted[state]), label{"state", string(state)})
			}
		}
		m.family("dnstree_mail_policy", "", "what the lookup of each mail policy came to: published, none, invalid where a sender reads it as none, or failed")
		for _, p := range []struct {
			name   string
			policy *trace.MailPolicy
		}{{"mta-sts", mail.MTASTS}, {"tls-rpt", mail.TLSRPT}, {"dmarc", mail.DMARC}} {
			if p.policy == nil {
				continue
			}
			for _, value := range []trace.PolicyFound{trace.PolicyPublished, trace.PolicyNone, trace.PolicyInvalid, trace.PolicyFailed} {
				m.sample("dnstree_mail_policy", flag(value == p.policy.Found), label{"policy", p.name}, label{"found", string(value)})
			}
		}
	}

	if path := tr.ServicePath; path != nil {
		reachable, stray := 0, 0
		for _, target := range path.Targets {
			if len(target.Addrs) > 0 {
				reachable++
			}
			stray += len(target.Stray)
		}
		m.family("dnstree_svcb_targets", "", "the servers the name's HTTPS or SVCB records lead a client to that have an address")
		m.sample("dnstree_svcb_targets", strconv.Itoa(reachable))
		// Past the budget the hints were not all judged, and a count of none
		// would say they had been.
		if !path.Cut {
			m.family("dnstree_svcb_stray_hints", "", "the address hints in the name's HTTPS or SVCB records that are none of their target's addresses")
			m.sample("dnstree_svcb_stray_hints", strconv.Itoa(stray))
		}
	}

	if reg := tr.Registration; reg != nil {
		m.family("dnstree_registration", "", "what the registry said about the domain over RDAP: registered, unregistered, unpublished where the TLD runs no RDAP service, or unreached")
		for _, value := range []trace.RegistrationState{trace.Registered, trace.Unregistered, trace.Unpublished, trace.Unreached} {
			m.sample("dnstree_registration", flag(value == reg.State), label{"domain", reg.Domain}, label{"state", string(value)})
		}
		if left, ok := tr.Lapses(reg); ok {
			m.family("dnstree_registration_left_seconds", "seconds", "how long the domain's registration had left when the walk was made, below zero once it has run out")
			m.sample("dnstree_registration_left_seconds", seconds(left), label{"domain", reg.Domain})
		}
		if reg.State == trace.Registered {
			m.family("dnstree_registration_held", "", "1 where the registry lists a status that takes the domain out of its zone, such as a hold or a pending delete")
			m.sample("dnstree_registration_held", flag(reg.Held() != ""), label{"domain", reg.Domain})
		}
		if reg.Parent != "" {
			m.family("dnstree_registration_agrees", "", "1 where the registry holds the nameservers, and with --dnssec the DS, that the zone above hands out")
			m.sample("dnstree_registration_agrees", flag(reg.Agrees()), label{"domain", reg.Domain})
		}
	}

	probes(m, tr)
	ednsTests(m, tr)
	resolvers(m, tr)

	m.family("dnstree_warnings", "", "what the walk could not do")
	m.sample("dnstree_warnings", strconv.Itoa(len(tr.Warnings)))

	m.write("# EOF\n")
	return out.Flush()
}

// probes writes what --check-axfr and --check-recursion found, one sample per
// nameserver and check. A server that could not be asked is left out: a zero
// for it would read as one that refused.
func probes(m *metrics, tr *trace.Trace) {
	var found []*trace.Step
	for step := range tr.Steps() {
		if step.Probe != nil && step.Probe.State != trace.ProbeUnchecked {
			found = append(found, step)
		}
	}
	if len(found) == 0 {
		return
	}
	m.family("dnstree_open", "", "whether a nameserver of the zone gave a stranger what it should not: the whole zone (transfer), or a lookup of another name (recursion)")
	for _, step := range found {
		m.sample("dnstree_open", flag(step.Probe.State == trace.ProbeOpen),
			label{"check", string(step.Probe.Kind)},
			label{"zone", step.Zone},
			label{"server", step.Server.Name},
			label{"address", address(step.Server)})
	}
}

// ednsTests writes what --check-edns found, one sample per nameserver and
// shape. A server that did not answer the baseline is left out: a zero for it
// would read as one that answered wrongly.
func ednsTests(m *metrics, tr *trace.Trace) {
	var found []*trace.Step
	for step := range tr.Steps() {
		if step.EDNS != nil && step.EDNS.State != trace.EDNSUnchecked {
			found = append(found, step)
		}
	}
	if len(found) == 0 {
		return
	}
	m.family("dnstree_edns_ok", "", "whether a nameserver of the zone answered an RFC 8906 test as EDNS says it must: EDNS0 alone (edns), version 1 (version), an unknown option (option) or an unknown flag (flag)")
	for _, step := range found {
		m.sample("dnstree_edns_ok", flag(step.EDNS.State == trace.EDNSOK),
			label{"test", string(step.EDNS.Kind)},
			label{"zone", step.Zone},
			label{"server", step.Server.Name},
			label{"address", address(step.Server)})
	}
}

// resolvers writes what the recursive servers made of the question, leaving
// out the ones that did not answer: a time for them would read as a fast one.
func resolvers(m *metrics, tr *trace.Trace) {
	// The zone's TTL is what a resolver's is read against: one above it is a
	// resolver keeping the answer longer than the zone allows.
	if zone := tr.Allowed(); zone > 0 {
		m.family("dnstree_answer_ttl_seconds", "seconds", "the TTL the zone gives the answer")
		m.sample("dnstree_answer_ttl_seconds", strconv.FormatUint(uint64(zone), 10))
	}

	var timed, compared, kept, failed []*trace.Resolver
	for _, answer := range tr.Resolvers {
		if answer == nil || !answer.Server.IP.IsValid() || answer.Err != "" {
			continue
		}
		timed = append(timed, answer)
		if answer.Match != "" {
			compared = append(compared, answer)
		}
		if answer.Failed != "" {
			failed = append(failed, answer)
		}
		if trace.TTL(answer.Records, tr.Question.Type) > 0 {
			kept = append(kept, answer)
		}
	}

	if len(timed) > 0 {
		m.family("dnstree_resolver_seconds", "seconds", "how long each recursive server took to answer the same question")
		for _, answer := range timed {
			m.sample("dnstree_resolver_seconds", seconds(answer.Elapsed), label{"resolver", answer.Server.IP.String()})
		}
	}
	if len(compared) > 0 {
		m.family("dnstree_resolver_agrees", "", "whether each recursive server answered what the walk found")
		for _, answer := range compared {
			m.sample("dnstree_resolver_agrees", flag(answer.Match == trace.MatchSame), label{"resolver", answer.Server.IP.String()})
		}
	}
	if len(kept) > 0 {
		m.family("dnstree_resolver_ttl_seconds", "seconds", "the TTL each recursive server handed its answer out with")
		for _, answer := range kept {
			m.sample("dnstree_resolver_ttl_seconds", strconv.FormatUint(uint64(trace.TTL(answer.Records, tr.Question.Type)), 10),
				label{"resolver", answer.Server.IP.String()})
		}
	}
	if len(failed) > 0 {
		m.family("dnstree_resolver_failed", "", "what a recursive server's SERVFAIL most likely came of, where the walk found an answer")
		for _, answer := range failed {
			for _, value := range []trace.Failure{
				trace.FailedBogus, trace.FailedValidation, trace.FailedCached, trace.FailedUnreachable,
			} {
				m.sample("dnstree_resolver_failed", flag(value == answer.Failed),
					label{"resolver", answer.Server.IP.String()}, label{"reason", string(value)})
			}
		}
	}
}

type label struct{ name, value string }

type metrics struct {
	out      *bufio.Writer
	question []label
}

// family opens a metric family. OpenMetrics wants a unit to be the end of the
// name as well as said on its own line.
func (m *metrics) family(name, unit, help string) {
	m.write("# TYPE " + name + " gauge\n")
	if unit != "" {
		m.write("# UNIT " + name + " " + unit + "\n")
	}
	m.write("# HELP " + name + " " + help + "\n")
}

func (m *metrics) sample(name, value string, labels ...label) {
	pairs := make([]string, 0, len(m.question)+len(labels))
	for _, l := range append(m.question[:len(m.question):len(m.question)], labels...) {
		pairs = append(pairs, l.name+`="`+escape(l.value)+`"`)
	}
	m.write(name + "{" + strings.Join(pairs, ",") + "} " + value + "\n")
}

// write adds to the output. A bufio writer holds the first error it meets until
// Flush, which is what Render returns.
func (m *metrics) write(text string) {
	_, _ = m.out.WriteString(text)
}

// escape is a label value as both formats read it. The names are escaped
// already, so a backslash here is the start of one of their \DDD.
func escape(value string) string {
	return escaped.Replace(value)
}

var escaped = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// result is how the walk ended, in the words the summary under the tree uses.
func result(tr *trace.Trace) string {
	if step := tr.Result(); step != nil {
		return string(step.Kind)
	}
	if tr.Filtered() != nil {
		return "filtered"
	}
	return "none"
}

// signal is the request --check-ds read off the zone the walk ended in.
func signal(tr *trace.Trace) *trace.Signal {
	for step := range tr.Steps() {
		if step.DNSSEC != nil && step.DNSSEC.Signal != nil {
			return step.DNSSEC.Signal
		}
	}
	return nil
}

func address(server trace.Server) string {
	if !server.IP.IsValid() {
		return ""
	}
	return server.IP.String()
}

func seconds(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', -1, 64)
}

func flag(on bool) string {
	if on {
		return "1"
	}
	return "0"
}
