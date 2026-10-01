// Package openmetrics renders a trace as numbers in the OpenMetrics text
// format, for a monitoring system to keep and alert on. It is written once and
// read by a program: a cron job writes it to a file, and node_exporter's
// textfile collector hands it to Prometheus.
package openmetrics

import (
	"bufio"
	"fmt"
	"io"
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
		if !asked(step) {
			continue
		}
		queries++
		if step.Probe != nil && step.Probe.State != trace.ProbeUnchecked {
			continue // a server that refused a probe did its job
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
	seen := map[string]bool{}
	for step := range tr.Mainline() {
		if !asked(step) {
			continue
		}
		hop := []label{
			{"zone", step.Zone},
			{"server", step.Server.Name},
			{"address", address(step.Server)},
			{"asked", step.Asked.Name},
		}
		if key := fmt.Sprint(hop); !seen[key] {
			seen[key] = true
			m.sample("dnstree_hop_seconds", seconds(step.RTT), hop...)
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
	}

	probes(m, tr)
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

// resolvers writes what the recursive servers made of the question, leaving
// out the ones that did not answer: a time for them would read as a fast one.
func resolvers(m *metrics, tr *trace.Trace) {
	// The zone's TTL is what a resolver's is read against: one above it is a
	// resolver keeping the answer longer than the zone allows.
	if zone := tr.Allowed(); zone > 0 {
		m.family("dnstree_answer_ttl_seconds", "seconds", "the TTL the zone gives the answer")
		m.sample("dnstree_answer_ttl_seconds", strconv.FormatUint(uint64(zone), 10))
	}

	var timed, compared, kept []*trace.Resolver
	for _, answer := range tr.Resolvers {
		if answer == nil || !answer.Server.IP.IsValid() || answer.Err != "" {
			continue
		}
		timed = append(timed, answer)
		if answer.Match != "" {
			compared = append(compared, answer)
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
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(value)
}

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

// asked reports whether a step is a query: the zone a trace starts from, a
// server never asked and a note about why the walk stopped are not.
func asked(step *trace.Step) bool {
	return step.Kind != trace.KindZone && step.Kind != trace.KindSkipped && step.Server.IP.IsValid()
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
