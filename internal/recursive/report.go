package recursive

import (
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// bogusCode is the extended error a broken chain of trust is reported as: DNSSEC
// Bogus (RFC 8914). The walk knows more precisely what broke, but not in a way
// that maps onto the codes without claiming more than it checked.
const bogusCode = 6

// Report sends the report a broken chain of trust is due, through send, and
// records it on the trace. Nothing is recorded where nothing was due. An agent
// at or below the name it would be told about is refused, as RFC 9567 says: a
// zone able to answer for its own reports could have them say anything.
func Report(tr *trace.Trace, send func(name string) (string, error)) {
	agent, _ := tr.ReportAgent()
	if agent == "" {
		return
	}
	report := &trace.Report{Agent: agent, Code: bogusCode}
	tr.Report = report

	if below(tr.Question.Name, agent) {
		report.Err = "the agent is at or below the name it would be told about, which RFC 9567 rules out"
		return
	}
	name, ok := transport.ReportName(tr.Question, bogusCode, agent)
	if !ok {
		report.Err = "the report would be longer than a name can be"
		return
	}
	report.Name = name
	rcode, err := send(name)
	if err != nil {
		report.Err = trace.Printable(err.Error(), trace.MaxErr)
		return
	}
	report.Rcode = rcode
}

// below reports whether name is zone or a name inside it, compared the way DNS
// compares names: without regard to case, and label by label.
func below(zone, name string) bool {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return zone == "" || name == zone || strings.HasSuffix(name, "."+zone)
}
