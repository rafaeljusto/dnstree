package tree

import (
	"fmt"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// requests draws what the zones on the walk ask their parents to change: what
// a CSYNC would have copied, and whether a parent would bootstrap a first DS.
// The lookups behind them are in the tree.
func (r *renderer) requests(tr *trace.Trace) []string {
	var lines []string
	for _, request := range tr.Requests() {
		lines = append(lines, r.csync(request.Zone, request.CSYNC)...)
		lines = append(lines, r.bootstrap(request.Zone, request.Signal)...)
	}
	return lines
}

func (r *renderer) csync(zone string, csync *trace.CSYNC) []string {
	if csync == nil {
		return nil
	}
	mark := "csync: "
	if r.glyphs.icons {
		mark = spaced("🔄")
	}

	record := fmt.Sprintf("%s CSYNC %d", zone, csync.Serial)
	if csync.Immediate {
		record += " immediate"
	}
	if csync.SOAMinimum {
		record += " soaminimum"
	}
	if len(csync.Types) > 0 {
		record += " " + strings.Join(csync.Types, " ")
	}
	var verdict string
	switch csync.State {
	case trace.CSYNCReady:
		verdict = r.paint.paint("a parent that polls copies it", green)
	case trace.CSYNCManual:
		verdict = r.paint.dim("waits for the parent to approve it")
	case trace.CSYNCWaiting:
		verdict = r.paint.paint("waiting: "+csync.Reason, yellow)
	case trace.CSYNCUnproven:
		verdict = r.paint.paint("unproven: "+csync.Reason, yellow)
	default:
		verdict = r.paint.dim("unchecked: " + csync.Reason)
	}
	lines := []string{join(r.paint.dim(mark+record), verdict)}

	for _, change := range csync.Changes {
		verb := "removes"
		if change.Add {
			verb = "adds"
		}
		text := mark + "  " + verb + " " + change.Type + " " + change.Name
		if change.Data != "" {
			text = mark + "  " + verb + " " + change.Type + " " + change.Data + " for " + change.Name
		}
		lines = append(lines, r.paint.dim(text))
	}
	if len(csync.Changes) == 0 && len(csync.Types) > 0 {
		lines = append(lines, r.paint.dim(mark+"  the delegation already holds what it asks for"))
	}
	return lines
}

func (r *renderer) bootstrap(zone string, signal *trace.Signal) []string {
	if signal == nil || signal.Bootstrap == nil {
		return nil
	}
	b := signal.Bootstrap
	mark := "bootstrap: "
	if r.glyphs.icons {
		mark = spaced("🌱")
	}

	var verdict string
	switch b.State {
	case trace.BootstrapReady:
		verdict = r.paint.paint("every operator vouches for it", green)
	case trace.BootstrapRefused:
		verdict = r.paint.paint("refused: "+b.Reason, yellow)
	default:
		verdict = r.paint.dim("unchecked: " + b.Reason)
	}
	lines := []string{join(r.paint.dim(mark+zone+" asks for its first ds, for "+tags(signal.Requested)), verdict)}

	for _, s := range b.Signals {
		text := mark + "  " + s.NS + " " + string(s.State)
		if s.State != trace.SignalingMatched && s.Reason != "" {
			text += ": " + s.Reason
		}
		var status *trace.DNSSECStatus
		if s.Lookup != nil {
			status = s.Lookup.DNSSEC
		}
		switch s.State {
		case trace.SignalingMatched:
			lines = append(lines, join(r.paint.dim(text), r.dnssec(status)))
		case trace.SignalingUnasked:
			lines = append(lines, r.paint.dim(text))
		default:
			lines = append(lines, join(r.paint.paint(text, yellow), r.dnssec(status)))
		}
	}
	return lines
}
