package tree

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// requests draws what the zones on the walk ask their parents to change: what
// a CSYNC would have copied, whether a parent would bootstrap a first DS, and
// where the parent takes notice of either. The lookups behind them are in the
// tree.
func (r *renderer) requests(tr *trace.Trace) []string {
	var lines []string
	for _, request := range tr.Requests() {
		lines = append(lines, r.csync(request.Zone, request.CSYNC)...)
		lines = append(lines, r.bootstrap(request.Zone, request.Signal)...)
		lines = append(lines, r.dsync(request.Zone, request.DSYNC)...)
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

func (r *renderer) dsync(zone string, d *trace.DSYNC) []string {
	if d == nil {
		return nil
	}
	mark := "dsync: "
	if r.glyphs.icons {
		mark = spaced("📮")
	}

	switch d.State {
	case trace.DSYNCNone:
		text := mark + d.Parent + " names nowhere to send a notice about " + zone + ", so a change waits for its next scan"
		if d.Reason != "" {
			text += " (" + d.Reason + ")"
		}
		return []string{r.paint.dim(text)}
	case trace.DSYNCBogus:
		return []string{r.paint.paint(mark+"where "+d.Parent+" takes notices about "+zone+" is bogus: "+d.Reason, yellow)}
	case trace.DSYNCUnchecked:
		return []string{r.paint.dim(mark + "where " + d.Parent + " takes notices about " + zone + " is unchecked: " + d.Reason)}
	}

	var status *trace.DNSSECStatus
	if len(d.Lookups) > 0 {
		status = d.Lookups[len(d.Lookups)-1].DNSSEC
	}
	header := mark + d.Parent + " takes notices about " + zone + " at " + d.Name
	if !slices.ContainsFunc(d.Endpoints, func(e trace.DSYNCEndpoint) bool { return e.Ignored == "" }) {
		header = mark + d.Parent + " publishes DSYNC records for " + zone + " at " + d.Name + ", but none a notifier uses"
	}
	lines := []string{join(r.paint.dim(header), r.dnssec(status))}
	var ignored []string
	for _, e := range d.Endpoints {
		text := fmt.Sprintf("%s  %s %s %s port %d", mark, e.Type, e.Scheme, e.Target, e.Port)
		switch {
		case e.Ignored != "":
			ignored = append(ignored, r.paint.dim(text+" ignored: "+e.Ignored))
		case len(e.Addrs) > 0:
			addrs := make([]string, len(e.Addrs))
			for i, addr := range e.Addrs {
				addrs[i] = addr.String()
			}
			lines = append(lines, join(r.paint.dim(text), strings.Join(addrs, ", ")))
		case answered(e.IPv4) && answered(e.IPv6):
			lines = append(lines, r.paint.paint(text+" has no address", yellow))
		default:
			lines = append(lines, r.paint.dim(text+" address unknown"))
		}
	}
	for _, kind := range []string{"CDS", "CSYNC"} {
		if !slices.ContainsFunc(d.Endpoints, func(e trace.DSYNCEndpoint) bool { return e.Type == kind && e.Ignored == "" }) {
			lines = append(lines, r.paint.dim(mark+"  "+kind+" none, so a change to "+notified(kind)+" waits for the next scan"))
		}
	}
	return append(lines, ignored...)
}

// notified is what a notice of the given type tells the parent about.
func notified(kind string) string {
	if kind == "CDS" {
		return "the keys"
	}
	return "the nameservers"
}

// answered reports whether a lookup was answered, if only with nothing, or was
// never asked.
func answered(lookup *trace.Lookup) bool {
	return lookup == nil || lookup.Err == ""
}
