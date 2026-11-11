package resolver

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// repeatSpacing is the pause between one round of repeats and the next, so a
// server that limits how fast it answers one source is not set off by the
// check that is looking for it.
const repeatSpacing = 100 * time.Millisecond

// again is one hop's question being asked again, and what came back.
type again struct {
	step    *trace.Step
	carrier transport.Transport
	qtype   uint16
	udpSize uint16
	rtts    []time.Duration
	rcodes  []string
	nsids   []string
	copies  []string
	got     trace.Repeated
}

// repeat asks every question of the walk's own hops again, Repeat times, of
// the server that was asked it and over the transport that carried it. The
// asides are left out: they answer other questions, and the probes among them
// are not ours to ask over and over. The rounds go out one after another,
// every hop side by side within one; what they got joins the hops once they
// are all in, from the goroutine doing the walking.
func (r *run) repeat(ctx context.Context) {
	times := min(r.cfg.Repeat, trace.MaxRepeat)
	if times <= 0 {
		return
	}

	type question struct {
		server netip.AddrPort
		proto  string
		asked  trace.Question
	}
	var hops []*again
	seen := map[question]bool{}
	for step := range r.trace.Mainline() {
		if step.Kind == trace.KindZone || !step.Queried() || !step.Server.IP.IsValid() {
			continue
		}
		key := question{netip.AddrPortFrom(step.Server.IP, step.Server.Port), step.Proto, step.Asked}
		qtype, err := dnsutil.StringToType(step.Asked.Type)
		if seen[key] || err != nil {
			continue
		}
		seen[key] = true
		hops = append(hops, &again{step: step, carrier: r.carrierFor(step.Proto), qtype: qtype, udpSize: sentSize(step, r.cfg.UDPSize)})
	}

	for round := range times {
		if round > 0 && r.cfg.Clock == nil {
			select {
			case <-time.After(repeatSpacing):
			case <-ctx.Done():
			}
		}
		if ctx.Err() != nil {
			break
		}
		askEach(hops, func(_ int, a *again) { r.askAgain(ctx, a) })
	}

	for _, a := range hops {
		a.step.Repeated = a.summary()
		r.warnRepeats(a.step)
	}
}

// askAgain puts a hop's question once more, and counts what came back. Like
// every query of the run it carries what the run rides along on: the cookie,
// the NSID, the zone version and the client subnet.
func (r *run) askAgain(ctx context.Context, a *again) {
	step := a.step
	server := netip.AddrPortFrom(step.Server.IP, cmp.Or(step.Server.Port, a.carrier.Port()))
	if r.cfg.Asking != nil {
		if done := r.cfg.Asking(step.Zone, step.Server); done != nil {
			defer done()
		}
	}
	a.got.Asked++
	version := r.cfg.Serial && a.udpSize > 0 && !r.dropsVersion(server.Addr())
	req, cookie, err := r.newQuery(a.carrier, server, step.Asked.Name, a.qtype, a.udpSize, version)
	if err != nil {
		a.got.Failed++
		return
	}
	resp, rtt, err := a.carrier.Exchange(ctx, req, server, step.Server.Name)
	r.cfg.Log.Debug("asked a nameserver again",
		"zone", step.Zone, "server", server, "proto", a.carrier.Proto(),
		"name", step.Asked.Name, "type", step.Asked.Type, "rtt", rtt, "error", err)
	switch {
	case err != nil && transport.IsTimeout(err):
		a.got.TimedOut++
		return
	case err != nil:
		a.got.Failed++
		return
	}
	if cookie {
		r.remember(server.Addr(), resp)
	}
	a.got.Answered++
	if resp.Truncated {
		a.got.Truncated++
	}
	a.rtts = append(a.rtts, rtt)
	a.rcodes = append(a.rcodes, dnsutil.RcodeToString(resp.Rcode))
	if nsid := transport.EchoedNSID(resp); nsid != "" {
		a.nsids = append(a.nsids, nsid)
	}
	if copied := transport.EchoedZoneVersion(resp, step.Asked.Name); copied != nil && strings.EqualFold(copied.Zone, step.Zone) {
		a.copies = append(a.copies, strconv.FormatUint(uint64(copied.Serial), 10))
	}
}

func (a *again) summary() *trace.Repeated {
	got := a.got
	got.Rcodes = trace.Tally(a.rcodes)
	got.Instances = trace.Tally(a.nsids)
	got.Copies = trace.Tally(a.copies)
	if len(a.rtts) > 0 {
		slices.Sort(a.rtts)
		got.Best, got.Worst = a.rtts[0], a.rtts[len(a.rtts)-1]
		got.Median = a.rtts[len(a.rtts)/2]
		if len(a.rtts)%2 == 0 {
			got.Median = (a.rtts[len(a.rtts)/2-1] + got.Median) / 2
		}
	}
	return &got
}

// warnRepeats says where the repeats of a hop did not all come back, or came
// back saying something other than what the walk was told.
func (r *run) warnRepeats(step *trace.Step) {
	got := step.Repeated
	server := at(step)
	if step.Server.Name != "" {
		server += " (" + step.Server.IP.String() + ")"
	}
	question := step.Asked.Name + " " + step.Asked.Type

	var why []string
	if step.Rcode == "" && got.Answered > 0 {
		why = append(why, "where the walk's own question went unanswered")
	}
	if got.TimedOut > 0 {
		why = append(why, fmt.Sprintf("%d timed out", got.TimedOut))
	}
	if got.Failed > 0 {
		why = append(why, fmt.Sprintf("%d failed", got.Failed))
	}
	if len(why) > 0 {
		r.warnIn(trace.AreaServers, step.Zone, "%s answered %d of %d repeats of %s; %s",
			server, got.Answered, got.Asked, question, strings.Join(why, ", "))
	}

	if len(got.Copies) > 1 {
		held := make([]string, 0, len(got.Copies))
		for _, c := range got.Copies {
			held = append(held, fmt.Sprintf("%s (%d)", c.Value, c.Times))
		}
		r.warnIn(trace.AreaConsistency, step.Zone, "%s answered repeats of %s out of %d copies of %s: %s",
			server, question, len(got.Copies), step.Zone, strings.Join(held, ", "))
	} else if own := step.ZoneVersion; len(got.Copies) == 1 && own != nil && strings.EqualFold(own.Zone, step.Zone) &&
		strconv.FormatUint(uint64(own.Serial), 10) != got.Copies[0].Value {
		r.warnIn(trace.AreaConsistency, step.Zone, "%s answered %s out of copy %d of %s, and its repeats out of copy %s",
			server, question, own.Serial, step.Zone, got.Copies[0].Value)
	}

	// What the repeats said is only held against an answer the walk got.
	if step.Rcode == "" {
		return
	}
	for _, rcode := range got.Rcodes {
		if rcode.Value != step.Rcode {
			r.warnIn(trace.AreaServers, step.Zone, "%s answered %s to %d of %d repeats of %s, where the walk was answered %s",
				server, rcode.Value, rcode.Times, got.Asked, question, step.Rcode)
		}
	}
}

// carrierFor is the transport that carried a hop over proto: the walk's own,
// its fallback, or the TCP a truncated answer was asked again over.
func (r *run) carrierFor(proto string) transport.Transport {
	for _, carrier := range []transport.Transport{r.cfg.Transport, r.cfg.Fallback, r.cfg.TCP} {
		if carrier != nil && carrier.Proto() == proto {
			return carrier
		}
	}
	return r.cfg.Transport
}

// sentSize is the EDNS0 buffer a hop's query went out with, none where it was
// asked again without EDNS0, and the run's own where the hop kept no record.
func sentSize(step *trace.Step, fallback uint16) uint16 {
	if step.Sent == nil {
		return fallback
	}
	if !step.Sent.EDNS {
		return 0
	}
	return step.Sent.UDPSize
}
