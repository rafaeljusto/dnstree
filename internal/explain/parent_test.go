package explain_test

import (
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/explain"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestRequests(t *testing.T) {
	added := []trace.DelegationChange{{Add: true, Type: "NS", Name: "ns2.test."}}
	for name, tt := range map[string]struct {
		csync   *trace.CSYNC
		signal  *trace.Signal
		dsync   *trace.DSYNC
		want    string
		unknown bool
	}{
		"a signed CSYNC a parent would act on": {
			csync: &trace.CSYNC{State: trace.CSYNCReady, Types: []string{"NS"}, Changes: added},
			want:  "test. asks its parent in a signed CSYNC to copy its NS, and a parent acting on it would add NS ns2.test.; whether its parent polls",
		},
		"a CSYNC the delegation already matches": {
			csync: &trace.CSYNC{State: trace.CSYNCReady, Types: []string{"NS"}},
			want:  "the delegation already holds what it asks for",
		},
		"a CSYNC waiting on the zone's serial": {
			csync: &trace.CSYNC{State: trace.CSYNCWaiting, Serial: 11, ZoneSerial: 10},
			want:  "the CSYNC of test. waits for serial 11 and the zone serves 10",
		},
		"an unsigned CSYNC": {
			csync: &trace.CSYNC{State: trace.CSYNCUnproven, Reason: "the chain of trust did not reach test. secure", Changes: added},
			want:  "the CSYNC of test. is not one a parent acts on (the chain of trust did not reach test. secure); a parent acting on it would add NS ns2.test. if it were signed",
		},
		"a CSYNC nobody checked": {
			csync:   &trace.CSYNC{State: trace.CSYNCUnchecked, Reason: "it could not be fetched"},
			want:    "the CSYNC of test. was not checked: it could not be fetched",
			unknown: true,
		},
		"a first DS every operator vouches for": {
			signal: &trace.Signal{State: trace.SignalPending, Requested: []uint16{7},
				Bootstrap: &trace.Bootstrap{State: trace.BootstrapReady}},
			want: "test. is signed but its parent holds no DS for it, and it asks for one for key 7",
		},
		"a first DS a parent would refuse": {
			signal: &trace.Signal{State: trace.SignalPending, Requested: []uint16{7, 9},
				Bootstrap: &trace.Bootstrap{State: trace.BootstrapRefused, Reason: "no signal under ns2.example."}},
			want: "test. asks for its first DS, for keys 7 and 9, but a parent that bootstraps would add none: no signal under ns2.example.",
		},
		"a first DS whose signals were not all looked up": {
			signal: &trace.Signal{State: trace.SignalPending, Requested: []uint16{7},
				Bootstrap: &trace.Bootstrap{State: trace.BootstrapUnchecked, Reason: "the budget ran out"}},
			want:    "whether a parent would bootstrap the first DS of test. was not checked: the budget ran out",
			unknown: true,
		},
		"a parent that takes notices": {
			dsync: &trace.DSYNC{State: trace.DSYNCFound, Parent: ".", Name: "test._dsync.", Endpoints: []trace.DSYNCEndpoint{
				{Type: "CDS", Scheme: "NOTIFY", Port: 5359, Target: "notify.example."},
				{Type: "CSYNC", Scheme: "NOTIFY", Target: "notify.example.", Ignored: "port 0 names no endpoint"},
			}},
			want: ". takes notices about test. (RFC 9859) of CDS at notify.example. port 5359, so its operator can send one",
		},
		"a parent whose records a notifier passes over": {
			dsync: &trace.DSYNC{State: trace.DSYNCFound, Parent: ".", Name: "_dsync.", Endpoints: []trace.DSYNCEndpoint{
				{Type: "CDS", Scheme: "0", Port: 5359, Target: "notify.example.", Ignored: "scheme 0 names no endpoint"},
			}},
			want: ". publishes DSYNC records for test. at _dsync., but none a notifier uses",
		},
		"a parent that names nowhere": {
			dsync: &trace.DSYNC{State: trace.DSYNCNone, Parent: "."},
			want:  ". names nowhere to send a notice about test. (RFC 9859), so a change to its CDS or CSYNC waits for the parent's next scan",
		},
		"a DSYNC that does not validate": {
			dsync: &trace.DSYNC{State: trace.DSYNCBogus, Parent: ".", Reason: "_dsync. does not validate: signature does not verify"},
			want:  "where . takes notices about test. does not validate (_dsync. does not validate: signature does not verify)",
		},
		"a DSYNC nobody could look up": {
			dsync:   &trace.DSYNC{State: trace.DSYNCUnchecked, Parent: ".", Reason: "the lookup of _dsync. failed: SERVFAIL"},
			want:    "where . takes notices about test. was not checked: the lookup of _dsync. failed: SERVFAIL",
			unknown: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			referral := hop(trace.KindReferral, "a.root-servers.net.")
			referral.Zone = "."
			referral.Delegation = &trace.Delegation{Zone: "test.", CSYNC: tt.csync, DSYNC: tt.dsync}
			referral.DNSSEC = &trace.DNSSECStatus{State: trace.Insecure, Signal: tt.signal}
			referral.Children = []*trace.Step{answered(300)}
			tr := walk(referral)

			if got := said(tr); !strings.Contains(got, tt.want) {
				t.Errorf("got %q, want it to say %q", got, tt.want)
			}
			for _, finding := range explain.Findings(tr) {
				if strings.Contains(finding.Text, tt.want) && finding.Unknown != tt.unknown {
					t.Errorf("got unknown %v, want %v", finding.Unknown, tt.unknown)
				}
			}
		})
	}
}
