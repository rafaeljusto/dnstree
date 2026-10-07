package explain

import (
	"fmt"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// requests are what the zones on the walk ask their parents to change, and
// what a parent that acts on such requests would make of them. Whether this
// parent polls for them at all is nothing a walk can see, and is said so.
func requests(tr *trace.Trace) []Finding {
	var findings []Finding
	for _, request := range tr.Requests() {
		if finding, ok := csync(request.Zone, request.CSYNC); ok {
			findings = append(findings, finding)
		}
		if finding, ok := bootstrap(request.Zone, request.Signal); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func csync(zone string, c *trace.CSYNC) (Finding, bool) {
	if c == nil {
		return Finding{}, false
	}
	var changes []string
	for _, change := range c.Changes {
		verb := "remove"
		if change.Add {
			verb = "add"
		}
		text := verb + " " + change.Type + " " + change.Name
		if change.Data != "" {
			text = verb + " " + change.Type + " " + change.Data + " for " + change.Name
		}
		changes = append(changes, text)
	}
	would := "the delegation already holds what it asks for"
	if len(changes) > 0 {
		would = "a parent acting on it would " + strings.Join(changes, ", ")
	}

	switch c.State {
	case trace.CSYNCReady:
		return Finding{Topic: Spread, Level: Note, Text: fmt.Sprintf(
			"%s asks its parent in a signed CSYNC to copy its %s, and %s; whether its parent polls for one is not something a walk can see",
			zone, strings.Join(c.Types, ", "), would)}, true
	case trace.CSYNCManual:
		return Finding{Topic: Spread, Level: Note, Text: fmt.Sprintf(
			"%s asks its parent in a signed CSYNC to copy its %s once someone approves it, and %s", zone, strings.Join(c.Types, ", "), would)}, true
	case trace.CSYNCWaiting:
		return Finding{Topic: Spread, Level: Warn, Text: fmt.Sprintf(
			"the CSYNC of %s waits for serial %d and the zone serves %d, so a parent copies nothing until the serial reaches it", zone, c.Serial, c.ZoneSerial)}, true
	case trace.CSYNCUnproven:
		return Finding{Topic: Spread, Level: Warn, Text: fmt.Sprintf(
			"the CSYNC of %s is not one a parent acts on (%s); %s if it were signed", zone, c.Reason, would)}, true
	case trace.CSYNCUnchecked:
		return Finding{Topic: Spread, Level: Note, Unknown: true, Text: fmt.Sprintf("the CSYNC of %s was not checked: %s", zone, c.Reason)}, true
	}
	return Finding{}, false
}

func bootstrap(zone string, signal *trace.Signal) (Finding, bool) {
	if signal == nil || signal.Bootstrap == nil {
		return Finding{}, false
	}
	b := signal.Bootstrap
	keys := keyTags(signal.Requested)
	switch b.State {
	case trace.BootstrapReady:
		return Finding{Topic: Trust, Level: Note, Text: fmt.Sprintf(
			"%s is signed but its parent holds no DS for it, and it asks for one for %s; the operator of every nameserver vouches for the request (RFC 9615), so a parent that bootstraps would add it, though whether its parent does is not something a walk can see",
			zone, keys)}, true
	case trace.BootstrapRefused:
		return Finding{Topic: Trust, Level: Warn, Text: fmt.Sprintf(
			"%s asks for its first DS, for %s, but a parent that bootstraps would add none: %s", zone, keys, b.Reason)}, true
	}
	return Finding{Topic: Trust, Level: Note, Unknown: true, Text: fmt.Sprintf(
		"whether a parent would bootstrap the first DS of %s was not checked: %s", zone, b.Reason)}, true
}

// keyTags names keys by their tags in a sentence.
func keyTags(tags []uint16) string {
	switch len(tags) {
	case 0:
		return "no key"
	case 1:
		return fmt.Sprintf("key %d", tags[0])
	}
	named := make([]string, len(tags))
	for i, tag := range tags {
		named[i] = fmt.Sprint(tag)
	}
	return "keys " + strings.Join(named[:len(named)-1], ", ") + " and " + named[len(named)-1]
}
