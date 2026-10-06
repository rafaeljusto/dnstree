package tree

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// registration draws what --rdap found at the registry: how long the domain
// has left, what holds it back, and where the registry and the zone above it
// disagree about its delegation.
func (r *renderer) registration(reg *trace.Registration) []string {
	if reg == nil {
		return nil
	}
	mark := "rdap: "
	if r.glyphs.icons {
		mark = spaced("📅")
	}

	switch reg.State {
	case trace.Unregistered:
		return []string{r.paint.paint(mark+reg.Why, red)}
	case trace.Unreached:
		return []string{r.paint.paint(mark+reg.Why, yellow)}
	case trace.Unpublished:
		return []string{r.paint.dim(mark + reg.Why)}
	}

	var lines []string
	left, known := r.trace.Lapses(reg)
	switch {
	case !known:
		lines = append(lines, r.paint.dim(mark+reg.Domain+" is registered; the registry does not say until when"))
	case left <= 0:
		lines = append(lines, r.paint.paint(fmt.Sprintf("%s%s expired %s ago, on %s: renew it before the registry lets it go",
			mark, reg.Domain, days(-left), date(reg.Expires)), red))
	case left < trace.RegistrationSoon:
		lines = append(lines, r.paint.paint(fmt.Sprintf("%s%s runs out in %s, on %s: renew it",
			mark, reg.Domain, days(left), date(reg.Expires)), yellow))
	default:
		lines = append(lines, r.paint.dim(fmt.Sprintf("%s%s is registered until %s, with %s left",
			mark, reg.Domain, date(reg.Expires), days(left))))
	}

	if held := reg.Held(); held != "" {
		lines = append(lines, r.paint.paint(mark+reg.Domain+" "+holds[held], red))
	} else if len(reg.Status) > 0 {
		lines = append(lines, r.paint.dim(mark+"status: "+strings.Join(reg.Status, ", ")))
	}
	return append(lines, r.agreement(reg, mark)...)
}

// holds says what each status that takes a domain out of its zone means for
// whoever looks it up.
var holds = map[string]string{
	"client hold":       "is on client hold: the registrar has taken it out of the zone",
	"server hold":       "is on server hold: the registry has taken it out of the zone",
	"pending delete":    "is pending delete: it lapsed, and is about to be deleted",
	"redemption period": "is in its redemption period: it lapsed, and only the registrar can still restore it",
	"pending restore":   "is pending restore: it lapsed, and is being restored",
	"inactive":          "is inactive: it has no nameservers, so it is not in the zone",
}

// agreement holds the delegation the registry has against the one the zone
// above hands out.
func (r *renderer) agreement(reg *trace.Registration, mark string) []string {
	if reg.Parent == "" {
		return nil
	}
	if reg.Agrees() {
		what := "nameservers match"
		if reg.DSChecked {
			what = "nameservers and DS match"
		}
		return []string{r.paint.dim(mark + what + " what " + reg.Parent + " hands out")}
	}

	var lines []string
	if part := apart(reg.NSOnlyRegistry, reg.NSOnlyParent, reg.Parent); part != "" {
		lines = append(lines, r.paint.paint(mark+"nameservers: "+part, yellow))
	}
	var registry, parent []string
	for _, tag := range reg.DSOnlyRegistry {
		registry = append(registry, "key "+strconv.Itoa(int(tag)))
	}
	for _, tag := range reg.DSOnlyParent {
		parent = append(parent, "key "+strconv.Itoa(int(tag)))
	}
	if part := apart(registry, parent, reg.Parent); part != "" {
		lines = append(lines, r.paint.paint(mark+"DS: "+part, yellow))
	}
	if reg.DSDiffer {
		said := "the registry holds no DS and " + reg.Parent + " hands some out"
		if reg.Signed || len(reg.DS) > 0 {
			said = "the registry holds DS and " + reg.Parent + " hands out none"
		}
		lines = append(lines, r.paint.paint(mark+"DS: "+said, yellow))
	}
	return append(lines, r.paint.dim(mark+"a change is stuck between the registry and the zone, or the registry's copy is stale"))
}

func apart(registry, parent []string, zone string) string {
	var said []string
	if len(registry) > 0 {
		said = append(said, "only the registry holds "+strings.Join(registry, ", "))
	}
	if len(parent) > 0 {
		said = append(said, "only "+zone+" hands out "+strings.Join(parent, ", "))
	}
	return strings.Join(said, "; ")
}

// days is how long a registration has, in days, or finer once less than one
// is left.
func days(d time.Duration) string {
	n := int(d / (24 * time.Hour))
	switch {
	case n == 1:
		return "1 day"
	case n > 1:
		return strconv.Itoa(n) + " days"
	}
	return short(d)
}

func date(t time.Time) string { return t.UTC().Format(time.DateOnly) }
