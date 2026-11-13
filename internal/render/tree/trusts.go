package tree

import (
	"fmt"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// trusts set each resolver's AD bit beside the chain of trust the walk
// checked, one line each, and only where the two disagree. The bit is the
// resolver's claim, so the line says what it says and suggests why.
func (r *renderer) trusts(tr *trace.Trace) []string {
	chain := tr.Chain()
	if chain == nil {
		return nil
	}

	var lines []string
	for _, answer := range tr.Resolvers {
		// One that --check-resolver saw not validating already has its line.
		if answer == nil || answer.Trusts == "" ||
			(answer.Trusts == trace.TrustsMissing && validates(answer) == trace.ObservedNo) {
			continue
		}
		who := "the resolver"
		if answer.Server.IP.IsValid() {
			who = answer.Server.IP.String()
		}

		var text string
		switch answer.Trusts {
		case trace.TrustsMissing:
			algorithms, digests := tr.Algorithms()
			checks := strings.Join(append(algorithms, digests...), ", ")
			text = fmt.Sprintf("%s gives the answer without AD, where the walk found it secure", who)
			if checks != "" {
				text += " (" + checks + ")"
			}
			switch seen := validates(answer); {
			case seen == trace.ObservedYes && checks != "":
				text += ": it validates, so it most likely cannot check one of these, and its users get no protection from the signatures"
			case seen == trace.ObservedYes:
				text += ": it validates, so it most likely cannot check an algorithm or digest the chain uses"
			default:
				text += ": it does not validate, or cannot check an algorithm or digest the chain uses"
			}
		case trace.TrustsUnproven:
			text = fmt.Sprintf("%s says the answer is authentic (AD), where the walk found the chain %s: "+
				"it trusts something the walk does not, such as a trust anchor of its own, another view of the zone or a copy cached from before a change",
				who, chain.DNSSEC.State)
		case trace.TrustsUnchecked:
			text = fmt.Sprintf("%s says the answer is authentic (AD), where the walk could not check the chain", who)
			if chain.DNSSEC.Algorithm != "" {
				text += " (" + chain.DNSSEC.Algorithm + ")"
			}
			text += ": it checks something this build of dnstree cannot"
		}
		if answer.Match == trace.MatchDiffers {
			text += "; its answer differs too, so the two may be about different data"
		}

		mark := "trust: "
		if r.glyphs.icons {
			mark = spaced("🔓")
		}
		lines = append(lines, r.paint.paint(mark+text, yellow))
	}
	return lines
}

// validates is what --check-resolver saw of the resolver's validation, empty
// where it did not ask.
func validates(answer *trace.Resolver) trace.Observed {
	if answer.Behaviour == nil {
		return ""
	}
	return answer.Behaviour.Validates
}
