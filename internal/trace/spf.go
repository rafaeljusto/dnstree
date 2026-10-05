package trace

import "slices"

// SPF is the sender policy a domain publishes (RFC 7208), as the tree of
// lookups a receiving mail server makes to check it. Which term a check stops
// at depends on who is sending, so this is the worst case: every term up to
// all, the way a sender that matches none of them is checked.
type SPF struct {
	Name string

	// Server is the recursive server the lookups were asked of, which is
	// where a mail server asks them too.
	Server Server

	// Record is the policy published at Name, empty where there is none.
	Record string
	Terms  []SPFTerm

	// Lookups are the terms that cost a DNS lookup, held against
	// SPFLookupLimit, and Void those that found nothing, against SPFVoidLimit.
	Lookups int
	Void    int

	// Cut is set where the query budget ran out before every term was
	// followed, which leaves the counts a floor.
	Cut bool

	// Result is what any check of the policy comes to before the sender is
	// known, and Why what made it so, empty for SPFOK.
	Result SPFResult
	Why    string
}

// The limits RFC 7208 4.6.4 sets on one check. Past either the check is a
// permerror, which many receivers treat as a failure.
const (
	SPFLookupLimit = 10
	SPFVoidLimit   = 2
)

// SPFResult is what a check comes to whoever is sending.
type SPFResult string

// What a policy can come to.
const (
	// SPFOK is a policy with nothing in it that stops a check: what it says
	// of a sender is up to its terms.
	SPFOK SPFResult = "ok"

	SPFNone      SPFResult = "none"
	SPFPermError SPFResult = "permerror"
	SPFTempError SPFResult = "temperror"

	// SPFUndecided is a policy the budget ran out on, one too long to read,
	// or one no recursive server could be asked about.
	SPFUndecided SPFResult = "undecided"
)

// SPFTerm is one mechanism or modifier of a policy, as written.
type SPFTerm struct {
	Term string

	// Kind is the mechanism or the modifier, lowercase and without its
	// qualifier: all, include, a, mx, ptr, ip4, ip6, exists, redirect, exp, or
	// the name of a modifier nobody defined. Empty for a term that does not
	// parse.
	Kind string

	// Lookup is the running count of lookups at this term, zero for one that
	// costs none.
	Lookup int

	// Target is the name it looks up, where it looks one up.
	Target string

	// Record is the policy an include or a redirect found at Target, and
	// Terms what that policy says.
	Record string
	Terms  []SPFTerm

	// Found is what an a or an exists found, the addresses, and what an mx
	// found, the mail servers.
	Found []string

	// Void is a lookup that found nothing.
	Void bool

	// Sender is a term whose name depends on who is sending (a macro, or ptr),
	// which is counted and not looked up.
	Sender bool

	// Unreached is a term no check comes to: after all, or a redirect beside
	// one.
	Unreached bool

	// Problem is what is wrong with the term, and Fatal whether it is what
	// makes the check fail rather than advice.
	Problem string
	Fatal   bool
}

// Shown is the policy with every name and text the zones wrote escaped.
func (s *SPF) Shown() *SPF {
	if s == nil {
		return nil
	}
	shown := *s
	shown.Name, shown.Record, shown.Why = Shown(s.Name), Shown(s.Record), Shown(s.Why)
	shown.Server = s.Server.Shown()
	shown.Terms = shownTerms(s.Terms)
	return &shown
}

func shownTerms(terms []SPFTerm) []SPFTerm {
	if terms == nil {
		return nil
	}
	shown := slices.Clone(terms)
	for i := range shown {
		term := &shown[i]
		term.Term, term.Kind = Shown(term.Term), Shown(term.Kind)
		term.Target, term.Record = Shown(term.Target), Shown(term.Record)
		term.Problem = Shown(term.Problem)
		term.Found = shownAll(term.Found)
		term.Terms = shownTerms(term.Terms)
	}
	return shown
}
