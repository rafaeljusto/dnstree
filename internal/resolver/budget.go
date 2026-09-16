package resolver

import "fmt"

// Defaults for one resolution.
const (
	DefaultMaxDepth   = 16
	DefaultMaxQueries = 64
	DefaultMaxCNAME   = 8
)

// Budget bounds a resolution. A referral has to go strictly down, so the zones
// of a walk cannot repeat; these counters are what stops everything else, and
// they are why the tool always terminates and always renders what it learned.
// The depth is counted per walk, since a CNAME or a nameserver name starts a
// fresh one; the others are counted over the whole run.
type Budget struct {
	MaxDepth   int // zone cuts followed, counted again for every restart
	MaxQueries int // hops made, over the whole run
	MaxCNAME   int // CNAME hops chased
}

// counters is the live state of a budget.
type counters struct {
	max             Budget
	queries, cnames int
}

func newCounters(budget Budget) *counters {
	if budget.MaxDepth <= 0 {
		budget.MaxDepth = DefaultMaxDepth
	}
	if budget.MaxQueries <= 0 {
		budget.MaxQueries = DefaultMaxQueries
	}
	if budget.MaxCNAME <= 0 {
		budget.MaxCNAME = DefaultMaxCNAME
	}
	return &counters{max: budget}
}

// query spends one hop. Retrying the same question over TCP, or without EDNS0,
// stays part of the hop that needed it.
func (c *counters) query() error {
	c.queries++
	if c.queries > c.max.MaxQueries {
		return fmt.Errorf("gave up after %d queries", c.max.MaxQueries)
	}
	return nil
}

func (c *counters) cname() error {
	c.cnames++
	if c.cnames > c.max.MaxCNAME {
		return fmt.Errorf("gave up after %d CNAME hops", c.max.MaxCNAME)
	}
	return nil
}
