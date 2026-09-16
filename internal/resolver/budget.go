package resolver

import "fmt"

// Defaults for one resolution.
const (
	DefaultMaxDepth   = 16
	DefaultMaxQueries = 64
)

// Budget bounds a resolution. A referral has to go strictly down, so the zones
// of a walk cannot repeat; these counters are what stops everything else, and
// they are why the tool always terminates and always renders what it learned.
type Budget struct {
	MaxDepth   int // zone cuts followed
	MaxQueries int // queries sent, over the whole run
}

// counters is the live state of a budget.
type counters struct {
	max            Budget
	depth, queries int
}

func newCounters(budget Budget) *counters {
	if budget.MaxDepth <= 0 {
		budget.MaxDepth = DefaultMaxDepth
	}
	if budget.MaxQueries <= 0 {
		budget.MaxQueries = DefaultMaxQueries
	}
	return &counters{max: budget}
}

func (c *counters) query() error {
	c.queries++
	if c.queries > c.max.MaxQueries {
		return fmt.Errorf("gave up after %d queries", c.max.MaxQueries)
	}
	return nil
}

func (c *counters) descend() error {
	c.depth++
	if c.depth > c.max.MaxDepth {
		return fmt.Errorf("gave up after %d zone cuts", c.max.MaxDepth)
	}
	return nil
}
