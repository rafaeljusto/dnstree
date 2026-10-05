package jsonout

import (
	"fmt"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// spf is the sender policy of the name (RFC 7208), as the tree of lookups a
// receiving mail server makes for it.
type spf struct {
	Name    string    `json:"name"`
	Server  *server   `json:"server,omitempty"`
	Record  string    `json:"record,omitempty"`
	Terms   []spfTerm `json:"terms,omitempty"`
	Lookups int       `json:"lookups"`
	Void    int       `json:"void"`
	Cut     bool      `json:"cut,omitempty"`
	Result  string    `json:"result"`
	Why     string    `json:"why,omitempty"`
}

type spfTerm struct {
	Term      string    `json:"term"`
	Kind      string    `json:"kind,omitempty"`
	Lookup    int       `json:"lookup,omitempty"`
	Target    string    `json:"target,omitempty"`
	Record    string    `json:"record,omitempty"`
	Terms     []spfTerm `json:"terms,omitempty"`
	Found     []string  `json:"found,omitempty"`
	Void      bool      `json:"void,omitempty"`
	Sender    bool      `json:"sender,omitempty"`
	Unreached bool      `json:"unreached,omitempty"`
	Problem   string    `json:"problem,omitempty"`
	Fatal     bool      `json:"fatal,omitempty"`
}

func convertSPF(from *trace.SPF) *spf {
	if from == nil {
		return nil
	}
	return &spf{
		Name:    from.Name,
		Server:  convertServer(from.Server),
		Record:  from.Record,
		Terms:   convertTerms(from.Terms),
		Lookups: from.Lookups,
		Void:    from.Void,
		Cut:     from.Cut,
		Result:  string(from.Result),
		Why:     from.Why,
	}
}

func convertTerms(from []trace.SPFTerm) []spfTerm {
	var to []spfTerm
	for _, term := range from {
		to = append(to, spfTerm{
			Term: term.Term, Kind: term.Kind, Lookup: term.Lookup, Target: term.Target, Record: term.Record,
			Terms: convertTerms(term.Terms), Found: term.Found, Void: term.Void, Sender: term.Sender,
			Unreached: term.Unreached, Problem: term.Problem, Fatal: term.Fatal,
		})
	}
	return to
}

// readSPF reads the policy back. --expect spf:ok and the metrics are read from
// its result, so that has to be one this build knows.
func readSPF(from *spf) (*trace.SPF, error) {
	if from == nil {
		return nil, nil
	}
	result := trace.SPFResult(from.Result)
	switch result {
	case trace.SPFOK, trace.SPFNone, trace.SPFPermError, trace.SPFTempError, trace.SPFUndecided:
	default:
		return nil, fmt.Errorf("jsonout: %q is not what an SPF check can come to", from.Result)
	}
	server, err := readServer(from.Server)
	if err != nil {
		return nil, err
	}
	terms, err := readTerms(from.Terms, 0)
	if err != nil {
		return nil, err
	}
	return &trace.SPF{
		Name: from.Name, Server: server, Record: from.Record, Terms: terms,
		Lookups: from.Lookups, Void: from.Void, Cut: from.Cut, Result: result, Why: from.Why,
	}, nil
}

func readTerms(from []spfTerm, depth int) ([]trace.SPFTerm, error) {
	if depth > maxNesting {
		return nil, fmt.Errorf("jsonout: spf terms nested deeper than %d, which no check goes", maxNesting)
	}
	var to []trace.SPFTerm
	for _, term := range from {
		terms, err := readTerms(term.Terms, depth+1)
		if err != nil {
			return nil, err
		}
		to = append(to, trace.SPFTerm{
			Term: term.Term, Kind: term.Kind, Lookup: term.Lookup, Target: term.Target, Record: term.Record,
			Terms: terms, Found: term.Found, Void: term.Void, Sender: term.Sender,
			Unreached: term.Unreached, Problem: term.Problem, Fatal: term.Fatal,
		})
	}
	return to, nil
}
