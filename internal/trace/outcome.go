package trace

// Outcome is how a hop went, in the few words every drawing colours it by.
type Outcome int

// The outcomes a legend tells apart.
const (
	OutcomeNone     Outcome = iota // a way down: a referral, or a minimised answer
	OutcomeAnswer                  // an answer or an alias
	OutcomeDenial                  // the name or the type is not there, or the server is lame
	OutcomeFiltered                // somebody decided the answer
	OutcomeFailed                  // a timeout or an error
	OutcomeSkipped                 // never queried
	OutcomeZone                    // the node a trace starts from
)

// Outcome sorts the hop for a legend. Under --qmin, an answer about a shorter
// name than the question is only a way down, never the answer.
func (s *Step) Outcome() Outcome {
	if s.Minimised && (s.Kind == KindAnswer || s.Kind == KindNoData) {
		return OutcomeNone
	}
	switch s.Kind {
	case KindAnswer, KindCNAME:
		return OutcomeAnswer
	case KindNoData, KindNXDomain, KindLame:
		return OutcomeDenial
	case KindFiltered:
		return OutcomeFiltered
	case KindTimeout, KindError:
		return OutcomeFailed
	case KindSkipped:
		return OutcomeSkipped
	case KindZone:
		return OutcomeZone
	}
	return OutcomeNone
}
