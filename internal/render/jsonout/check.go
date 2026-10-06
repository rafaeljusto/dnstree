package jsonout

import (
	"fmt"
	"slices"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// check is the grade --check gave each area of the zone's health. Unlike
// propagation it is read back: which area a warning is about is known only to
// the walk that raised it.
type check struct {
	Zone  string   `json:"zone"`
	Areas []graded `json:"areas"`
}

type graded struct {
	Area  string `json:"area"`
	Grade string `json:"grade"`
	Text  string `json:"text,omitempty"`
	More  int    `json:"more,omitempty"`
}

func convertCheck(from *trace.Check) *check {
	if from == nil {
		return nil
	}
	to := &check{Zone: from.Zone, Areas: []graded{}}
	for _, area := range from.Areas {
		to.Areas = append(to.Areas, graded{Area: string(area.Area), Grade: string(area.Grade), Text: area.Text, More: area.More})
	}
	return to
}

// readCheck refuses an area or a grade this build does not know, since
// --expect turns the grades into an exit code.
func readCheck(from *check) (*trace.Check, error) {
	if from == nil {
		return nil, nil
	}
	to := &trace.Check{Zone: from.Zone}
	for _, area := range from.Areas {
		if !slices.Contains(trace.Areas, trace.Area(area.Area)) {
			return nil, fmt.Errorf("jsonout: %q is not an area --check grades", area.Area)
		}
		switch grade := trace.Grade(area.Grade); grade {
		case trace.GradePassed, trace.GradeLook, trace.GradeBroken, trace.GradeSkipped:
		default:
			return nil, fmt.Errorf("jsonout: %q is not a grade --check gives", area.Grade)
		}
		if area.More < 0 {
			return nil, fmt.Errorf("jsonout: %d is not a number of findings", area.More)
		}
		to.Areas = append(to.Areas, trace.Graded{Area: trace.Area(area.Area), Grade: trace.Grade(area.Grade),
			Text: area.Text, More: area.More})
	}
	return to, nil
}
