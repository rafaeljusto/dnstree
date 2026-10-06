package tree

import (
	"fmt"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// grades is how each grade is marked, colour aside: a glyph in the tree, a
// word in ascii, an emoji in the emoji charset.
var grades = map[Charset]map[trace.Grade]string{
	Unicode: {trace.GradePassed: "✔", trace.GradeLook: "⚠", trace.GradeBroken: "✘", trace.GradeSkipped: "·"},
	ASCII:   {trace.GradePassed: "ok", trace.GradeLook: "!!", trace.GradeBroken: "xx", trace.GradeSkipped: "--"},
	Emoji:   {trace.GradePassed: "✅", trace.GradeLook: "⚠️", trace.GradeBroken: "❌", trace.GradeSkipped: "➖"},
}

var gradeColors = map[trace.Grade]string{
	trace.GradePassed: green, trace.GradeLook: yellow, trace.GradeBroken: red, trace.GradeSkipped: grey,
}

// check draws what --check graded: a line for each area, the worst of what it
// found, and how many areas came out each way.
func (r *renderer) check(c *trace.Check) []string {
	if c == nil {
		return nil
	}
	charset := r.charset
	marks := grades[charset]
	lines := []string{r.paint.paint("check "+c.Zone, bold)}
	width := 0
	for _, area := range c.Areas {
		width = max(width, len(area.Area))
	}
	for _, area := range c.Areas {
		text := area.Text
		if area.More > 0 {
			text += r.paint.dim(fmt.Sprintf(" (and %d more)", area.More))
		}
		// spaced pads a glyph a terminal draws narrower than the emoji beside
		// it, which would pull its label out of line.
		mark := r.paint.paint(marks[area.Grade], gradeColors[area.Grade])
		mark = strings.Replace(spaced(marks[area.Grade]), marks[area.Grade], mark, 1)
		label := fmt.Sprintf("%-*s", width, area.Area)
		if area.Grade == trace.GradeSkipped {
			text = r.paint.dim(text)
		}
		lines = append(lines, "  "+mark+label+"  "+text)
	}

	var counts []string
	for _, said := range []struct {
		grade trace.Grade
		words string
	}{
		{trace.GradeBroken, "broken"},
		{trace.GradeLook, "to look at"},
		{trace.GradePassed, "passed"},
		{trace.GradeSkipped, "skipped"},
	} {
		if n := c.Count(said.grade); n > 0 {
			counts = append(counts, r.paint.paint(fmt.Sprintf("%d %s", n, said.words), gradeColors[said.grade]))
		}
	}
	return append(lines, strings.Join(counts, separator(charset)))
}
