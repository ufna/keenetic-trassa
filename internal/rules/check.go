package rules

import (
	"fmt"
	"math/bits"
	"sort"
	"strings"
)

// Load parses the rules and, if parsing succeeded without errors, checks expectations and reports warnings.
func Load(src string, read ReadFile) (*Config, []Problem) {
	cfg, ps := Parse(src, read)
	if HasErrors(ps) {
		return cfg, ps
	}
	return cfg, append(ps, Check(cfg)...)
}

// Check verifies test expectations and looks for suspicious rules.
func Check(c *Config) []Problem {
	var ps []Problem
	if len(c.Exits) > MaxExits {
		ps = append(ps, Problem{c.Exits[MaxExits].Line, Error,
			fmt.Sprintf("%d exits: at most %d are supported", len(c.Exits), MaxExits)})
	}
	if c.Default.Strict {
		ps = append(ps, Problem{c.DefaultLine, Warning,
			"strict in default: if all of the exit's tunnels go down, the whole internet is lost except for direct rules"})
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		// Negation only: almost the whole internet falls under the rule. A negation next to ordinary
		// conditions only narrows the rule, and warning about it would teach people to confirm without looking.
		if r.Action.Strict && len(r.Neg) > 0 && len(r.Pos) == 0 && len(r.Nets) == 0 {
			ps = append(ps, Problem{r.Line, Warning,
				"strict on a negation rule: if all of the exit's tunnels go down, almost the whole internet is lost"})
		}
		if by := c.shadowedBy(i); by != "" {
			ps = append(ps, Problem{r.Line, Warning,
				"rule can never match: its conditions are covered by earlier rules (" + by + ")"})
		}
	}
	for _, t := range c.Tests {
		if p, failed := c.runTest(t); failed {
			ps = append(ps, p)
		}
	}
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Line < ps[j].Line })
	return ps
}

// takes reports that the rule certainly takes every name matching condition b:
// b is covered by one of the ordinary conditions (or there are none) and overlaps none of the negations.
func (r *Rule) takes(b Cond) bool {
	if len(r.Pos) == 0 && len(r.Neg) == 0 {
		return false
	}
	if len(r.Pos) > 0 {
		covered := false
		for _, c := range r.Pos {
			if c.covers(b) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	for _, c := range r.Neg {
		if !c.disjoint(b) {
			return false
		}
	}
	return true
}

// shadowedBy returns the list of lines of earlier rules that fully cover rule i,
// or an empty string. The check is conservative: rule i is not judged if it has negations,
// and regular expressions are never judged.
func (c *Config) shadowedBy(i int) string {
	r := &c.Rules[i]
	if len(r.Neg) > 0 {
		return ""
	}
	lines := map[int]bool{}
	for _, cond := range r.Pos {
		line := 0
		for j := 0; j < i && line == 0; j++ {
			if c.Rules[j].coversDevices(r) && c.Rules[j].takes(cond) {
				line = c.Rules[j].Line
			}
		}
		if line == 0 {
			return ""
		}
		lines[line] = true
	}
	for _, n := range r.Nets {
		line := 0
		for j := 0; j < i && line == 0; j++ {
			if !c.Rules[j].coversDevices(r) {
				continue
			}
			for _, en := range c.Rules[j].Nets {
				if en.Bits() <= n.Bits() && en.Contains(n.Addr()) {
					line = c.Rules[j].Line
					break
				}
			}
		}
		if line == 0 {
			return ""
		}
		lines[line] = true
	}
	var sorted []int
	for l := range lines {
		sorted = append(sorted, l)
	}
	sort.Ints(sorted)
	parts := make([]string, len(sorted))
	for k, l := range sorted {
		parts[k] = fmt.Sprintf("line %d", l)
	}
	return strings.Join(parts, ", ")
}

func (c *Config) runTest(t Test) (Problem, bool) {
	_, d, err := c.MatchSubject(t.Subject)
	if err != nil {
		return Problem{t.Line, Error, fmt.Sprintf("test: %v", err)}, true
	}
	if d.Action.Exit == t.Want {
		return Problem{}, false
	}
	where := "by default"
	if d.Rule != nil {
		where = fmt.Sprintf("by the rule on line %d", d.Rule.Line)
	}
	return Problem{t.Line, Error, fmt.Sprintf("expectation failed: %s goes to %s (%s), expected %s",
		t.Subject, d.Action.Exit, where, t.Want)}, true
}

// coversDevices reports that rule r applies to every device that rule o applies to. Only the lists
// the two rules name matter, and every combination of them is tried; when there are too many to
// try, the answer is a cautious false.
func (r *Rule) coversDevices(o *Rule) bool {
	if r.forMask == 0 && r.notMask == 0 {
		return true
	}
	named := r.forMask | r.notMask | o.forMask | o.notMask
	if bits.OnesCount16(uint16(named)) > 12 {
		return false
	}
	for v := named; ; v = (v - 1) & named {
		if o.AppliesTo(v) && !r.AppliesTo(v) {
			return false
		}
		if v == 0 {
			return true
		}
	}
}
