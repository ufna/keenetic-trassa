package rules

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Load разбирает правила и, если разбор прошёл без ошибок, проверяет ожидания и выдаёт предупреждения.
func Load(src string, read ReadFile) (*Config, []Problem) {
	cfg, ps := Parse(src, read)
	if HasErrors(ps) {
		return cfg, ps
	}
	return cfg, append(ps, Check(cfg)...)
}

// Check проверяет ожидания test и ищет подозрительные правила.
func Check(c *Config) []Problem {
	var ps []Problem
	if c.Default.Strict {
		ps = append(ps, Problem{c.DefaultLine, Warning,
			"strict в default: при падении всех туннелей выхода пропадёт весь интернет, кроме правил direct"})
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Action.Strict && len(r.Neg) > 0 {
			ps = append(ps, Problem{r.Line, Warning,
				"strict на правиле с отрицанием: при падении всех туннелей выхода пропадёт почти весь интернет"})
		}
		if by := c.shadowedBy(i); by != "" {
			ps = append(ps, Problem{r.Line, Warning,
				"правило никогда не сработает: его условия перекрыты более ранними правилами (" + by + ")"})
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

// shadowedBy возвращает перечень строк более ранних правил, целиком перекрывающих правило i,
// или пустую строку. Проверка осторожная: правила с отрицанием и регулярные выражения не судятся.
func (c *Config) shadowedBy(i int) string {
	r := &c.Rules[i]
	if len(r.Neg) > 0 {
		return ""
	}
	lines := map[int]bool{}
	for _, cond := range r.Pos {
		line := 0
		for j := 0; j < i && line == 0; j++ {
			e := &c.Rules[j]
			if len(e.Neg) > 0 {
				continue
			}
			for _, ec := range e.Pos {
				if ec.covers(cond) {
					line = e.Line
					break
				}
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
		parts[k] = fmt.Sprintf("строка %d", l)
	}
	return strings.Join(parts, ", ")
}

func (c *Config) runTest(t Test) (Problem, bool) {
	var d Decision
	if a, err := netip.ParseAddr(t.Subject); err == nil {
		d = c.MatchAddr(a)
	} else {
		n, err := NormalizeName(t.Subject)
		if err != nil {
			return Problem{t.Line, Error, fmt.Sprintf("test: %v", err)}, true
		}
		d = c.MatchName(n)
	}
	if d.Action.Exit == t.Want {
		return Problem{}, false
	}
	where := "по default"
	if d.Rule != nil {
		where = fmt.Sprintf("по правилу в строке %d", d.Rule.Line)
	}
	return Problem{t.Line, Error, fmt.Sprintf("ожидание не выполнено: %s идёт в %s (%s), а ожидалось %s",
		t.Subject, d.Action.Exit, where, t.Want)}, true
}
