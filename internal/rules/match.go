package rules

import "net/netip"

// Decision — результат сопоставления. Rule == nil означает, что сработал default;
// Index тогда равен числу правил, то есть ниже любого правила по старшинству.
type Decision struct {
	Index  int
	Rule   *Rule
	Action Action
}

func (c *Config) defaultDecision() Decision {
	return Decision{Index: len(c.Rules), Action: c.Default}
}

func (r *Rule) matchName(name string) bool {
	if len(r.Pos) == 0 && len(r.Neg) == 0 {
		return false
	}
	ok := len(r.Pos) == 0
	for _, c := range r.Pos {
		if c.Match(name) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	for _, c := range r.Neg {
		if c.Match(name) {
			return false
		}
	}
	return true
}

// MatchName находит первое правило, подходящее имени. Имя должно быть приведено NormalizeName.
func (c *Config) MatchName(name string) Decision {
	for i := range c.Rules {
		if c.Rules[i].matchName(name) {
			return Decision{Index: i, Rule: &c.Rules[i], Action: c.Rules[i].Action}
		}
	}
	return c.defaultDecision()
}

// MatchAddr находит первое правило, в чьи адреса и подсети входит a.
func (c *Config) MatchAddr(a netip.Addr) Decision {
	for i := range c.Rules {
		for _, n := range c.Rules[i].Nets {
			if n.Contains(a) {
				return Decision{Index: i, Rule: &c.Rules[i], Action: c.Rules[i].Action}
			}
		}
	}
	return c.defaultDecision()
}

// MatchChain решает судьбу DNS-ответа: names — запрошенное имя и его CNAME-цели по порядку.
// Берётся первое имя цепочки, для которого нашлось правило.
func (c *Config) MatchChain(names []string) Decision {
	for _, n := range names {
		if d := c.MatchName(n); d.Rule != nil {
			return d
		}
	}
	return c.defaultDecision()
}
