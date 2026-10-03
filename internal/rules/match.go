package rules

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

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

// MatchSubject решает судьбу того, что ввёл человек — адреса или имени — и возвращает
// приведённую запись. Недописанный адрес и IPv6 — ошибка, а не имя: иначе ответ был бы
// правдоподобным, но неверным.
func (c *Config) MatchSubject(s string) (string, Decision, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return "", Decision{}, fmt.Errorf("%q: не удалось взять домен из ссылки", s)
		}
		s = u.Hostname()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if !a.Is4() {
			return "", Decision{}, fmt.Errorf("адрес %s: IPv6 пока не поддерживается", s)
		}
		return a.String(), c.MatchAddr(a), nil
	}
	if looksNumeric(s) {
		return "", Decision{}, fmt.Errorf("%q похоже на адрес, но записано неверно", s)
	}
	name, err := NormalizeName(s)
	if err != nil {
		return "", Decision{}, err
	}
	return name, c.MatchName(name), nil
}

// Explain объясняет по одним правилам, без сведений из DNS, куда пойдёт имя, адрес или ссылка.
func (c *Config) Explain(subject string) (string, error) {
	subj, d, err := c.MatchSubject(subject)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s → %s\n", subj, d.Action)
	if d.Rule != nil {
		fmt.Fprintf(&b, "правило, строка %d: %s\n", d.Rule.Line, d.Rule.Text)
	} else {
		fmt.Fprintf(&b, "ни одно правило не подошло, действует default (строка %d)\n", c.DefaultLine)
	}
	if e, found := c.Exit(d.Action.Exit); found {
		fmt.Fprintf(&b, "выход %s: %s\n", e.Name, strings.Join(e.Interfaces, ", "))
	} else {
		b.WriteString("выход direct: напрямую через провайдера\n")
	}
	return b.String(), nil
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
