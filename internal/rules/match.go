package rules

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Decision is the result of matching. Rule == nil means the default applied;
// Index is then the number of rules, i.e. lower in precedence than any rule.
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

// MatchName finds the first rule matching the name. The name must be normalized with NormalizeName.
func (c *Config) MatchName(name string) Decision {
	for i := range c.Rules {
		if c.Rules[i].matchName(name) {
			return Decision{Index: i, Rule: &c.Rules[i], Action: c.Rules[i].Action}
		}
	}
	return c.defaultDecision()
}

// MatchAddr finds the first rule whose addresses and subnets contain a.
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

// MatchSubject decides what happens to whatever a person typed, an address or a name, and returns
// its normalized form. An incomplete address or IPv6 is an error, not a name: otherwise the answer
// would be plausible but wrong.
func (c *Config) MatchSubject(s string) (string, Decision, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return "", Decision{}, fmt.Errorf("%q: could not take a domain from the link", s)
		}
		s = u.Hostname()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if !a.Is4() {
			return "", Decision{}, fmt.Errorf("address %s: IPv6 is not supported yet", s)
		}
		return a.String(), c.MatchAddr(a), nil
	}
	if looksNumeric(s) {
		return "", Decision{}, fmt.Errorf("%q looks like an address but is malformed", s)
	}
	name, err := NormalizeName(s)
	if err != nil {
		return "", Decision{}, err
	}
	return name, c.MatchName(name), nil
}

// Explain explains, from the rules alone and without DNS data, where a name, address or link will go.
func (c *Config) Explain(subject string) (string, error) {
	subj, d, err := c.MatchSubject(subject)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s → %s\n", subj, d.Action)
	if d.Rule != nil {
		fmt.Fprintf(&b, "rule, line %d: %s\n", d.Rule.Line, d.Rule.Text)
	} else {
		fmt.Fprintf(&b, "no rule matched; default applies (line %d)\n", c.DefaultLine)
	}
	if e, found := c.Exit(d.Action.Exit); found {
		fmt.Fprintf(&b, "exit %s: %s\n", e.Name, strings.Join(e.Interfaces, ", "))
	} else {
		b.WriteString("exit direct: straight through the ISP\n")
	}
	return b.String(), nil
}

// MatchChain decides what happens to a DNS response: names are the queried name and its CNAME targets in order.
// The first name in the chain that has a matching rule wins.
func (c *Config) MatchChain(names []string) Decision {
	for _, n := range names {
		if d := c.MatchName(n); d.Rule != nil {
			return d
		}
	}
	return c.defaultDecision()
}
