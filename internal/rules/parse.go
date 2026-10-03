package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

// Direct is the name of the exit that goes straight through the ISP.
const Direct = "direct"

// MaxExits is how many exits can be declared: each one needs two routing tables,
// and trassa's table numbers are 540–599.
const MaxExits = 29

type Severity int

const (
	Error Severity = iota
	Warning
)

// Problem is an error or a warning in the rules file. Line == 0 if it is not tied to a line.
type Problem struct {
	Line     int
	Severity Severity
	Msg      string
}

func (p Problem) String() string {
	kind := "error"
	if p.Severity == Warning {
		kind = "warning"
	}
	if p.Line == 0 {
		return kind + ": " + p.Msg
	}
	return fmt.Sprintf("line %d: %s: %s", p.Line, kind, p.Msg)
}

func HasErrors(ps []Problem) bool {
	for _, p := range ps {
		if p.Severity == Error {
			return true
		}
	}
	return false
}

// Exit is an ordered list of interfaces; the first live one is used.
type Exit struct {
	Name       string
	Interfaces []string
	Line       int
}

// Action says where to send traffic. Exit == Direct means "through the ISP".
type Action struct {
	Exit   string
	Strict bool
}

func (a Action) String() string {
	if a.Strict {
		return a.Exit + " strict"
	}
	return a.Exit
}

type Rule struct {
	Line   int
	Text   string
	Pos    []Cond // at least one matches (if any)
	Neg    []Cond // none matches
	Nets   []netip.Prefix
	Action Action
}

// Test is an expectation from a "test <name or address> = <exit>" line.
type Test struct {
	Line    int
	Subject string
	Want    string
}

type Config struct {
	Exits       []Exit
	Default     Action
	DefaultLine int
	Rules       []Rule
	Tests       []Test
}

func (c *Config) Exit(name string) (Exit, bool) {
	for _, e := range c.Exits {
		if e.Name == name {
			return e, true
		}
	}
	return Exit{}, false
}

// ReadFile reads the file referenced by an @path condition.
type ReadFile func(path string) (string, error)

// Parse parses the rules text. It returns parse errors; expectations and warnings are checked by Check.
func Parse(src string, read ReadFile) (*Config, []Problem) {
	p := &parser{cfg: &Config{}, read: read}
	if !utf8.ValidString(src) {
		p.errf(0, "the file is not UTF-8 encoded: re-save it as UTF-8")
		return p.cfg, p.problems
	}
	for i, line := range strings.Split(strings.TrimPrefix(src, "\uFEFF"), "\n") {
		p.line(i+1, line)
	}
	p.finish()
	return p.cfg, p.problems
}

type exitRef struct {
	line int
	name string
}

type parser struct {
	cfg      *Config
	read     ReadFile
	problems []Problem
	refs     []exitRef
}

func (p *parser) errf(line int, format string, args ...any) {
	p.problems = append(p.problems, Problem{line, Error, fmt.Sprintf(format, args...)})
}

// clean strips a comment, a carriage return and surrounding whitespace.
func clean(raw string) string {
	s := strings.TrimRight(raw, "\r")
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			s = s[:i]
			break
		}
	}
	return strings.TrimSpace(s)
}

func (p *parser) line(n int, raw string) {
	s := clean(raw)
	if s == "" {
		return
	}
	f := strings.Fields(s)
	switch f[0] {
	case "exit":
		p.exit(n, s[len("exit"):])
	case "default":
		p.def(n, f[1:])
	case "test":
		p.test(n, s[len("test"):])
	default:
		p.rule(n, s)
	}
}

func validIdent(s string) bool {
	if s == "" || s == "strict" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// validIface accepts only the characters that firmware interface names consist of:
// the name is later substituted into a router command.
func validIface(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '.' || c == '/' || c == '-') {
			return false
		}
	}
	return true
}

func (p *parser) exit(n int, rest string) {
	name, list, ok := strings.Cut(rest, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		p.errf(n, "expected: exit <name> = <interface>, <interface>...")
		return
	}
	if !validIdent(name) {
		p.errf(n, "exit name %q: only lowercase Latin letters, digits, - and _ are allowed", name)
		return
	}
	if name == Direct {
		p.errf(n, "name %q is reserved: it is the direct path through the ISP", Direct)
		return
	}
	if _, dup := p.cfg.Exit(name); dup {
		p.errf(n, "exit %q is already declared", name)
		return
	}
	var ifs []string
	for _, x := range strings.Split(list, ",") {
		x = strings.TrimSpace(x)
		if x == "" || strings.ContainsAny(x, " \t") {
			p.errf(n, "empty interface name in the list, or a missing comma")
			return
		}
		if !validIface(x) {
			p.errf(n, "interface name %q: only Latin letters, digits and the characters _ . / - are allowed", x)
			return
		}
		ifs = append(ifs, x)
	}
	p.cfg.Exits = append(p.cfg.Exits, Exit{Name: name, Interfaces: ifs, Line: n})
}

func (p *parser) action(n int, f []string) (Action, bool) {
	if len(f) == 0 || len(f) > 2 || len(f) == 2 && f[1] != "strict" {
		p.errf(n, "expected an exit: direct or <exit name> [strict]")
		return Action{}, false
	}
	a := Action{Exit: f[0], Strict: len(f) == 2}
	if a.Exit == Direct && a.Strict {
		p.errf(n, "strict makes no sense for direct")
		return Action{}, false
	}
	p.refs = append(p.refs, exitRef{n, a.Exit})
	return a, true
}

func (p *parser) def(n int, f []string) {
	a, ok := p.action(n, f)
	if !ok {
		return
	}
	if p.cfg.DefaultLine != 0 {
		p.errf(n, "default is already set on line %d", p.cfg.DefaultLine)
		return
	}
	p.cfg.Default, p.cfg.DefaultLine = a, n
}

func (p *parser) test(n int, rest string) {
	subj, want, ok := strings.Cut(rest, "=")
	subj, want = strings.TrimSpace(subj), strings.TrimSpace(want)
	if !ok || subj == "" || want == "" || strings.ContainsAny(subj+want, " \t") {
		p.errf(n, "expected: test <name or address> = <exit>")
		return
	}
	p.refs = append(p.refs, exitRef{n, want})
	p.cfg.Tests = append(p.cfg.Tests, Test{Line: n, Subject: subj, Want: want})
}

func (p *parser) rule(n int, s string) {
	left, right, ok := strings.Cut(s, "->")
	if !ok {
		p.errf(n, `cannot parse the line: expected "conditions -> exit", exit, default or test`)
		return
	}
	toks := strings.Fields(left)
	if len(toks) == 0 {
		p.errf(n, "no conditions before ->")
		return
	}
	a, ok := p.action(n, strings.Fields(right))
	if !ok {
		return
	}
	r := Rule{Line: n, Text: s, Action: a}
	good := true
	for _, tok := range toks {
		if strings.HasPrefix(tok, "@") {
			good = p.include(n, tok[1:], &r) && good
			continue
		}
		if err := r.add(tok); err != nil {
			p.errf(n, "%v", err)
			good = false
		}
	}
	if good {
		p.cfg.Rules = append(p.cfg.Rules, r)
	}
}

func (p *parser) include(n int, path string, r *Rule) bool {
	if path == "" {
		p.errf(n, "a file path is needed after @")
		return false
	}
	if p.read == nil {
		p.errf(n, "file %s: including files is not available here", path)
		return false
	}
	text, err := p.read(path)
	if err != nil {
		p.errf(n, "file %s: %v", path, err)
		return false
	}
	if !utf8.ValidString(text) {
		p.errf(n, "file %s is not UTF-8 encoded: re-save it as UTF-8", path)
		return false
	}
	good, count := true, 0
	for i, raw := range strings.Split(strings.TrimPrefix(text, "\uFEFF"), "\n") {
		for _, tok := range strings.Fields(clean(raw)) {
			count++
			if strings.HasPrefix(tok, "@") {
				p.errf(n, "file %s, line %d: nested includes are not supported", path, i+1)
				good = false
				continue
			}
			if err := r.add(tok); err != nil {
				p.errf(n, "file %s, line %d: %v", path, i+1, err)
				good = false
			}
		}
	}
	if count == 0 {
		p.errf(n, "file %s is empty", path)
		return false
	}
	return good
}

// linkError explains that a link was pasted instead of a domain and suggests the domain from it.
func linkError(tok string) error {
	if u, err := url.Parse(tok); err == nil && u.Hostname() != "" {
		return fmt.Errorf("condition %q is a link, but a domain is needed: %s", tok, u.Hostname())
	}
	return fmt.Errorf("condition %q is a link, but a domain is needed", tok)
}

// add adds one condition to the rule: a name (negated or not), or an address or subnet.
func (r *Rule) add(tok string) error {
	neg := strings.HasPrefix(tok, "!")
	if neg {
		tok = tok[1:]
	}
	if tok == "" {
		return errors.New("empty condition")
	}
	if strings.Contains(tok, "://") && !strings.HasPrefix(tok, "~") {
		return linkError(tok)
	}
	if tok == "strict" || tok == Direct {
		return fmt.Errorf("the word %q is among the conditions, but it belongs after ->", tok)
	}
	if !strings.HasPrefix(tok, "~") {
		pfx, isNet, err := parseNet(tok)
		if err != nil {
			return err
		}
		if isNet {
			if neg {
				return fmt.Errorf("condition !%s: negating addresses and subnets is not supported", tok)
			}
			r.Nets = append(r.Nets, pfx)
			return nil
		}
		if looksNumeric(tok) {
			return fmt.Errorf("condition %q looks like an address but is malformed", tok)
		}
	}
	c, err := parseCond(tok)
	if err != nil {
		return err
	}
	if neg {
		c.Text = "!" + c.Text
		r.Neg = append(r.Neg, c)
	} else {
		r.Pos = append(r.Pos, c)
	}
	return nil
}

// parseNet recognizes an IPv4 address or subnet. isNet == false means "not an address but a name".
func parseNet(tok string) (pfx netip.Prefix, isNet bool, err error) {
	if a, e := netip.ParseAddr(tok); e == nil {
		if !a.Is4() {
			return pfx, true, fmt.Errorf("address %s: IPv6 is not supported yet", tok)
		}
		return netip.PrefixFrom(a, 32), true, nil
	}
	if !strings.Contains(tok, "/") {
		return pfx, false, nil
	}
	p, e := netip.ParsePrefix(tok)
	if e != nil {
		return pfx, true, fmt.Errorf("subnet %q: malformed", tok)
	}
	if !p.Addr().Is4() {
		return pfx, true, fmt.Errorf("subnet %s: IPv6 is not supported yet", tok)
	}
	if p.Bits() == 0 {
		return pfx, true, fmt.Errorf(`subnet %s: "everything else" is not a subnet; use default for that`, tok)
	}
	return p.Masked(), true, nil
}

func (p *parser) finish() {
	if p.cfg.DefaultLine == 0 {
		p.errf(0, "no default line: specify where everything that matches no rule should go")
	}
	for _, ref := range p.refs {
		if ref.name == Direct {
			continue
		}
		if _, ok := p.cfg.Exit(ref.name); !ok {
			p.errf(ref.line, "exit %q is not declared (add a line: exit %s = <interfaces>)", ref.name, ref.name)
		}
	}
	// An exit name among the conditions almost certainly means a misplaced arrow: "youtube.com vpn -> direct".
	for _, r := range p.cfg.Rules {
		for _, c := range append(append([]Cond(nil), r.Pos...), r.Neg...) {
			name := strings.TrimPrefix(c.Text, "!")
			if _, ok := p.cfg.Exit(name); ok {
				p.errf(r.Line, "condition %q is an exit name, not a domain: the exit goes after ->; if you mean a domain zone, write it as *.%s", c.Text, name)
			}
		}
	}
	sort.SliceStable(p.problems, func(i, j int) bool { return p.problems[i].Line < p.problems[j].Line })
}
