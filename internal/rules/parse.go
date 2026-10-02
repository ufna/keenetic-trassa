package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Direct — имя выхода напрямую через провайдера.
const Direct = "direct"

type Severity int

const (
	Error Severity = iota
	Warning
)

// Problem — ошибка или предупреждение в файле правил. Line == 0, если к строке не привязано.
type Problem struct {
	Line     int
	Severity Severity
	Msg      string
}

func (p Problem) String() string {
	kind := "ошибка"
	if p.Severity == Warning {
		kind = "предупреждение"
	}
	if p.Line == 0 {
		return kind + ": " + p.Msg
	}
	return fmt.Sprintf("строка %d: %s: %s", p.Line, kind, p.Msg)
}

func HasErrors(ps []Problem) bool {
	for _, p := range ps {
		if p.Severity == Error {
			return true
		}
	}
	return false
}

// Exit — выход: упорядоченный список интерфейсов, первый живой используется.
type Exit struct {
	Name       string
	Interfaces []string
	Line       int
}

// Action — куда направить трафик. Exit == Direct означает «через провайдера».
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
	Pos    []Cond // подходит хотя бы одно (если есть)
	Neg    []Cond // не подходит ни одно
	Nets   []netip.Prefix
	Action Action
}

// Test — ожидание из строки «test <имя или адрес> = <выход>».
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

// ReadFile читает файл, на который ссылается условие @путь.
type ReadFile func(path string) (string, error)

// Parse разбирает текст правил. Возвращает ошибки разбора; ожидания и предупреждения проверяет Check.
func Parse(src string, read ReadFile) (*Config, []Problem) {
	p := &parser{cfg: &Config{}, read: read}
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

// clean убирает комментарий, возврат каретки и пробелы по краям.
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

func (p *parser) exit(n int, rest string) {
	name, list, ok := strings.Cut(rest, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		p.errf(n, "ожидается: exit <имя> = <интерфейс>, <интерфейс>...")
		return
	}
	if !validIdent(name) {
		p.errf(n, "имя выхода %q: допустимы строчные латинские буквы, цифры, - и _", name)
		return
	}
	if name == Direct {
		p.errf(n, "имя %q занято: так называется путь напрямую через провайдера", Direct)
		return
	}
	if _, dup := p.cfg.Exit(name); dup {
		p.errf(n, "выход %q уже объявлен", name)
		return
	}
	var ifs []string
	for _, x := range strings.Split(list, ",") {
		x = strings.TrimSpace(x)
		if x == "" || strings.ContainsAny(x, " \t") {
			p.errf(n, "пустое имя интерфейса в списке или пропущена запятая")
			return
		}
		ifs = append(ifs, x)
	}
	p.cfg.Exits = append(p.cfg.Exits, Exit{Name: name, Interfaces: ifs, Line: n})
}

func (p *parser) action(n int, f []string) (Action, bool) {
	if len(f) == 0 || len(f) > 2 || len(f) == 2 && f[1] != "strict" {
		p.errf(n, "ожидается выход: direct или <имя выхода> [strict]")
		return Action{}, false
	}
	a := Action{Exit: f[0], Strict: len(f) == 2}
	if a.Exit == Direct && a.Strict {
		p.errf(n, "strict не имеет смысла для direct")
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
		p.errf(n, "default уже задан в строке %d", p.cfg.DefaultLine)
		return
	}
	p.cfg.Default, p.cfg.DefaultLine = a, n
}

func (p *parser) test(n int, rest string) {
	subj, want, ok := strings.Cut(rest, "=")
	subj, want = strings.TrimSpace(subj), strings.TrimSpace(want)
	if !ok || subj == "" || want == "" || strings.ContainsAny(subj+want, " \t") {
		p.errf(n, "ожидается: test <имя или адрес> = <выход>")
		return
	}
	p.refs = append(p.refs, exitRef{n, want})
	p.cfg.Tests = append(p.cfg.Tests, Test{Line: n, Subject: subj, Want: want})
}

func (p *parser) rule(n int, s string) {
	left, right, ok := strings.Cut(s, "->")
	if !ok {
		p.errf(n, "не понимаю строку: ожидается «условия -> выход», exit, default или test")
		return
	}
	toks := strings.Fields(left)
	if len(toks) == 0 {
		p.errf(n, "перед -> нет ни одного условия")
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
		p.errf(n, "после @ нужен путь к файлу")
		return false
	}
	if p.read == nil {
		p.errf(n, "файл %s: включение файлов здесь недоступно", path)
		return false
	}
	text, err := p.read(path)
	if err != nil {
		p.errf(n, "файл %s: %v", path, err)
		return false
	}
	good, count := true, 0
	for i, raw := range strings.Split(strings.TrimPrefix(text, "\uFEFF"), "\n") {
		for _, tok := range strings.Fields(clean(raw)) {
			count++
			if strings.HasPrefix(tok, "@") {
				p.errf(n, "файл %s, строка %d: вложенные включения не поддерживаются", path, i+1)
				good = false
				continue
			}
			if err := r.add(tok); err != nil {
				p.errf(n, "файл %s, строка %d: %v", path, i+1, err)
				good = false
			}
		}
	}
	if count == 0 {
		p.errf(n, "файл %s пуст", path)
		return false
	}
	return good
}

// add добавляет в правило одно условие: по имени (с отрицанием или без) либо адрес или подсеть.
func (r *Rule) add(tok string) error {
	neg := strings.HasPrefix(tok, "!")
	if neg {
		tok = tok[1:]
	}
	if tok == "" {
		return errors.New("пустое условие")
	}
	if !strings.HasPrefix(tok, "~") {
		pfx, isNet, err := parseNet(tok)
		if err != nil {
			return err
		}
		if isNet {
			if neg {
				return fmt.Errorf("условие !%s: отрицание адресов и подсетей не поддерживается", tok)
			}
			r.Nets = append(r.Nets, pfx)
			return nil
		}
		if strings.Trim(tok, "0123456789.") == "" {
			return fmt.Errorf("условие %q похоже на адрес, но записано неверно", tok)
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

// parseNet распознаёт IPv4-адрес или подсеть. isNet == false означает «это не адрес, а имя».
func parseNet(tok string) (pfx netip.Prefix, isNet bool, err error) {
	if a, e := netip.ParseAddr(tok); e == nil {
		if !a.Is4() {
			return pfx, true, fmt.Errorf("адрес %s: IPv6 пока не поддерживается", tok)
		}
		return netip.PrefixFrom(a, 32), true, nil
	}
	if !strings.Contains(tok, "/") {
		return pfx, false, nil
	}
	p, e := netip.ParsePrefix(tok)
	if e != nil {
		return pfx, true, fmt.Errorf("подсеть %q: неверная запись", tok)
	}
	if !p.Addr().Is4() {
		return pfx, true, fmt.Errorf("подсеть %s: IPv6 пока не поддерживается", tok)
	}
	return p.Masked(), true, nil
}

func (p *parser) finish() {
	if p.cfg.DefaultLine == 0 {
		p.errf(0, "нет строки default: укажите, куда идёт всё, что не подошло ни под одно правило")
	}
	for _, ref := range p.refs {
		if ref.name == Direct {
			continue
		}
		if _, ok := p.cfg.Exit(ref.name); !ok {
			p.errf(ref.line, "выход %q не объявлен (нужна строка: exit %s = <интерфейсы>)", ref.name, ref.name)
		}
	}
	sort.SliceStable(p.problems, func(i, j int) bool { return p.problems[i].Line < p.problems[j].Line })
}
