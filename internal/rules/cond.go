package rules

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type condKind int

const (
	condSuffix condKind = iota // домен и все поддомены
	condExact                  // только точное имя
	condSub                    // только поддомены
	condRegex
)

// Cond — одно условие по имени.
type Cond struct {
	Text string // запись условия как в файле правил
	kind condKind
	name string
	re   *regexp.Regexp
}

// parseCond разбирает условие без ведущего «!».
func parseCond(tok string) (Cond, error) {
	c := Cond{Text: tok}
	if strings.HasPrefix(tok, "~") {
		if tok == "~" {
			return c, errors.New("пустое регулярное выражение")
		}
		for _, r := range tok {
			if r >= 0x80 {
				return c, fmt.Errorf("регулярное выражение %q: имена сравниваются в виде xn--…, поэтому символ U+%04X не совпадёт никогда", tok[1:], r)
			}
		}
		// Имена приводятся к нижнему регистру, поэтому выражение сравнивается без учёта регистра.
		re, err := regexp.Compile("(?i)" + tok[1:])
		if err != nil {
			return c, fmt.Errorf("регулярное выражение %q: %v", tok[1:], err)
		}
		c.kind, c.re = condRegex, re
		return c, nil
	}
	name := tok
	switch {
	case strings.HasPrefix(tok, "="):
		c.kind, name = condExact, tok[1:]
	case strings.HasPrefix(tok, "*."):
		c.kind, name = condSub, tok[2:]
	default:
		c.kind = condSuffix
	}
	if strings.Contains(name, "*") {
		return c, fmt.Errorf("условие %q: звёздочка допустима только в начале, в виде *.example.com", tok)
	}
	if looksNumeric(name) {
		return c, fmt.Errorf("условие %q похоже на адрес: адреса и подсети пишутся без =, *. и !", tok)
	}
	n, err := NormalizeName(name)
	if err != nil {
		return c, fmt.Errorf("условие %q: %w", tok, err)
	}
	c.name = n
	return c, nil
}

// Match сообщает, подходит ли имя под условие. Имя должно быть приведено NormalizeName.
func (c Cond) Match(name string) bool {
	switch c.kind {
	case condExact:
		return name == c.name
	case condSuffix:
		return name == c.name || strings.HasSuffix(name, "."+c.name)
	case condSub:
		return strings.HasSuffix(name, "."+c.name)
	case condRegex:
		return c.re.MatchString(name)
	}
	return false
}

// disjoint сообщает, что ни одно имя не подходит под оба условия сразу.
// Проверка осторожная: для регулярных выражений ответ всегда «нет».
func (a Cond) disjoint(b Cond) bool {
	if a.kind == condRegex || b.kind == condRegex {
		return false
	}
	return a.name != b.name && !strings.HasSuffix(a.name, "."+b.name) && !strings.HasSuffix(b.name, "."+a.name)
}

// covers сообщает, что любое имя, подходящее под b, подходит и под a.
// Для регулярных выражений ответ всегда «нет»: проверка намеренно осторожная.
func (a Cond) covers(b Cond) bool {
	if a.kind == condRegex || b.kind == condRegex {
		return false
	}
	same := a.name == b.name
	under := strings.HasSuffix(b.name, "."+a.name)
	switch a.kind {
	case condSuffix:
		return same || under
	case condExact:
		return b.kind == condExact && same
	case condSub:
		if b.kind == condSub {
			return same || under
		}
		return under
	}
	return false
}
