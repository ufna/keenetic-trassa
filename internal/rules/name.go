// Package rules разбирает файл правил trassa и сопоставляет имена и адреса с правилами.
package rules

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// NormalizeName приводит доменное имя к виду, в котором оно сравнивается:
// нижний регистр, без точки в конце, метки с не-ASCII символами — в punycode.
func NormalizeName(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" {
		return "", errors.New("пустое имя")
	}
	labels := strings.Split(strings.ToLower(s), ".")
	for i, l := range labels {
		if l == "" {
			return "", fmt.Errorf("имя %q: пустая метка", s)
		}
		a, err := toASCIILabel(l)
		if err != nil {
			return "", fmt.Errorf("имя %q: %w", s, err)
		}
		labels[i] = a
	}
	return strings.Join(labels, "."), nil
}

// looksNumeric сообщает, что запись состоит только из цифр и точек, то есть похожа на адрес.
func looksNumeric(s string) bool {
	return s != "" && strings.Trim(s, "0123456789.") == ""
}

func toASCIILabel(l string) (string, error) {
	latin, other, nonASCII := false, false, false
	for _, r := range l {
		switch {
		case r < 0x80:
			latin = latin || r >= 'a' && r <= 'z'
		case unicode.IsLetter(r):
			nonASCII = true
			if unicode.Is(unicode.Latin, r) {
				latin = true
			} else {
				other = true
			}
		case unicode.IsDigit(r):
			nonASCII = true
		default:
			// Невидимые символы, знаки препинания, следы неверной кодировки: под такое имя
			// не подойдёт ни один настоящий домен, поэтому это ошибка, а не punycode.
			return "", fmt.Errorf("недопустимый символ U+%04X (если он действительно нужен, запишите метку в виде xn--…)", r)
		}
	}
	if latin && other {
		return "", fmt.Errorf("в метке %q смешаны латинские и нелатинские буквы — проверьте раскладку", l)
	}
	if nonASCII {
		l = "xn--" + punycodeEncode(l)
	}
	if len(l) > 63 {
		return "", errors.New("метка длиннее 63 символов")
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", fmt.Errorf("недопустимый символ %q", c)
		}
	}
	return l, nil
}

// Параметры punycode из RFC 3492.
const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

func punycodeEncode(s string) string {
	in := []rune(s)
	var out []byte
	for _, r := range in {
		if r < 0x80 {
			out = append(out, byte(r))
		}
	}
	basic := len(out)
	handled := basic
	if basic > 0 {
		out = append(out, '-')
	}
	n, delta, bias := rune(pcInitialN), 0, pcInitialBias
	for handled < len(in) {
		m := rune(0x10FFFF)
		for _, r := range in {
			if r >= n && r < m {
				m = r
			}
		}
		delta += int(m-n) * (handled + 1)
		n = m
		for _, r := range in {
			if r < n {
				delta++
			}
			if r != n {
				continue
			}
			q := delta
			for k := pcBase; ; k += pcBase {
				t := k - bias
				if t < pcTMin {
					t = pcTMin
				} else if t > pcTMax {
					t = pcTMax
				}
				if q < t {
					break
				}
				out = append(out, pcDigit(t+(q-t)%(pcBase-t)))
				q = (q - t) / (pcBase - t)
			}
			out = append(out, pcDigit(q))
			bias = pcAdapt(delta, handled+1, handled == basic)
			delta = 0
			handled++
		}
		delta++
		n++
	}
	return string(out)
}

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func pcAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}
