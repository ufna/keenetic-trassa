// Package rules parses the trassa rules file and matches names and addresses against the rules.
package rules

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// NormalizeName brings a domain name to the form used for comparison:
// lowercase, no trailing dot, labels with non-ASCII characters in punycode.
func NormalizeName(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" {
		return "", errors.New("empty name")
	}
	labels := strings.Split(strings.ToLower(s), ".")
	for i, l := range labels {
		if l == "" {
			return "", fmt.Errorf("name %q: empty label", s)
		}
		a, err := toASCIILabel(l)
		if err != nil {
			return "", fmt.Errorf("name %q: %w", s, err)
		}
		labels[i] = a
	}
	name := strings.Join(labels, ".")
	if len(name) > 253 {
		return "", errors.New("name is longer than 253 characters")
	}
	return name, nil
}

// looksNumeric reports that the text consists only of digits and dots, i.e. looks like an address.
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
			// Invisible characters, punctuation, traces of a wrong encoding: no real domain
			// matches such a name, so it is an error rather than punycode.
			return "", fmt.Errorf("invalid character U+%04X (if you really need it, write the label in xn--… form)", r)
		}
	}
	if latin && other {
		return "", fmt.Errorf("label %q mixes Latin and non-Latin letters: check the keyboard layout", l)
	}
	if nonASCII {
		l = "xn--" + punycodeEncode(l)
	}
	if len(l) > 63 {
		return "", errors.New("label is longer than 63 characters")
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", fmt.Errorf("invalid character %q", c)
		}
	}
	return l, nil
}

// Punycode parameters from RFC 3492.
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
