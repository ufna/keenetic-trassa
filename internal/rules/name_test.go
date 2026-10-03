package rules

import (
	"strings"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"  yOuTuBe.CoM.  ", "youtube.com"},
		{"рф", "xn--p1ai"},
		{"РФ", "xn--p1ai"},
		{"москва.рф", "xn--80adxhks.xn--p1ai"},
		{"испытание", "xn--80akhbyknj4f"},
		{"bücher.example", "xn--bcher-kva.example"},
		{"xn--p1ai", "xn--p1ai"},
		{"rr1---sn-4g5ednsl.googlevideo.com", "rr1---sn-4g5ednsl.googlevideo.com"},
		{"_dmarc.example.com", "_dmarc.example.com"},
	}
	for _, c := range cases {
		got, err := NormalizeName(c.in)
		if err != nil {
			t.Errorf("NormalizeName(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeName(%q) = %q, expected %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeNameErrors(t *testing.T) {
	bad := []string{"", ".", "a..b", "exa mple.com", "ex*mple.com", strings.Repeat("a", 64) + ".com"}
	for _, in := range bad {
		if got, err := NormalizeName(in); err == nil {
			t.Errorf("NormalizeName(%q) = %q, expected an error", in, got)
		}
	}
}

func TestNormalizeNameRejectsLookalikes(t *testing.T) {
	bad := map[string]string{
		"youtube.com\u200b":  "trailing zero-width space",
		"you\u00adtube.com":  "soft hyphen",
		"\ufeffyoutube.com":  "BOM before the name",
		"youtube\u3002com":   "ideographic full stop instead of a dot",
		"youtube.\u0441om":   "Cyrillic \"с\" in a Latin word",
		"\u0438\u0306ога.рф": "\"й\" typed as \"и\" plus a combining mark",
		"\ufffd\ufffd.com":   "trace of a wrong encoding",
	}
	for in, what := range bad {
		if got, err := NormalizeName(in); err == nil {
			t.Errorf("%s: NormalizeName(%q) = %q, expected an error", what, in, got)
		}
	}
}

func TestNormalizeNameAcceptsLetters(t *testing.T) {
	for _, in := range []string{"йога.рф", "bücher.example", "日本語.jp", "сайт-1.рф"} {
		if _, err := NormalizeName(in); err != nil {
			t.Errorf("NormalizeName(%q): unexpected error %v", in, err)
		}
	}
}

func TestNormalizeNameLength(t *testing.T) {
	l63 := strings.Repeat("a", 63)
	ok := l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 61) // 253 characters
	if got, err := NormalizeName(ok); err != nil || len(got) != 253 {
		t.Errorf("253-character name: %q, %v", got, err)
	}
	if _, err := NormalizeName(ok + "b"); err == nil || !strings.Contains(err.Error(), "253") {
		t.Errorf("a 254-character name must be an error, got %v", err)
	}
}

// Names from DNS are shown on the web page and in the log: control characters and markup must not reach them.
func TestNormalizeNameRejectsControlChars(t *testing.T) {
	for _, in := range []string{"a\x1bb.com", "ex\nample.com", "a\x00.com", "a\x7f.com", "<b>.com"} {
		if got, err := NormalizeName(in); err == nil {
			t.Errorf("NormalizeName(%q) = %q, expected an error", in, got)
		}
	}
}
