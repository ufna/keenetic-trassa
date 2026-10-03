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
			t.Errorf("NormalizeName(%q): неожиданная ошибка %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeName(%q) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeNameErrors(t *testing.T) {
	bad := []string{"", ".", "a..b", "exa mple.com", "ex*mple.com", strings.Repeat("a", 64) + ".com"}
	for _, in := range bad {
		if got, err := NormalizeName(in); err == nil {
			t.Errorf("NormalizeName(%q) = %q, ожидалась ошибка", in, got)
		}
	}
}

func TestNormalizeNameRejectsLookalikes(t *testing.T) {
	bad := map[string]string{
		"youtube.com\u200b":  "пробел нулевой ширины в конце",
		"you\u00adtube.com":  "мягкий перенос",
		"\ufeffyoutube.com":  "BOM перед именем",
		"youtube\u3002com":   "идеографическая точка вместо обычной",
		"youtube.\u0441om":   "кириллическая «с» в латинском слове",
		"\u0438\u0306ога.рф": "«й», набранная как «и» и отдельный знак",
		"\ufffd\ufffd.com":   "след неверной кодировки",
	}
	for in, what := range bad {
		if got, err := NormalizeName(in); err == nil {
			t.Errorf("%s: NormalizeName(%q) = %q, ожидалась ошибка", what, in, got)
		}
	}
}

func TestNormalizeNameAcceptsLetters(t *testing.T) {
	for _, in := range []string{"йога.рф", "bücher.example", "日本語.jp", "сайт-1.рф"} {
		if _, err := NormalizeName(in); err != nil {
			t.Errorf("NormalizeName(%q): неожиданная ошибка %v", in, err)
		}
	}
}

func TestNormalizeNameLength(t *testing.T) {
	l63 := strings.Repeat("a", 63)
	ok := l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 61) // 253 символа
	if got, err := NormalizeName(ok); err != nil || len(got) != 253 {
		t.Errorf("имя из 253 символов: %q, %v", got, err)
	}
	if _, err := NormalizeName(ok + "b"); err == nil || !strings.Contains(err.Error(), "253") {
		t.Errorf("имя из 254 символов должно быть ошибкой, получено %v", err)
	}
}

// Имена из DNS выводятся на страницу и в журнал: управляющие символы и разметка до них не доходят.
func TestNormalizeNameRejectsControlChars(t *testing.T) {
	for _, in := range []string{"a\x1bb.com", "ex\nample.com", "a\x00.com", "a\x7f.com", "<b>.com"} {
		if got, err := NormalizeName(in); err == nil {
			t.Errorf("NormalizeName(%q) = %q, ожидалась ошибка", in, got)
		}
	}
}
