package rules

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Пример из спецификации; им пользуются и тесты других файлов пакета.
const exampleSrc = `# пример из спецификации
exit vpn = Wireguard2, Wireguard0, Wireguard3
default direct

youtube.com googlevideo.com ytimg.com -> vpn strict
@lists/telegram.txt -> vpn
149.154.160.0/20 91.108.4.0/22 -> vpn
*.ru *.рф *.su -> direct
!*.ru -> vpn
`

func exampleRead(path string) (string, error) {
	if path == "lists/telegram.txt" {
		return "telegram.org\nt.me # короткие ссылки\n\n91.108.56.0/22\n", nil
	}
	return "", errors.New("нет такого файла")
}

func summary(c *Config) string {
	var b strings.Builder
	for _, e := range c.Exits {
		fmt.Fprintf(&b, "exit %s=%v\n", e.Name, e.Interfaces)
	}
	fmt.Fprintf(&b, "default %s\n", c.Default)
	for _, r := range c.Rules {
		fmt.Fprintf(&b, "%d:", r.Line)
		for _, x := range r.Pos {
			b.WriteString(" " + x.Text)
		}
		for _, x := range r.Neg {
			b.WriteString(" " + x.Text)
		}
		for _, n := range r.Nets {
			b.WriteString(" " + n.String())
		}
		fmt.Fprintf(&b, " -> %s\n", r.Action)
	}
	return b.String()
}

const exampleSummary = `exit vpn=[Wireguard2 Wireguard0 Wireguard3]
default direct
5: youtube.com googlevideo.com ytimg.com -> vpn strict
6: telegram.org t.me 91.108.56.0/22 -> vpn
7: 149.154.160.0/20 91.108.4.0/22 -> vpn
8: *.ru *.рф *.su -> direct
9: !*.ru -> vpn
`

func TestParseExample(t *testing.T) {
	cfg, ps := Parse(exampleSrc, exampleRead)
	if len(ps) != 0 {
		t.Fatalf("неожиданные проблемы: %v", ps)
	}
	if got := summary(cfg); got != exampleSummary {
		t.Errorf("разбор:\n%s\nожидалось:\n%s", got, exampleSummary)
	}
	if cfg.DefaultLine != 3 {
		t.Errorf("DefaultLine = %d, ожидалось 3", cfg.DefaultLine)
	}
	if e, ok := cfg.Exit("vpn"); !ok || e.Line != 2 {
		t.Errorf("Exit(vpn) = %+v, %v", e, ok)
	}
	if _, ok := cfg.Exit("nope"); ok {
		t.Error("Exit(nope) нашёлся")
	}
}

func TestParseTolerant(t *testing.T) {
	src := "\uFEFF" + strings.ReplaceAll(strings.ReplaceAll(exampleSrc, " -> ", "\t->\t"), "\n", "\r\n")
	cfg, ps := Parse(src, exampleRead)
	if len(ps) != 0 {
		t.Fatalf("неожиданные проблемы: %v", ps)
	}
	if got := summary(cfg); got != exampleSummary {
		t.Errorf("разбор:\n%s\nожидалось:\n%s", got, exampleSummary)
	}
}

func TestParseTests(t *testing.T) {
	cfg, ps := Parse("exit vpn = W\ndefault direct\ntest yandex.ru = direct\ntest 1.2.3.4 = vpn\n", nil)
	if len(ps) != 0 {
		t.Fatalf("неожиданные проблемы: %v", ps)
	}
	want := []Test{{3, "yandex.ru", "direct"}, {4, "1.2.3.4", "vpn"}}
	if len(cfg.Tests) != 2 || cfg.Tests[0] != want[0] || cfg.Tests[1] != want[1] {
		t.Errorf("Tests = %+v, ожидалось %+v", cfg.Tests, want)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		src  string
		line int
		msg  string
	}{
		{"exit vpn = W\nfoo.com -> vpn\n", 0, "нет строки default"},
		{"default direct\nfoo.com -> vpn\n", 2, "не объявлен"},
		{"default direct\nfoo.com vpn\n", 2, "не понимаю строку"},
		{"default direct\n-> direct\n", 2, "нет ни одного условия"},
		{"default direct\nfoo.com -> direct strict\n", 2, "strict не имеет смысла"},
		{"default direct\nfoo.com -> direct extra\n", 2, "ожидается выход"},
		{"default direct\ndefault direct\n", 2, "уже задан"},
		{"exit direct = W\ndefault direct\n", 1, "занято"},
		{"exit vpn = W\nexit vpn = W\ndefault direct\n", 2, "уже объявлен"},
		{"exit vpn =\ndefault direct\n", 1, "пустое имя интерфейса"},
		{"exit Bad Name = W\ndefault direct\n", 1, "имя выхода"},
		{"default direct\n10.0.0.0/33 -> direct\n", 2, "неверная запись"},
		{"default direct\n0.0.0.0/0 -> direct\n", 2, "есть default"},
		{"default direct\n!10.0.0.0/8 -> direct\n", 2, "отрицание адресов"},
		{"default direct\n2001:db8::1 -> direct\n", 2, "IPv6"},
		{"default direct\n1.2.3 -> direct\n", 2, "похоже на адрес"},
		{"default direct\n~( -> direct\n", 2, "регулярное выражение"},
		{"default direct\nfoo.*.com -> direct\n", 2, "звёздочка"},
		{"default direct\n@nofile -> direct\n", 2, "nofile"},
		{"default direct\n@ -> direct\n", 2, "нужен путь"},
		{"default direct\ntest foo.com\n", 2, "ожидается: test"},
		{"default direct\ntest foo.com = nowhere\n", 2, "не объявлен"},
	}
	for _, c := range cases {
		_, ps := Parse(c.src, exampleRead)
		found := false
		for _, p := range ps {
			if p.Severity == Error && p.Line == c.line && strings.Contains(p.Msg, c.msg) {
				found = true
			}
		}
		if !found {
			t.Errorf("для %q нет ошибки в строке %d с текстом %q; получено: %v", c.src, c.line, c.msg, ps)
		}
	}
}

func TestParseIncludeProblems(t *testing.T) {
	read := func(path string) (string, error) {
		switch path {
		case "empty":
			return "# только комментарий\n\n", nil
		case "nested":
			return "foo.com\n@other\n", nil
		case "bad":
			return "foo.com\nbar..com\n", nil
		}
		return "", errors.New("нет такого файла")
	}
	cases := []struct{ file, msg string }{
		{"empty", "пуст"},
		{"nested", "строка 2: вложенные включения"},
		{"bad", "строка 2"},
	}
	for _, c := range cases {
		_, ps := Parse("default direct\n@"+c.file+" -> direct\n", read)
		if !HasErrors(ps) || !strings.Contains(ps[0].Msg, c.msg) {
			t.Errorf("@%s: ожидалась ошибка с текстом %q, получено %v", c.file, c.msg, ps)
		}
	}
	if _, ps := Parse("default direct\n@x -> direct\n", nil); !HasErrors(ps) {
		t.Error("включение без функции чтения должно быть ошибкой")
	}
}

func TestProblemString(t *testing.T) {
	if got := (Problem{7, Error, "плохо"}).String(); got != "строка 7: ошибка: плохо" {
		t.Errorf("получено %q", got)
	}
	if got := (Problem{0, Warning, "так себе"}).String(); got != "предупреждение: так себе" {
		t.Errorf("получено %q", got)
	}
}

func TestParseRejectsNonUTF8(t *testing.T) {
	// «*.рф», сохранённое в Windows-1251.
	_, ps := Parse("exit vpn = W\ndefault direct\n*.\xf0\xf4 -> vpn\n", nil)
	if !HasErrors(ps) || !strings.Contains(ps[0].Msg, "UTF-8") {
		t.Errorf("файл не в UTF-8 принят: %v", ps)
	}
	read := func(string) (string, error) { return "\xf0\xf4\n", nil }
	_, ps = Parse("default direct\n@x -> direct\n", read)
	if !HasErrors(ps) || !strings.Contains(ps[0].Msg, "UTF-8") {
		t.Errorf("включённый файл не в UTF-8 принят: %v", ps)
	}
}

func TestParseMisplacedWords(t *testing.T) {
	cases := []struct{ rule, msg string }{
		{"youtube.com strict -> vpn", "strict"},
		{"youtube.com direct -> vpn", "direct"},
		{"youtube.com vpn -> direct", "имя выхода"},
		{"!vpn -> direct", "имя выхода"},
	}
	for _, c := range cases {
		_, ps := Parse("exit vpn = W\ndefault direct\n"+c.rule+"\n", nil)
		found := false
		for _, p := range ps {
			if p.Severity == Error && p.Line == 3 && strings.Contains(p.Msg, c.msg) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: нет ошибки с текстом %q; получено %v", c.rule, c.msg, ps)
		}
	}
}

func TestParseInterfaceNames(t *testing.T) {
	for _, bad := range []string{"W;reboot", "$(x)", "a=b", "W'x", "W`x`", "Вайргард"} {
		_, ps := Parse("exit vpn = "+bad+"\ndefault direct\n", nil)
		if !HasErrors(ps) || ps[0].Line != 1 || !strings.Contains(ps[0].Msg, "интерфейс") {
			t.Errorf("имя интерфейса %q принято: %v", bad, ps)
		}
	}
	if _, ps := Parse("exit vpn = GigabitEthernet0/Vlan1, Wireguard2, ISP-2_a.b\ndefault direct\n", nil); len(ps) != 0 {
		t.Errorf("обычные имена интерфейсов отклонены: %v", ps)
	}
}

func TestParseLinks(t *testing.T) {
	_, ps := Parse("exit vpn = W\ndefault direct\nhttps://www.youtube.com/watch?v=1 -> vpn\n!http://mail.ru -> vpn\n", nil)
	want := []string{
		`строка 3: ошибка: условие "https://www.youtube.com/watch?v=1" — это ссылка, а нужен домен: www.youtube.com`,
		`строка 4: ошибка: условие "http://mail.ru" — это ссылка, а нужен домен: mail.ru`,
	}
	if len(ps) != len(want) {
		t.Fatalf("проблемы: %v", ps)
	}
	for i, w := range want {
		if ps[i].String() != w {
			t.Errorf("получено %q, ожидалось %q", ps[i].String(), w)
		}
	}
}
