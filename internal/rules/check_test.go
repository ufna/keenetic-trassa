package rules

import (
	"fmt"
	"strings"
	"testing"
)

const head = "exit vpn = W\ndefault direct\n"

func problemsOf(t *testing.T, src string) []Problem {
	t.Helper()
	_, ps := Load(src, exampleRead)
	return ps
}

func hasProblem(ps []Problem, sev Severity, line int, msg string) bool {
	for _, p := range ps {
		if p.Severity == sev && p.Line == line && strings.Contains(p.Msg, msg) {
			return true
		}
	}
	return false
}

func TestLoadExampleIsClean(t *testing.T) {
	if ps := problemsOf(t, exampleSrc); len(ps) != 0 {
		t.Errorf("пример из спецификации дал проблемы: %v", ps)
	}
}

func TestExpectations(t *testing.T) {
	ok := head + "foo.com -> vpn\n1.2.3.0/24 -> vpn\n" +
		"test foo.com = vpn\ntest WWW.Foo.com = vpn\ntest bar.com = direct\ntest 1.2.3.4 = vpn\ntest 8.8.8.8 = direct\n"
	if ps := problemsOf(t, ok); len(ps) != 0 {
		t.Errorf("верные ожидания дали проблемы: %v", ps)
	}

	ps := problemsOf(t, head+"foo.com -> vpn\ntest foo.com = direct\n")
	if !hasProblem(ps, Error, 4, "ожидание не выполнено: foo.com идёт в vpn (по правилу в строке 3), а ожидалось direct") {
		t.Errorf("нет ошибки невыполненного ожидания: %v", ps)
	}

	ps = problemsOf(t, head+"test bar.com = vpn\n")
	if !hasProblem(ps, Error, 3, "bar.com идёт в direct (по default), а ожидалось vpn") {
		t.Errorf("нет ошибки для default: %v", ps)
	}

	ps = problemsOf(t, head+"test bad..name = direct\n")
	if !hasProblem(ps, Error, 3, "пустая метка") {
		t.Errorf("нет ошибки для неверного имени в test: %v", ps)
	}
}

func TestShadowedRule(t *testing.T) {
	ps := problemsOf(t, head+"google.com -> vpn\nmail.google.com -> direct\n")
	if !hasProblem(ps, Warning, 4, "никогда не сработает") || !hasProblem(ps, Warning, 4, "строка 3") {
		t.Errorf("нет предупреждения о перекрытом правиле: %v", ps)
	}

	ps = problemsOf(t, head+"10.0.0.0/8 -> vpn\n10.1.0.0/16 -> direct\n")
	if !hasProblem(ps, Warning, 4, "никогда не сработает") {
		t.Errorf("нет предупреждения о перекрытой подсети: %v", ps)
	}

	for _, src := range []string{
		head + "google.com !mail.google.com -> vpn\nmail.google.com -> direct\n", // у раннего правила есть отрицание
		head + "mail.google.com -> direct\ngoogle.com -> vpn\n",                  // узкое раньше широкого
		head + "google.com -> vpn\nmail.google.com example.org -> direct\n",      // перекрыта только часть условий
		head + "~google -> vpn\nmail.google.com -> direct\n",                     // регулярные выражения не судим
		head + "google.com -> vpn\n!*.ru -> vpn\n",                               // правило с отрицанием не судим
	} {
		if ps := problemsOf(t, src); len(ps) != 0 {
			t.Errorf("лишние проблемы для %q: %v", src, ps)
		}
	}
}

func TestStrictWarnings(t *testing.T) {
	ps := problemsOf(t, head+"!*.ru -> vpn strict\n")
	if !hasProblem(ps, Warning, 3, "strict на правиле с отрицанием") {
		t.Errorf("нет предупреждения о strict с отрицанием: %v", ps)
	}
	ps = problemsOf(t, "exit vpn = W\ndefault vpn strict\n")
	if !hasProblem(ps, Warning, 2, "strict в default") {
		t.Errorf("нет предупреждения о strict в default: %v", ps)
	}
	if HasErrors(ps) {
		t.Errorf("предупреждения не должны считаться ошибками: %v", ps)
	}
}

func TestLoadStopsAtParseErrors(t *testing.T) {
	ps := problemsOf(t, "foo.com -> vpn\ntest foo.com = direct\n")
	for _, p := range ps {
		if strings.Contains(p.Msg, "ожидание") {
			t.Errorf("ожидания проверялись при ошибках разбора: %v", ps)
		}
	}
	if !HasErrors(ps) {
		t.Error("ошибки разбора потерялись")
	}
}

func TestShadowedByNegationRule(t *testing.T) {
	ps := problemsOf(t, head+"!*.ru -> vpn\nyoutube.com -> vpn strict\n")
	if !hasProblem(ps, Warning, 4, "никогда не сработает") || !hasProblem(ps, Warning, 4, "строка 3") {
		t.Errorf("нет предупреждения о правиле после всеохватного отрицания: %v", ps)
	}
	for _, src := range []string{
		head + "!*.com -> vpn\nyoutube.com -> direct\n",          // youtube.com под отрицанием: раннее правило его не берёт
		head + "!mail.google.com -> vpn\ngoogle.com -> direct\n", // часть имён позднего правила под отрицанием
		head + "!~^a -> vpn\nyoutube.com -> direct\n",            // регулярные выражения не судим
		head + "10.0.0.0/8 -> vpn\nyoutube.com -> direct\n",      // раннее правило только с адресами имён не берёт
	} {
		for _, p := range problemsOf(t, src) {
			if strings.Contains(p.Msg, "никогда не сработает") {
				t.Errorf("ложное предупреждение для %q: %v", src, p)
			}
		}
	}
}

func TestExpectationSubjectMustBeValid(t *testing.T) {
	ps := problemsOf(t, head+"!*.ru -> vpn\ntest 149.154.167 = vpn\n")
	if !hasProblem(ps, Error, 4, "похоже на адрес") {
		t.Errorf("недописанный адрес в test принят за имя: %v", ps)
	}
	ps = problemsOf(t, head+"test 2001:db8::1 = direct\n")
	if !hasProblem(ps, Error, 3, "IPv6") {
		t.Errorf("IPv6-адрес в test не отклонён: %v", ps)
	}
}

func TestTooManyExits(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxExits+1; i++ {
		fmt.Fprintf(&b, "exit e%d = W\n", i)
	}
	b.WriteString("default direct\n")
	ps := problemsOf(t, b.String())
	if !hasProblem(ps, Error, MaxExits+1, "не больше 29") {
		t.Errorf("тридцатый выход не отклонён: %v", ps)
	}
	ok := strings.Replace(b.String(), fmt.Sprintf("exit e%d = W\n", MaxExits), "", 1)
	if ps := problemsOf(t, ok); len(ps) != 0 {
		t.Errorf("29 выходов дали проблемы: %v", ps)
	}
}
