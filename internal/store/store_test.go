package store

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trassa/internal/rules"
)

const (
	textA = "exit vpn = W\ndefault direct\nyoutube.com -> vpn\n"
	textB = textA + "t.me -> vpn\n"
	textC = textB + "discord.com -> vpn\n"
)

// newStore создаёт каталог правил с действующим файлом text (пустая строка — файла нет).
// Часы идут вперёд на секунду при каждом обращении.
func newStore(t *testing.T, text string) *Store {
	t.Helper()
	dir := t.TempDir()
	if text != "" {
		if err := os.WriteFile(filepath.Join(dir, RulesFile), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	clock := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	return &Store{Dir: dir, Now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(time.Second)
		return clock
	}}
}

func current(t *testing.T, s *Store) string {
	t.Helper()
	text, err := s.Current()
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func mustSave(t *testing.T, s *Store, text string) Result {
	t.Helper()
	res, err := s.Save(text, false)
	if err != nil || !res.Saved {
		t.Fatalf("сохранение: %+v, %v", res, err)
	}
	return res
}

// kinds — виды версий от новой к старой; действующая отмечена звёздочкой.
func kinds(t *testing.T, s *Store) string {
	t.Helper()
	h, err := s.History()
	if err != nil {
		t.Fatal(err)
	}
	var parts []string
	for _, v := range h {
		k := v.Kind
		if v.Current {
			k += "*"
		}
		parts = append(parts, k)
	}
	return strings.Join(parts, " ")
}

func TestReaderStaysInsideDir(t *testing.T) {
	s := newStore(t, "")
	os.MkdirAll(filepath.Join(s.Dir, "lists"), 0o755)
	os.WriteFile(filepath.Join(s.Dir, "lists", "tg.txt"), []byte("t.me\n"), 0o644)
	if _, ps := s.Check("default direct\nexit vpn = W\n@lists/tg.txt -> vpn\n"); len(ps) != 0 {
		t.Errorf("файл внутри каталога: %v", ps)
	}
	for _, p := range []string{"/etc/passwd", "../rules.conf", "lists/../../x"} {
		_, ps := s.Check("default direct\nexit vpn = W\n@" + p + " -> vpn\n")
		if !rules.HasErrors(ps) || !strings.Contains(ps[0].Msg, "внутри каталога правил") {
			t.Errorf("@%s: %v", p, ps)
		}
	}
}

func TestSaveRejectsErrors(t *testing.T) {
	s := newStore(t, textA)
	res, err := s.Save("default direct\nfoo.com -> vpn\n", true)
	if err != nil || res.Saved || !rules.HasErrors(res.Problems) {
		t.Fatalf("%+v, %v", res, err)
	}
	if current(t, s) != textA || kinds(t, s) != "" {
		t.Errorf("файл с ошибкой что-то изменил: %q, история %q", current(t, s), kinds(t, s))
	}
}

func TestSaveNeedsConfirmForWarnings(t *testing.T) {
	s := newStore(t, textA)
	warn := "exit vpn = W\ndefault vpn strict\n"
	res, err := s.Save(warn, false)
	if err != nil || res.Saved || !res.NeedConfirm || len(res.Problems) != 1 {
		t.Fatalf("без подтверждения: %+v, %v", res, err)
	}
	if current(t, s) != textA {
		t.Fatal("без подтверждения файл изменён")
	}
	res, err = s.Save(warn, true)
	if err != nil || !res.Saved || res.Applied != NotRunning || res.Message == "" || current(t, s) != warn {
		t.Errorf("с подтверждением: %+v, %v", res, err)
	}
}

func TestSaveKeepsHistory(t *testing.T) {
	s := newStore(t, textA)
	res := mustSave(t, s, textB)
	if res.Rules != 2 || res.Exits != 1 {
		t.Errorf("счётчики: %+v", res)
	}
	if got := kinds(t, s); got != "page* outside" {
		t.Errorf("после первой правки: %q", got)
	}
	mustSave(t, s, textC)
	if got := kinds(t, s); got != "page* page outside" {
		t.Errorf("после второй правки: %q", got)
	}
	res, err := s.Save(textC, false)
	if err != nil || !res.Unchanged || res.Saved || kinds(t, s) != "page* page outside" {
		t.Errorf("тот же текст: %+v, %v, история %q", res, err, kinds(t, s))
	}
}

func TestSaveArchivesOutsideEdit(t *testing.T) {
	s := newStore(t, textA)
	mustSave(t, s, textB)
	os.WriteFile(filepath.Join(s.Dir, RulesFile), []byte(textC), 0o644) // правка по SSH
	mustSave(t, s, textA)
	if got := kinds(t, s); got != "page* outside page outside" {
		t.Errorf("история: %q", got)
	}
	h, _ := s.History()
	if text, _ := s.Version(h[1].ID); text != textC {
		t.Errorf("правка по SSH потеряна: %q", text)
	}
}

func TestFirstSaveWithoutFile(t *testing.T) {
	s := newStore(t, "")
	mustSave(t, s, textA)
	if current(t, s) != textA || kinds(t, s) != "page*" {
		t.Errorf("файл %q, история %q", current(t, s), kinds(t, s))
	}
}

func TestHistoryKeepsTwenty(t *testing.T) {
	s := newStore(t, textA)
	for i := 0; i < 25; i++ {
		mustSave(t, s, textA+strings.Repeat("# правка\n", i+1))
	}
	h, err := s.History()
	if err != nil || len(h) != Keep || !h[0].Current {
		t.Fatalf("версий %d, ошибка %v", len(h), err)
	}
	if text, _ := s.Version(h[0].ID); text != current(t, s) {
		t.Error("самая новая версия не совпадает с действующей")
	}
	for i := 1; i < len(h); i++ {
		if !h[i-1].Time.After(h[i].Time) {
			t.Errorf("порядок нарушен: %v, %v", h[i-1].Time, h[i].Time)
		}
	}
}

func TestRollback(t *testing.T) {
	s := newStore(t, textA)
	mustSave(t, s, textB)
	mustSave(t, s, textC)
	h, _ := s.History() // page(C) page(B) outside(A)
	res, err := s.Rollback(h[1].ID, false)
	if err != nil || !res.Saved || current(t, s) != textB {
		t.Fatalf("%+v, %v, файл %q", res, err, current(t, s))
	}
	if got := kinds(t, s); got != "rollback* page page outside" {
		t.Errorf("история: %q", got)
	}
	prev, err := s.Previous()
	if text, _ := s.Version(prev); err != nil || text != textC {
		t.Errorf("предыдущая версия: %q, %v", text, err)
	}
}

func TestRollbackUnknownVersion(t *testing.T) {
	s := newStore(t, textA)
	for _, id := range []string{"../../etc/passwd", "20261003-120000.000-page", ""} {
		if _, err := s.Rollback(id, true); err == nil {
			t.Errorf("%q: ожидалась ошибка", id)
		}
	}
}

func TestPreviousWithoutOtherVersion(t *testing.T) {
	s := newStore(t, "")
	mustSave(t, s, textA)
	if _, err := s.Previous(); err == nil {
		t.Error("единственная версия совпадает с действующей — возвращать нечего")
	}
}

func TestApplyStates(t *testing.T) {
	for _, a := range []Applied{Running, Partly, NotRunning, Unknown} {
		s := newStore(t, textA)
		s.Apply = func() (Applied, string) { return a, "" }
		res := mustSave(t, s, textB)
		if res.Applied != a || res.Message == "" || current(t, s) != textB {
			t.Errorf("%v: %+v", a, res)
		}
	}
}

func TestApplyRejectedRestoresFile(t *testing.T) {
	s := newStore(t, textA)
	s.Apply = func() (Applied, string) {
		return Rejected, "интерфейс W не существует на роутере"
	}
	res, err := s.Save(textB, false)
	if err != nil || res.Saved || res.Applied != Rejected || !strings.Contains(res.Message, "не существует") {
		t.Fatalf("%+v, %v", res, err)
	}
	if current(t, s) != textA {
		t.Errorf("файл не возвращён: %q", current(t, s))
	}
	if got := kinds(t, s); got != "outside*" {
		t.Errorf("отвергнутая версия осталась в истории: %q", got)
	}
}

func TestValidateErrorsBlockSave(t *testing.T) {
	s := newStore(t, textA)
	s.Validate = func(c *rules.Config) []rules.Problem {
		return []rules.Problem{{Line: 1, Severity: rules.Error, Msg: "интерфейс W не существует на роутере"}}
	}
	res, err := s.Save(textB, true)
	if err != nil || res.Saved || !rules.HasErrors(res.Problems) || current(t, s) != textA {
		t.Errorf("%+v, %v", res, err)
	}
}

func TestTooLarge(t *testing.T) {
	s := newStore(t, textA)
	res, _ := s.Save(textA+strings.Repeat("#", MaxSize), true)
	if res.Saved || !rules.HasErrors(res.Problems) {
		t.Errorf("%+v", res)
	}
}

// Страница и trassa rollback могут сохранять одновременно: история не должна перепутаться.
func TestConcurrentSaves(t *testing.T) {
	s := newStore(t, textA)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.Save(textA+strings.Repeat("# правка\n", i+1), false)
		}(i)
	}
	wg.Wait()
	h, err := s.History()
	if err != nil || len(h) != 9 || !h[0].Current {
		t.Fatalf("версий %d (ожидалось 9), ошибка %v", len(h), err)
	}
	if text, _ := s.Version(h[0].ID); text != current(t, s) {
		t.Error("самая новая версия не совпадает с действующей")
	}
}
