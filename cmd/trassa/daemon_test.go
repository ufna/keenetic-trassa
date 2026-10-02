package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trassa/internal/ctl"
	"trassa/internal/engine"
	"trassa/internal/exits"
	"trassa/internal/nfq"
	"trassa/internal/rules"
)

func startDaemonStub(t *testing.T, rulesText string) (rulesPath string) {
	t.Helper()
	rulesPath = write(t, map[string]string{"rules.conf": rulesText})
	cfg, ps, ok := load(rulesPath, os.Stderr)
	if !ok || rules.HasErrors(ps) {
		t.Fatalf("правила: %v", ps)
	}
	eng := engine.New(cfg, nil, func(string, ...any) {}, time.Now())
	sock := filepath.Join(t.TempDir(), "trassa.sock")
	t.Setenv("TRASSA_SOCK", sock)
	srv, err := ctl.Serve(sock, handler(eng, reloader(rulesPath, eng, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return rulesPath
}

const live = "exit vpn = W\ndefault direct\nyoutube.com -> vpn\n"

func TestLiveWhyAndStatus(t *testing.T) {
	startDaemonStub(t, live)
	code, out, errOut := exec("why", "WWW.YouTube.com")
	if code != 0 || !strings.Contains(out, "www.youtube.com → vpn") || !strings.Contains(out, "DNS-ответов для этого имени ещё не было") {
		t.Errorf("why: код %d, вывод %q, stderr %q", code, out, errOut)
	}
	code, out, _ = exec("status")
	if code != 0 || !strings.Contains(out, "режим наблюдения") || !strings.Contains(out, "правил: 1") {
		t.Errorf("status: код %d, вывод %q", code, out)
	}
	if code, _, errOut := exec("why", "149.154.167"); code != 1 || !strings.Contains(errOut, "похоже на адрес") {
		t.Errorf("why с недописанным адресом: код %d, stderr %q", code, errOut)
	}
}

func TestReloadAppliesNewRules(t *testing.T) {
	path := startDaemonStub(t, live)
	if err := os.WriteFile(path, []byte(live+"vimeo.com -> vpn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := exec("reload")
	if code != 0 || !strings.Contains(out, "правила перечитаны: правил 2") {
		t.Fatalf("reload: код %d, вывод %q, stderr %q", code, out, errOut)
	}
	if _, out, _ := exec("why", "vimeo.com"); !strings.Contains(out, "vimeo.com → vpn") {
		t.Errorf("новое правило не действует: %q", out)
	}
}

func TestReloadKeepsOldRulesOnError(t *testing.T) {
	path := startDaemonStub(t, live)
	if err := os.WriteFile(path, []byte("exit vpn = W\ndefault direct\nyoutube.com -> nowhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := exec("reload")
	if code != 1 || !strings.Contains(out, "строка 3: ошибка") || !strings.Contains(errOut, "оставлены прежние правила") {
		t.Fatalf("reload с ошибкой: код %d, вывод %q, stderr %q", code, out, errOut)
	}
	if _, out, _ := exec("why", "youtube.com"); !strings.Contains(out, "youtube.com → vpn") {
		t.Errorf("прежние правила потеряны: %q", out)
	}
	// Файл пропал совсем: то же самое.
	os.Remove(path)
	if code, _, errOut := exec("reload"); code != 1 || !strings.Contains(errOut, "оставлены прежние правила") {
		t.Errorf("reload без файла: код %d, stderr %q", code, errOut)
	}
}

func TestReloadWarningsAreShown(t *testing.T) {
	path := startDaemonStub(t, live)
	if err := os.WriteFile(path, []byte(live+"www.youtube.com -> direct\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := exec("reload")
	if code != 0 || !strings.Contains(out, "предупреждение") || !strings.Contains(out, "правила перечитаны") {
		t.Errorf("reload с предупреждением: код %d, вывод %q", code, out)
	}
}

func TestUnknownControlCommand(t *testing.T) {
	startDaemonStub(t, live)
	if _, err := ctl.Call(os.Getenv("TRASSA_SOCK"), "explode", "", time.Second); err == nil || !strings.Contains(err.Error(), "неизвестная команда") {
		t.Errorf("ошибка %v", err)
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": live})
	bad := write(t, map[string]string{"rules.conf": "youtube.com -> vpn\n"})
	cases := []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"run", "-only", "не-адрес", "-rules", path}, 2, "-only"},
		{[]string{"run", "-only", "fdbd::1", "-rules", path}, 2, "-only"},
		{[]string{"run", "-queue", "70000", "-rules", path}, 2, "-queue"},
		{[]string{"run", "-rules", path, "лишнее"}, 2, "Использование"},
		{[]string{"run", "-rules", bad}, 1, "демон не запущен"},
		{[]string{"run", "-rules", filepath.Join(t.TempDir(), "nope.conf")}, 1, "не могу прочитать"},
	}
	for _, c := range cases {
		t.Setenv("TRASSA_SOCK", filepath.Join(t.TempDir(), "s.sock"))
		if code, _, errOut := exec(c.args...); code != c.code || !strings.Contains(errOut, c.msg) {
			t.Errorf("%v: код %d, stderr %q; ожидалось %d и %q", c.args, code, errOut, c.code, c.msg)
		}
	}
}

func TestParseOffset(t *testing.T) {
	cases := map[string]int{"+0300": 3 * 3600, "-0530": -(5*3600 + 30*60), "+0000": 0, "+1245": 12*3600 + 45*60}
	for in, want := range cases {
		loc, err := parseOffset(in)
		if err != nil {
			t.Errorf("parseOffset(%q): %v", in, err)
			continue
		}
		if _, got := time.Date(2026, 1, 1, 0, 0, 0, 0, loc).Zone(); got != want {
			t.Errorf("parseOffset(%q): смещение %d, ожидалось %d", in, got, want)
		}
	}
	for _, bad := range []string{"", "MSK", "0300", "+03", "+03:00", "+0360", "+2500", "+03xx"} {
		if _, err := parseOffset(bad); err == nil {
			t.Errorf("parseOffset(%q): ожидалась ошибка", bad)
		}
	}
}

func TestWatchStall(t *testing.T) {
	// Цикл приёма замер: сторож должен заметить и сообщить, сколько длится простой.
	fired := make(chan time.Duration, 1)
	stop := make(chan struct{})
	go watchStall(func() time.Duration { return time.Hour }, 20*time.Millisecond, 5*time.Millisecond, stop, func(idle time.Duration) { fired <- idle })
	select {
	case idle := <-fired:
		if idle != time.Hour {
			t.Errorf("простой %s, ожидался час", idle)
		}
	case <-time.After(time.Second):
		t.Fatal("сторож не сработал на замерший цикл")
	}
	close(stop)

	// Цикл жив: сторож молчит, а по сигналу остановки завершается.
	fired = make(chan time.Duration, 1)
	stop = make(chan struct{})
	done := make(chan struct{})
	go func() {
		watchStall(func() time.Duration { return 0 }, 20*time.Millisecond, 5*time.Millisecond, stop, func(idle time.Duration) { fired <- idle })
		close(done)
	}()
	select {
	case idle := <-fired:
		t.Fatalf("сторож сработал на живой цикл: простой %s", idle)
	case <-time.After(80 * time.Millisecond):
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("сторож не завершился по сигналу остановки")
	}
}

// fakeQueue выдаёт заранее заданные пакеты и ошибки; когда они кончились — «пакетов нет».
type fakeQueue struct {
	script    []any // nfq.Packet или error
	next      int
	accepted  []uint32
	acceptErr error
}

func (f *fakeQueue) Recv() (nfq.Packet, error) {
	if f.next >= len(f.script) {
		return nfq.Packet{}, nfq.ErrTimeout
	}
	x := f.script[f.next]
	f.next++
	if err, ok := x.(error); ok {
		return nfq.Packet{}, err
	}
	return x.(nfq.Packet), nil
}

func (f *fakeQueue) Accept(id uint32) error {
	f.accepted = append(f.accepted, id)
	return f.acceptErr
}

func (f *fakeQueue) drained() bool { return f.next >= len(f.script) }

func quiet(string, ...any) {}

func TestPumpAlwaysReleasesPackets(t *testing.T) {
	pumpErrorPause = 0
	q := &fakeQueue{script: []any{
		nfq.Packet{ID: 1, Payload: []byte("ok")},
		errors.New("сбой чтения"),
		nfq.Packet{ID: 2, Payload: []byte("boom")},
		nfq.Packet{ID: 3, Payload: []byte("ok")},
	}}
	var handled, beats int
	handle := func(raw []byte) {
		handled++
		if string(raw) == "boom" {
			panic("разбор упал")
		}
	}
	if err := pump(q, handle, func() { beats++ }, q.drained, quiet); err != nil {
		t.Fatalf("pump: %v", err)
	}
	if len(q.accepted) != 3 || q.accepted[0] != 1 || q.accepted[1] != 2 || q.accepted[2] != 3 {
		t.Errorf("отпущены пакеты %v, ожидалось [1 2 3]: пакет, на котором разбор упал, тоже должен быть отпущен", q.accepted)
	}
	if handled != 3 || beats < 4 {
		t.Errorf("обработано %d, отметок %d", handled, beats)
	}
}

func TestPumpGivesUpOnDeadQueue(t *testing.T) {
	pumpErrorPause = 0
	var script []any
	for i := 0; i < maxQueueErrors+10; i++ {
		script = append(script, errors.New("сокет закрыт"))
	}
	q := &fakeQueue{script: script}
	err := pump(q, func([]byte) {}, func() {}, q.drained, quiet)
	if err == nil || q.next != maxQueueErrors {
		t.Errorf("ошибка %v после %d чтений; ожидалась ошибка после %d", err, q.next, maxQueueErrors)
	}
}

func TestPumpGivesUpWhenVerdictsFail(t *testing.T) {
	pumpErrorPause = 0
	var script []any
	for i := 0; i < maxQueueErrors+10; i++ {
		script = append(script, nfq.Packet{ID: uint32(i)})
	}
	q := &fakeQueue{script: script, acceptErr: errors.New("вердикт не принят")}
	if err := pump(q, func([]byte) {}, func() {}, q.drained, quiet); err == nil || len(q.accepted) != maxQueueErrors {
		t.Errorf("ошибка %v после %d вердиктов; ожидалась ошибка после %d", err, len(q.accepted), maxQueueErrors)
	}
}

func TestPumpErrorsMustBeConsecutive(t *testing.T) {
	pumpErrorPause = 0
	var script []any
	for i := 0; i < maxQueueErrors*3; i++ {
		script = append(script, errors.New("редкий сбой"), nfq.Packet{ID: uint32(i)})
	}
	q := &fakeQueue{script: script}
	if err := pump(q, func([]byte) {}, func() {}, q.drained, quiet); err != nil {
		t.Errorf("редкие сбои вперемешку с пакетами остановили цикл: %v", err)
	}
}

func TestReloadRejectsUnknownInterface(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": live})
	cfg, _, _ := load(path, os.Stderr)
	eng := engine.New(cfg, nil, func(string, ...any) {}, time.Now())
	validate := func(c *rules.Config) []rules.Problem {
		for _, e := range c.Exits {
			if e.Name == "ghost" {
				return []rules.Problem{{Line: e.Line, Severity: rules.Error, Msg: "интерфейс Nope не существует на роутере"}}
			}
		}
		return nil
	}
	reload := reloader(path, eng, validate)
	if _, err := reload(); err != nil {
		t.Fatalf("исправные правила отклонены: %v", err)
	}
	os.WriteFile(path, []byte(live+"exit ghost = Nope\n"), 0o644)
	text, err := reload()
	if err == nil || !strings.Contains(text, "строка 4: ошибка: интерфейс Nope не существует") || !strings.Contains(err.Error(), "оставлены прежние правила") {
		t.Errorf("текст %q, ошибка %v", text, err)
	}
	if len(eng.Config().Exits) != 1 {
		t.Error("правила с несуществующим интерфейсом применены")
	}
}

func TestSaveState(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": live})
	cfg, _, _ := load(path, os.Stderr)
	eng := engine.New(cfg, nil, func(string, ...any) {}, time.Now())
	state := filepath.Join(t.TempDir(), "trassa.state")
	if err := saveState(state, eng); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(state); err != nil || len(b) != 0 {
		t.Errorf("пустое состояние: %q, %v", b, err)
	}
	// Временных файлов рядом не остаётся.
	if left, _ := filepath.Glob(state + ".*"); len(left) != 0 {
		t.Errorf("остались временные файлы: %v", left)
	}
	if err := saveState(filepath.Join(t.TempDir(), "нет", "такого", "каталога"), eng); err == nil {
		t.Error("запись в несуществующий каталог должна быть ошибкой")
	}
	var buf bytes.Buffer
	if err := eng.SaveState(&buf); err != nil {
		t.Fatal(err)
	}
}

func TestSameExits(t *testing.T) {
	a := map[string]exits.Choice{"vpn": {Interface: "Wireguard2", System: "nwg2"}, "alt": {}}
	b := map[string]exits.Choice{"vpn": {Interface: "Wireguard2", System: "nwg2"}, "alt": {}}
	if !sameExits(a, b) {
		t.Error("одинаковые состояния признаны разными")
	}
	b["alt"] = exits.Choice{Interface: "Wireguard0", System: "nwg0"}
	if sameExits(a, b) {
		t.Error("поднявшийся туннель не замечен")
	}
	if sameExits(a, map[string]exits.Choice{"vpn": a["vpn"]}) || sameExits(nil, a) {
		t.Error("разный состав выходов признан одинаковым")
	}
}

func TestRunRejectsBadRouteArguments(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": live})
	cases := []struct {
		args []string
		msg  string
	}{
		{[]string{"run", "-rules", path, "-source", "192.168.1.94"}, "-source"},
		{[]string{"run", "-rules", path, "-route", "-source", "не-адрес"}, "-source"},
		{[]string{"run", "-rules", path, "-route", "-source", "fdbd::1"}, "-source"},
	}
	for _, c := range cases {
		t.Setenv("TRASSA_SOCK", filepath.Join(t.TempDir(), "s.sock"))
		if code, _, errOut := exec(c.args...); code != 2 || !strings.Contains(errOut, c.msg) {
			t.Errorf("%v: код %d, stderr %q", c.args, code, errOut)
		}
	}
	// Прошивка недоступна: выходы проверить нельзя, демон в режиме маршрутизации не запускается.
	t.Setenv("TRASSA_SOCK", filepath.Join(t.TempDir(), "s.sock"))
	code, _, errOut := exec("run", "-rules", path, "-route", "-rci", "http://127.0.0.1:1")
	if code != 1 || !strings.Contains(errOut, "прошивка не отвечает") || !strings.Contains(errOut, "демон не запущен") {
		t.Errorf("недоступная прошивка: код %d, stderr %q", code, errOut)
	}
}
