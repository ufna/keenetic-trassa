package ctl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func echo(cmd, arg string) (string, error) {
	if cmd == "fail" {
		return "подробности\n", errors.New("не получилось")
	}
	return cmd + ":" + arg + "\n", nil
}

func sock(t *testing.T) string {
	return filepath.Join(t.TempDir(), "trassa.sock")
}

func TestCallRoundTrip(t *testing.T) {
	path := sock(t)
	srv, err := Serve(path, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	text, err := Call(path, "why", "youtube.com", time.Second)
	if err != nil || text != "why:youtube.com\n" {
		t.Errorf("ответ %q, ошибка %v", text, err)
	}
	// Кириллица и перевод строки в аргументе проходят без искажений.
	text, err = Call(path, "why", "сайт.рф\n", time.Second)
	if err != nil || text != "why:сайт.рф\n\n" {
		t.Errorf("ответ %q, ошибка %v", text, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("права на сокет: %v, %v", fi.Mode().Perm(), err)
	}
}

func TestCallReturnsHandlerErrorWithText(t *testing.T) {
	path := sock(t)
	srv, err := Serve(path, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	text, err := Call(path, "fail", "", time.Second)
	if err == nil || err.Error() != "не получилось" || text != "подробности\n" {
		t.Errorf("ответ %q, ошибка %v", text, err)
	}
	if errors.Is(err, ErrPartial) {
		t.Error("обычная ошибка демона выдана за частичное выполнение")
	}
}

func TestCallWithoutDaemon(t *testing.T) {
	_, err := Call(sock(t), "status", "", 200*time.Millisecond)
	if !errors.Is(err, ErrNoDaemon) || !strings.Contains(err.Error(), "демон trassa не запущен") {
		t.Errorf("ошибка %v", err)
	}
}

func TestServeRefusesSecondInstance(t *testing.T) {
	path := sock(t)
	first, err := Serve(path, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := Serve(path, echo); err == nil || !strings.Contains(err.Error(), "уже запущен") {
		t.Errorf("второй экземпляр: ошибка %v", err)
	}
	// Первый экземпляр продолжает отвечать.
	if text, err := Call(path, "ping", "", time.Second); err != nil || text != "ping:\n" {
		t.Errorf("первый экземпляр после попытки второго: %q, %v", text, err)
	}
}

func TestServeReplacesStaleSocket(t *testing.T) {
	path := sock(t)
	if err := os.WriteFile(path, nil, 0o600); err != nil { // остался после аварийного завершения
		t.Fatal(err)
	}
	srv, err := Serve(path, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if text, err := Call(path, "ping", "", time.Second); err != nil || text != "ping:\n" {
		t.Errorf("%q, %v", text, err)
	}
}

func TestCloseRemovesSocket(t *testing.T) {
	path := sock(t)
	srv, err := Serve(path, echo)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("файл сокета остался: %v", err)
	}
}

func TestCallPartial(t *testing.T) {
	path := sock(t)
	srv, err := Serve(path, func(cmd, arg string) (string, error) {
		return "правила приняты\n", fmt.Errorf("%w: списки не построены", ErrPartial)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	text, err := Call(path, "reload", "", time.Second)
	if !errors.Is(err, ErrPartial) || err.Error() != "выполнено не полностью: списки не построены" || text != "правила приняты\n" {
		t.Errorf("ответ %q, ошибка %v", text, err)
	}
}

func TestCallNoReply(t *testing.T) {
	path := sock(t)
	srv, err := Serve(path, func(cmd, arg string) (string, error) {
		time.Sleep(300 * time.Millisecond)
		return "поздно\n", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, err := Call(path, "reload", "", 100*time.Millisecond); !errors.Is(err, ErrNoReply) {
		t.Errorf("ошибка %v", err)
	}
}

// Долгая команда (перечитывание правил с перестроением списков) успевает ответить, если клиент
// готов ждать: срок на ответ отсчитывается после выполнения команды.
func TestSlowCommandStillAnswers(t *testing.T) {
	old := replyTimeout
	replyTimeout = 200 * time.Millisecond
	t.Cleanup(func() { replyTimeout = old })
	path := sock(t)
	srv, err := Serve(path, func(cmd, arg string) (string, error) {
		time.Sleep(300 * time.Millisecond)
		return "готово\n", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if text, err := Call(path, "reload", "", 2*time.Second); err != nil || text != "готово\n" {
		t.Errorf("ответ %q, ошибка %v", text, err)
	}
}
