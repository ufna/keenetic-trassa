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
		return "details\n", errors.New("it failed")
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
		t.Errorf("reply %q, error %v", text, err)
	}
	// Cyrillic text and a newline in the argument pass through intact.
	text, err = Call(path, "why", "сайт.рф\n", time.Second)
	if err != nil || text != "why:сайт.рф\n\n" {
		t.Errorf("reply %q, error %v", text, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket permissions: %v, %v", fi.Mode().Perm(), err)
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
	if err == nil || err.Error() != "it failed" || text != "details\n" {
		t.Errorf("reply %q, error %v", text, err)
	}
	if errors.Is(err, ErrPartial) {
		t.Error("an ordinary daemon error was reported as partial completion")
	}
}

func TestCallWithoutDaemon(t *testing.T) {
	_, err := Call(sock(t), "status", "", 200*time.Millisecond)
	if !errors.Is(err, ErrNoDaemon) || !strings.Contains(err.Error(), "trassa daemon is not running") {
		t.Errorf("error %v", err)
	}
}

func TestServeRefusesSecondInstance(t *testing.T) {
	path := sock(t)
	first, err := Serve(path, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := Serve(path, echo); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("second instance: error %v", err)
	}
	// The first instance keeps answering.
	if text, err := Call(path, "ping", "", time.Second); err != nil || text != "ping:\n" {
		t.Errorf("first instance after the second one's attempt: %q, %v", text, err)
	}
}

func TestServeReplacesStaleSocket(t *testing.T) {
	path := sock(t)
	if err := os.WriteFile(path, nil, 0o600); err != nil { // left over after a crash
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
		t.Errorf("socket file left behind: %v", err)
	}
}

func TestCallPartial(t *testing.T) {
	path := sock(t)
	srv, err := Serve(path, func(cmd, arg string) (string, error) {
		return "rules accepted\n", fmt.Errorf("%w: sets not built", ErrPartial)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	text, err := Call(path, "reload", "", time.Second)
	if !errors.Is(err, ErrPartial) || err.Error() != "partially done: sets not built" || text != "rules accepted\n" {
		t.Errorf("reply %q, error %v", text, err)
	}
}

func TestCallNoReply(t *testing.T) {
	path := sock(t)
	srv, err := Serve(path, func(cmd, arg string) (string, error) {
		time.Sleep(300 * time.Millisecond)
		return "too late\n", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, err := Call(path, "reload", "", 100*time.Millisecond); !errors.Is(err, ErrNoReply) {
		t.Errorf("error %v", err)
	}
}

// A slow command (rereading rules and rebuilding the address sets) still gets to reply if the client
// is willing to wait: the reply deadline starts after the command completes.
func TestSlowCommandStillAnswers(t *testing.T) {
	old := replyTimeout
	replyTimeout = 200 * time.Millisecond
	t.Cleanup(func() { replyTimeout = old })
	path := sock(t)
	srv, err := Serve(path, func(cmd, arg string) (string, error) {
		time.Sleep(300 * time.Millisecond)
		return "done\n", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if text, err := Call(path, "reload", "", 2*time.Second); err != nil || text != "done\n" {
		t.Errorf("reply %q, error %v", text, err)
	}
}
