package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trassa/internal/claims"
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
		t.Fatalf("rules: %v", ps)
	}
	eng := engine.New(cfg, nil, func(string, ...any) {}, time.Now())
	sock := filepath.Join(t.TempDir(), "trassa.sock")
	t.Setenv("TRASSA_SOCK", sock)
	srv, err := ctl.Serve(sock, handler(eng, reloader(rulesPath, eng, nil), nil))
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
	if code != 0 || !strings.Contains(out, "www.youtube.com → vpn") || !strings.Contains(out, "no DNS answers for this name yet") {
		t.Errorf("why: code %d, output %q, stderr %q", code, out, errOut)
	}
	code, out, _ = exec("status")
	if code != 0 || !strings.Contains(out, "observe mode") || !strings.Contains(out, "rules: 1") {
		t.Errorf("status: code %d, output %q", code, out)
	}
	if code, _, errOut := exec("why", "149.154.167"); code != 1 || !strings.Contains(errOut, "looks like an address") {
		t.Errorf("why with an incomplete address: code %d, stderr %q", code, errOut)
	}
}

func TestReloadAppliesNewRules(t *testing.T) {
	path := startDaemonStub(t, live)
	if err := os.WriteFile(path, []byte(live+"vimeo.com -> vpn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := exec("reload")
	if code != 0 || !strings.Contains(out, "rules reloaded: rules 2") {
		t.Fatalf("reload: code %d, output %q, stderr %q", code, out, errOut)
	}
	if _, out, _ := exec("why", "vimeo.com"); !strings.Contains(out, "vimeo.com → vpn") {
		t.Errorf("new rule not in effect: %q", out)
	}
}

func TestReloadKeepsOldRulesOnError(t *testing.T) {
	path := startDaemonStub(t, live)
	if err := os.WriteFile(path, []byte("exit vpn = W\ndefault direct\nyoutube.com -> nowhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := exec("reload")
	if code != 1 || !strings.Contains(out, "line 3: error") || !strings.Contains(errOut, "the previous rules remain") {
		t.Fatalf("reload with an error: code %d, output %q, stderr %q", code, out, errOut)
	}
	if _, out, _ := exec("why", "youtube.com"); !strings.Contains(out, "youtube.com → vpn") {
		t.Errorf("previous rules lost: %q", out)
	}
	// The file is gone altogether: same thing.
	os.Remove(path)
	if code, _, errOut := exec("reload"); code != 1 || !strings.Contains(errOut, "the previous rules remain") {
		t.Errorf("reload without a file: code %d, stderr %q", code, errOut)
	}
}

func TestReloadWarningsAreShown(t *testing.T) {
	path := startDaemonStub(t, live)
	if err := os.WriteFile(path, []byte(live+"www.youtube.com -> direct\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := exec("reload")
	if code != 0 || !strings.Contains(out, "warning") || !strings.Contains(out, "rules reloaded") {
		t.Errorf("reload with a warning: code %d, output %q", code, out)
	}
}

func TestUnknownControlCommand(t *testing.T) {
	startDaemonStub(t, live)
	if _, err := ctl.Call(os.Getenv("TRASSA_SOCK"), "explode", "", time.Second); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("error %v", err)
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
		{[]string{"run", "-only", "not-an-address", "-rules", path}, 2, "-only"},
		{[]string{"run", "-only", "fdbd::1", "-rules", path}, 2, "-only"},
		{[]string{"run", "-queue", "70000", "-rules", path}, 2, "-queue"},
		{[]string{"run", "-rules", path, "extra"}, 2, "Usage"},
		{[]string{"run", "-rules", bad}, 1, "daemon is not started"},
		{[]string{"run", "-rules", filepath.Join(t.TempDir(), "nope.conf")}, 1, "cannot read"},
	}
	for _, c := range cases {
		t.Setenv("TRASSA_SOCK", filepath.Join(t.TempDir(), "s.sock"))
		if code, _, errOut := exec(c.args...); code != c.code || !strings.Contains(errOut, c.msg) {
			t.Errorf("%v: code %d, stderr %q; expected %d and %q", c.args, code, errOut, c.code, c.msg)
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
			t.Errorf("parseOffset(%q): offset %d, expected %d", in, got, want)
		}
	}
	for _, bad := range []string{"", "MSK", "0300", "+03", "+03:00", "+0360", "+2500", "+03xx"} {
		if _, err := parseOffset(bad); err == nil {
			t.Errorf("parseOffset(%q): expected an error", bad)
		}
	}
}

func TestWatchStall(t *testing.T) {
	// The packet loop froze: the watchdog must notice and report how long it has been idle.
	fired := make(chan time.Duration, 1)
	stop := make(chan struct{})
	go watchStall(func() time.Duration { return time.Hour }, 20*time.Millisecond, 5*time.Millisecond, stop, func(idle time.Duration) { fired <- idle })
	select {
	case idle := <-fired:
		if idle != time.Hour {
			t.Errorf("idle %s, expected an hour", idle)
		}
	case <-time.After(time.Second):
		t.Fatal("watchdog did not fire on a frozen loop")
	}
	close(stop)

	// The loop is alive: the watchdog stays quiet and returns when told to stop.
	fired = make(chan time.Duration, 1)
	stop = make(chan struct{})
	done := make(chan struct{})
	go func() {
		watchStall(func() time.Duration { return 0 }, 20*time.Millisecond, 5*time.Millisecond, stop, func(idle time.Duration) { fired <- idle })
		close(done)
	}()
	select {
	case idle := <-fired:
		t.Fatalf("watchdog fired on a live loop: idle %s", idle)
	case <-time.After(80 * time.Millisecond):
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not return when told to stop")
	}
}

// fakeQueue returns preset packets and errors; when they run out, it reports "no packets".
type fakeQueue struct {
	script    []any // nfq.Packet or error
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
		errors.New("read failure"),
		nfq.Packet{ID: 2, Payload: []byte("boom")},
		nfq.Packet{ID: 3, Payload: []byte("ok")},
	}}
	var handled, beats int
	handle := func(raw []byte) {
		handled++
		if string(raw) == "boom" {
			panic("parsing panicked")
		}
	}
	if err := pump(q, handle, func() { beats++ }, q.drained, quiet); err != nil {
		t.Fatalf("pump: %v", err)
	}
	if len(q.accepted) != 3 || q.accepted[0] != 1 || q.accepted[1] != 2 || q.accepted[2] != 3 {
		t.Errorf("released packets %v, expected [1 2 3]: the packet whose parsing panicked must be released too", q.accepted)
	}
	if handled != 3 || beats < 4 {
		t.Errorf("handled %d, heartbeats %d", handled, beats)
	}
}

func TestPumpGivesUpOnDeadQueue(t *testing.T) {
	pumpErrorPause = 0
	var script []any
	for i := 0; i < maxQueueErrors+10; i++ {
		script = append(script, errors.New("socket closed"))
	}
	q := &fakeQueue{script: script}
	err := pump(q, func([]byte) {}, func() {}, q.drained, quiet)
	if err == nil || q.next != maxQueueErrors {
		t.Errorf("error %v after %d reads; expected an error after %d", err, q.next, maxQueueErrors)
	}
}

func TestPumpGivesUpWhenVerdictsFail(t *testing.T) {
	pumpErrorPause = 0
	var script []any
	for i := 0; i < maxQueueErrors+10; i++ {
		script = append(script, nfq.Packet{ID: uint32(i)})
	}
	q := &fakeQueue{script: script, acceptErr: errors.New("verdict not accepted")}
	if err := pump(q, func([]byte) {}, func() {}, q.drained, quiet); err == nil || len(q.accepted) != maxQueueErrors {
		t.Errorf("error %v after %d verdicts; expected an error after %d", err, len(q.accepted), maxQueueErrors)
	}
}

func TestPumpErrorsMustBeConsecutive(t *testing.T) {
	pumpErrorPause = 0
	var script []any
	for i := 0; i < maxQueueErrors*3; i++ {
		script = append(script, errors.New("rare failure"), nfq.Packet{ID: uint32(i)})
	}
	q := &fakeQueue{script: script}
	if err := pump(q, func([]byte) {}, func() {}, q.drained, quiet); err != nil {
		t.Errorf("rare failures mixed with packets stopped the loop: %v", err)
	}
}

func TestReloadRejectsUnknownInterface(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": live})
	cfg, _, _ := load(path, os.Stderr)
	eng := engine.New(cfg, nil, func(string, ...any) {}, time.Now())
	validate := func(c *rules.Config) []rules.Problem {
		for _, e := range c.Exits {
			if e.Name == "ghost" {
				return []rules.Problem{{Line: e.Line, Severity: rules.Error, Msg: "interface Nope does not exist on the router"}}
			}
		}
		return nil
	}
	reload := reloader(path, eng, validate)
	if _, err := reload(); err != nil {
		t.Fatalf("valid rules rejected: %v", err)
	}
	os.WriteFile(path, []byte(live+"exit ghost = Nope\n"), 0o644)
	text, err := reload()
	if err == nil || !strings.Contains(text, "line 4: error: interface Nope does not exist") || !strings.Contains(err.Error(), "the previous rules remain") {
		t.Errorf("text %q, error %v", text, err)
	}
	if errors.Is(err, ctl.ErrPartial) {
		t.Error("rejected rules reported as partially applied")
	}
	if len(eng.Config().Exits) != 1 {
		t.Error("rules with a nonexistent interface were applied")
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
		t.Errorf("empty state: %q, %v", b, err)
	}
	// No temporary files are left next to it.
	if left, _ := filepath.Glob(state + ".*"); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
	// The state directory is created private to root; a file where the directory should be is an error.
	dir := filepath.Join(t.TempDir(), "var", "trassa")
	if err := saveState(filepath.Join(dir, "state"), eng); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state directory: %v, %v", fi.Mode().Perm(), err)
	}
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, nil, 0o600)
	if err := saveState(filepath.Join(blocker, "state"), eng); err == nil {
		t.Error("a file in place of the directory must be an error")
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
		t.Error("equal states reported as different")
	}
	b["alt"] = exits.Choice{Interface: "Wireguard0", System: "nwg0"}
	if sameExits(a, b) {
		t.Error("a tunnel that came up was not noticed")
	}
	if sameExits(a, map[string]exits.Choice{"vpn": a["vpn"]}) || sameExits(nil, a) {
		t.Error("different exit sets reported as equal")
	}
}

func TestRunRejectsBadRouteArguments(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": live})
	cases := []struct {
		args []string
		msg  string
	}{
		{[]string{"run", "-rules", path, "-source", "192.168.1.94"}, "-source"},
		{[]string{"run", "-rules", path, "-route", "-source", "not-an-address"}, "-source"},
		{[]string{"run", "-rules", path, "-route", "-source", "fdbd::1"}, "-source"},
	}
	for _, c := range cases {
		t.Setenv("TRASSA_SOCK", filepath.Join(t.TempDir(), "s.sock"))
		if code, _, errOut := exec(c.args...); code != 2 || !strings.Contains(errOut, c.msg) {
			t.Errorf("%v: code %d, stderr %q", c.args, code, errOut)
		}
	}
	// The firmware is unreachable: exits cannot be checked, so the daemon does not start in routing mode.
	t.Setenv("TRASSA_SOCK", filepath.Join(t.TempDir(), "s.sock"))
	code, _, errOut := exec("run", "-rules", path, "-route", "-rci", "http://127.0.0.1:1")
	if code != 1 || !strings.Contains(errOut, "firmware does not respond") || !strings.Contains(errOut, "daemon is not started") {
		t.Errorf("unreachable firmware: code %d, stderr %q", code, errOut)
	}
}

// brokenSink is a set of address sets and routes that cannot be built.
type brokenSink struct{}

func (brokenSink) Apply([]claims.Change) error { return errors.New("ipset unavailable") }
func (brokenSink) Rebuild(*rules.Config, []claims.Entry) error {
	return errors.New("ipset unavailable")
}

func TestReloadReportsBuildFailure(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": live})
	cfg, _, _ := load(path, os.Stderr)
	eng := engine.New(cfg, brokenSink{}, func(string, ...any) {}, time.Now())
	os.WriteFile(path, []byte(live+"vimeo.com -> vpn\n"), 0o644)
	text, err := reloader(path, eng, nil)()
	if err == nil || !strings.Contains(err.Error(), "building the address sets and routes failed") || strings.Contains(text, "rules reloaded") || !errors.Is(err, ctl.ErrPartial) {
		t.Errorf("build failure reported as success: text %q, error %v", text, err)
	}
	// The rules are still accepted, and the build will be retried.
	if len(eng.Config().Rules) != 2 || !eng.NeedsResync() {
		t.Errorf("rules %d, needs rebuild: %v", len(eng.Config().Rules), eng.NeedsResync())
	}
}

func TestHandlerState(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": live})
	cfg, _, _ := load(path, os.Stderr)
	eng := engine.New(cfg, nil, func(string, ...any) {}, time.Now())
	text, err := handler(eng, nil, nil)("state", "")
	var st ctl.State
	if err != nil || json.Unmarshal([]byte(text), &st) != nil || st.Mode != "observe" || st.Rules != 1 {
		t.Errorf("answer %q, error %v", text, err)
	}
}

// The state file is not read through a symlink planted in its place.
func TestStateIsNotReadThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	os.WriteFile(target, []byte("{}\n"), 0o600)
	link := filepath.Join(dir, "state")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openState(link); err == nil {
		f.Close()
		t.Error("the state file was opened through a symlink")
	}
	if f, err := openState(target); err != nil {
		t.Errorf("a regular state file: %v", err)
	} else {
		f.Close()
	}
}

// A router without a clock battery may boot with its clock behind: the state file's own time
// is a lower bound for the real time.
func TestLoadTime(t *testing.T) {
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	written := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if got := loadTime(now, written); !got.Equal(written) {
		t.Errorf("clock behind the file: %v", got)
	}
	if got := loadTime(written.Add(time.Hour), written); !got.Equal(written.Add(time.Hour)) {
		t.Errorf("clock ahead of the file: %v", got)
	}
}

// The page and "trassa disable" ask the daemon to stop over the control socket.
func TestHandlerStop(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": live})
	cfg, _, _ := load(path, os.Stderr)
	eng := engine.New(cfg, nil, func(string, ...any) {}, time.Now())
	stopped := 0
	if text, err := handler(eng, nil, func() { stopped++ })("stop", ""); err != nil || stopped != 1 || text == "" {
		t.Errorf("stop: %q, %v, stopped %d", text, err, stopped)
	}
}
