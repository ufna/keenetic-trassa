package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	osexec "os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"trassa/internal/ctl"
	"trassa/internal/dataplane"
	"trassa/internal/engine"
	"trassa/internal/exits"
	"trassa/internal/nfq"
	"trassa/internal/rules"
)

// reloader returns a function that rereads the rules file. On errors the old rules stay.
// validate, if set, checks the exits of the new rules on the router.
func reloader(path string, eng *engine.Engine, validate func(*rules.Config) []rules.Problem) func() (string, error) {
	return func() (string, error) {
		var readErr bytes.Buffer
		cfg, ps, ok := load(path, &readErr)
		if !ok {
			return "", errors.New(strings.TrimSpace(readErr.String()) + "; the previous rules remain")
		}
		if validate != nil && !rules.HasErrors(ps) {
			ps = append(ps, validate(cfg)...)
		}
		var b strings.Builder
		printProblems(&b, ps)
		if rules.HasErrors(ps) {
			return b.String(), errors.New("the rules file has errors; the previous rules remain")
		}
		if err := eng.Reload(cfg); err != nil {
			// The rules are accepted, but the kernel still holds the old state: this is not a success,
			// and not a failure either, since the old rules are no longer in effect.
			return b.String(), fmt.Errorf("%w: rules accepted, but building the address sets and routes failed: %v; it will be retried within 30 seconds", ctl.ErrPartial, err)
		}
		fmt.Fprintf(&b, "rules reloaded: rules %d, exits %d\n", len(cfg.Rules), len(cfg.Exits))
		return b.String(), nil
	}
}

// openState opens the state file without following a symlink planted in its place.
func openState(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// saveState snapshots the claims into memory under the engine lock and writes them outside it:
// the file lives on flash, and a slow write must not hold up the packet loop. The directory is
// private to root; the file is replaced whole and synced.
func saveState(path string, eng *engine.Engine) error {
	var buf bytes.Buffer
	if err := eng.SaveState(&buf); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, werr := f.Write(buf.Bytes())
	if werr == nil {
		werr = f.Sync()
	}
	if err := errors.Join(werr, f.Close()); err != nil {
		os.Remove(f.Name())
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		os.Remove(f.Name())
		return err
	}
	return nil
}

// sameExits compares two exit states.
func sameExits(a, b map[string]exits.Choice) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// handler executes commands that arrive over the control socket.
func handler(eng *engine.Engine, reload func() (string, error)) ctl.Handler {
	return func(cmd, arg string) (string, error) {
		switch cmd {
		case "why":
			return eng.Why(arg, time.Now())
		case "status":
			return eng.Status(time.Now()), nil
		case "state":
			b, err := json.Marshal(eng.State())
			return string(b), err
		case "reload":
			return reload()
		}
		return "", fmt.Errorf("unknown command %q", cmd)
	}
}

// stallLimit is how long the packet loop may stay silent. It gets control at least once a
// second, so several seconds of silence mean it is stuck holding a packet.
const stallLimit = 5 * time.Second

// watchStall calls fail if the packet loop has not checked in for longer than limit. It returns
// when stop is closed. idle measures by the monotonic clock, so changing the system time cannot
// fool the watchdog.
func watchStall(idle func() time.Duration, limit, every time.Duration, stop <-chan struct{}, fail func(idle time.Duration)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if d := idle(); d > limit {
				fail(d)
				return
			}
		}
	}
}

// packetQueue is what the packet loop needs from the packet queue.
type packetQueue interface {
	Recv() (nfq.Packet, error)
	Accept(id uint32) error
}

// maxQueueErrors is how many consecutive queue failures mean the queue is broken.
const maxQueueErrors = 20

// pumpErrorPause is the pause after a read failure; tests set it to zero.
var pumpErrorPause = 200 * time.Millisecond

// pump reads packets from the queue and issues a verdict for each, whatever happens in handle.
// It returns nil when asked to stop and an error if the queue stopped working: then the daemon
// is better off exiting — the kernel starts passing packets by itself and the supervisor
// restarts the daemon.
func pump(q packetQueue, handle func(raw []byte), beat func(), stopping func() bool, logf func(string, ...any)) error {
	failures := 0
	for !stopping() {
		beat()
		p, err := q.Recv()
		if err == nfq.ErrTimeout {
			continue
		}
		if err != nil {
			failures++
			logf("queue: %v", err)
			if failures >= maxQueueErrors {
				return fmt.Errorf("the packet queue is not working: %w", err)
			}
			time.Sleep(pumpErrorPause)
			continue
		}
		safely(handle, p.Payload, logf)
		if err := q.Accept(p.ID); err != nil {
			failures++
			logf("verdict: %v", err)
			if failures >= maxQueueErrors {
				return fmt.Errorf("the kernel does not accept verdicts: %w", err)
			}
			continue
		}
		failures = 0
	}
	return nil
}

// safely calls handle and survives its panic: the packet is still released afterwards.
func safely(handle func(raw []byte), raw []byte, logf func(string, ...any)) {
	defer func() {
		if r := recover(); r != nil {
			logf("panic while parsing a packet: %v", r)
		}
	}()
	handle(raw)
}

// parseOffset parses a UTC offset in the form printed by "date +%z": +0300, -0530.
func parseOffset(s string) (*time.Location, error) {
	if len(s) != 5 || s[0] != '+' && s[0] != '-' {
		return nil, fmt.Errorf("cannot parse time offset %q", s)
	}
	h, err1 := strconv.Atoi(s[1:3])
	m, err2 := strconv.Atoi(s[3:5])
	if err1 != nil || err2 != nil || h > 14 || m > 59 {
		return nil, fmt.Errorf("cannot parse time offset %q", s)
	}
	off := h*3600 + m*60
	if s[0] == '-' {
		off = -off
	}
	return time.FixedZone(s, off), nil
}

// useLocalTime switches times in the log and in answers to local time. The router has no time
// zone database, so the offset is taken from the system utility; if that fails, UTC stays.
func useLocalTime() {
	out, err := osexec.Command("date", "+%z").Output()
	if err != nil {
		return
	}
	if loc, err := parseOffset(strings.TrimSpace(string(out))); err == nil {
		time.Local = loc
	}
}

func cmdCleanup() int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dataplane.DNSTap{}.Remove(ctx, dataplane.Exec{})
	dataplane.Teardown(ctx, dataplane.Exec{})
	return 0
}

func cmdRun(args []string, errw io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rulesPath := fs.String("rules", "/opt/etc/trassa/rules.conf", "")
	pidPath := fs.String("pid", "", "")
	lan := fs.String("lan", "br0", "")
	queue := fs.Uint("queue", 5353, "")
	only := fs.String("only", "", "")
	route := fs.Bool("route", false, "")
	source := fs.String("source", "", "")
	statePath := fs.String("state", "/opt/var/lib/trassa/state", "")
	rci := fs.String("rci", "http://127.0.0.1:79", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprint(errw, usage)
		return 2
	}
	if *queue > 65535 {
		fmt.Fprintln(errw, "-queue: queue number from 0 to 65535")
		return 2
	}
	tap := dataplane.DNSTap{LAN: *lan, Queue: uint16(*queue)}
	if *only != "" {
		a, err := netip.ParseAddr(*only)
		if err != nil || !a.Is4() {
			fmt.Fprintln(errw, "-only: an IPv4 address is needed, for example 192.168.1.94")
			return 2
		}
		tap.Only = a
	}
	var sourceAddr netip.Addr
	if *source != "" {
		a, err := netip.ParseAddr(*source)
		if err != nil || !a.Is4() || !*route {
			fmt.Fprintln(errw, "-source: an IPv4 address is needed, and only together with -route")
			return 2
		}
		sourceAddr = a
	}
	useLocalTime()
	logger := log.New(errw, "", log.LstdFlags)

	cfg, ps, ok := load(*rulesPath, errw)
	if !ok {
		return 1
	}
	if rules.HasErrors(ps) {
		printProblems(errw, ps)
		fmt.Fprintln(errw, "the rules file has errors, the daemon is not started")
		return 1
	}
	var router *dataplane.Router
	var sink engine.Sink
	var validate func(*rules.Config) []rules.Problem
	var src exits.Source
	mode := "observe mode"
	if *route {
		mode = "routing mode"
		if sourceAddr.IsValid() {
			mode += " for " + sourceAddr.String()
		}
		src = exits.RCI{Base: *rci, Client: &http.Client{Timeout: 3 * time.Second}}
		validate = func(c *rules.Config) []rules.Problem {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return exits.Validate(ctx, c, src)
		}
		if ps := validate(cfg); rules.HasErrors(ps) {
			printProblems(errw, ps)
			fmt.Fprintln(errw, "exits failed the check on the router, the daemon is not started")
			return 1
		}
		router = dataplane.NewRouter(dataplane.Exec{}, *lan, sourceAddr)
		sink = router
	}
	eng := engine.New(cfg, sink, logger.Printf, time.Now())
	reload := reloader(*rulesPath, eng, validate)

	// refreshExits asks the firmware about the tunnels and changes the routes if anything changed.
	var current map[string]exits.Choice
	refreshExits := func() {
		if router == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		active, err := exits.Active(ctx, eng.Config(), src, current)
		if err != nil {
			logger.Printf("tunnel state unknown, routes are not changed: %v", err)
			return
		}
		if sameExits(active, current) {
			return
		}
		systems, names := map[string]string{}, map[string]string{}
		for exit, c := range active {
			systems[exit], names[exit] = c.System, c.Interface
			if old, known := current[exit]; !known || old != c {
				if c.System == "" {
					logger.Printf("exit %s: no live tunnels", exit)
				} else {
					logger.Printf("exit %s: goes via %s", exit, c.Interface)
				}
			}
		}
		eng.SetExits(names)
		if err := router.SetExits(systems); err != nil {
			// Keep the previous state: the next round retries.
			logger.Printf("exit routes: %v", err)
			return
		}
		current = active
	}

	// The socket goes first: it also checks that no other instance is running.
	// After a reload over the socket the tunnels are rechecked at once: otherwise a new exit would
	// count as unavailable until the next poll.
	kick := make(chan struct{}, 1)
	reloadAndKick := func() (string, error) {
		text, err := reload()
		if err != nil {
			logger.Printf("rules reload requested over the control socket: %v\n%s", err, text)
		} else {
			logger.Printf("rules reload requested over the control socket: %s", strings.TrimSpace(text))
		}
		select {
		case kick <- struct{}{}:
		default:
		}
		return text, err
	}
	srv, err := ctl.Serve(sockPath(), handler(eng, reloadAndKick))
	if err != nil {
		logger.Printf("control socket: %v", err)
		return 1
	}
	defer srv.Close()

	if router != nil {
		refreshExits()
		if f, err := openState(*statePath); err == nil {
			n := eng.LoadState(f, time.Now())
			f.Close()
			logger.Printf("claims restored from the saved state: %d", n)
		}
		if err := eng.Resync(); err != nil {
			// The error is already logged. Routing mode does not work without address sets and routes.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			dataplane.Teardown(ctx, dataplane.Exec{})
			cancel()
			fmt.Fprintln(errw, "address sets and routes were not built, the daemon is not started")
			return 1
		}
	}

	q, err := nfq.Open(tap.Queue)
	if err != nil {
		logger.Printf("packet queue %d: %v", tap.Queue, err)
		if router != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			dataplane.Teardown(ctx, dataplane.Exec{})
			cancel()
		}
		return 1
	}

	// The packet loop and the watchdog start before the DNS tap rule: from the moment the rule
	// appears, someone is already reading the queue.
	started := time.Now()
	var stopping atomic.Bool
	var beat atomic.Int64 // when the packet loop last got control, relative to started
	stopWatch := make(chan struct{})
	go watchStall(func() time.Duration { return time.Since(started) - time.Duration(beat.Load()) }, stallLimit, time.Second, stopWatch,
		func(idle time.Duration) {
			// Exiting closes the queue socket, and the kernel starts passing DNS answers without the
			// daemon. Logging runs in its own goroutine: if the log itself is stuck, exit is not delayed.
			go logger.Printf("packet loop silent for %s — emergency exit", idle.Round(time.Second))
			time.Sleep(100 * time.Millisecond)
			os.Exit(3)
		})
	failed := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := pump(q, func(raw []byte) { eng.HandlePacket(time.Now(), raw) },
			func() { beat.Store(int64(time.Since(started))) }, stopping.Load, logger.Printf)
		if err != nil {
			failed <- err
		}
	}()

	runner := dataplane.Exec{}
	ensure := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := tap.Ensure(ctx, runner); err != nil {
			logger.Printf("DNS tap rule: %v", err)
		}
	}
	ensure()
	if *pidPath != "" {
		os.WriteFile(*pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
	}
	logger.Printf("trassa started: %s, rules %d, queue %d", mode, len(cfg.Rules), tap.Queue)

	// shutdown removes the rule, waits for the packet loop and closes the queue — in this order:
	// packets must not wait for a verdict that will never come.
	shutdown := func() {
		if router != nil {
			if err := saveState(*statePath, eng); err != nil {
				logger.Printf("state not saved: %v", err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		tap.Remove(ctx, runner)
		cancel()
		close(stopWatch)
		stopping.Store(true)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		q.Close()
		if router != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			dataplane.Teardown(ctx, runner)
			cancel()
		}
		if *pidPath != "" {
			os.Remove(*pidPath)
		}
	}

	// checkRoutes restores the address sets and routes if the firmware wiped them.
	checkRoutes := func() {
		if router == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if eng.NeedsResync() {
			logger.Print("address sets diverged from memory after a failure — rebuilding")
			eng.Resync()
			return
		}
		switch err := router.Reconcile(ctx); {
		case errors.Is(err, dataplane.ErrMissing):
			logger.Printf("%v — rebuilding", err)
			eng.Resync()
		case err != nil:
			logger.Printf("reconciling rules and routes: %v", err)
		}
	}

	sig := make(chan os.Signal, 8)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	exitsTick := time.NewTicker(5 * time.Second)
	defer exitsTick.Stop()
	// The state is on flash: written rarely, and on every stop.
	stateTick := time.NewTicker(30 * time.Minute)
	defer stateTick.Stop()
	for {
		select {
		case err := <-failed:
			logger.Printf("%v — exiting", err)
			shutdown()
			return 4
		case <-tick.C:
			eng.Tick(time.Now())
			ensure()
			checkRoutes()
		case <-exitsTick.C:
			refreshExits()
		case <-kick:
			refreshExits()
		case <-stateTick.C:
			if router != nil {
				if err := saveState(*statePath, eng); err != nil {
					logger.Printf("state not saved: %v", err)
				}
			}
		case s := <-sig:
			switch s {
			case syscall.SIGUSR1:
				ensure()
				checkRoutes()
			case syscall.SIGUSR2:
				refreshExits()
			case syscall.SIGHUP:
				if text, err := reload(); err != nil {
					logger.Printf("reloading rules: %v\n%s", err, text)
				} else {
					logger.Print(strings.TrimSpace(text))
					refreshExits()
				}
			default:
				shutdown()
				logger.Print("trassa stopped")
				return 0
			}
		}
	}
}
