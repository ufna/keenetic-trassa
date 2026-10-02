package main

import (
	"bytes"
	"context"
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

// reloader возвращает функцию, перечитывающую файл правил. При ошибках правила остаются прежними.
// validate, если задана, проверяет выходы новых правил на роутере.
func reloader(path string, eng *engine.Engine, validate func(*rules.Config) []rules.Problem) func() (string, error) {
	return func() (string, error) {
		var readErr bytes.Buffer
		cfg, ps, ok := load(path, &readErr)
		if !ok {
			return "", errors.New(strings.TrimSpace(readErr.String()) + "; оставлены прежние правила")
		}
		if validate != nil && !rules.HasErrors(ps) {
			ps = append(ps, validate(cfg)...)
		}
		var b strings.Builder
		printProblems(&b, ps)
		if rules.HasErrors(ps) {
			return b.String(), errors.New("в файле правил ошибки; оставлены прежние правила")
		}
		if err := eng.Reload(cfg); err != nil {
			// Правила приняты, но в ядре пока прежнее состояние: об успехе сообщать нельзя.
			return b.String(), fmt.Errorf("правила приняты, но списки и маршруты построить не удалось: %v; попытка повторится в течение 30 секунд", err)
		}
		fmt.Fprintf(&b, "правила перечитаны: правил %d, выходов %d\n", len(cfg.Rules), len(cfg.Exits))
		return b.String(), nil
	}
}

// saveState записывает состояние во временный файл и подменяет им прежний: при сбое
// посреди записи прежний файл остаётся целым.
func saveState(path string, eng *engine.Engine) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	if err := eng.SaveState(f); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), path)
}

// sameExits сравнивает два состояния выходов.
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

// handler исполняет команды, пришедшие по сокету управления.
func handler(eng *engine.Engine, reload func() (string, error)) ctl.Handler {
	return func(cmd, arg string) (string, error) {
		switch cmd {
		case "why":
			return eng.Why(arg, time.Now())
		case "status":
			return eng.Status(time.Now()), nil
		case "reload":
			return reload()
		}
		return "", fmt.Errorf("неизвестная команда %q", cmd)
	}
}

// stallLimit — сколько цикл приёма пакетов может молчать. Он получает управление не реже раза
// в секунду, поэтому несколько секунд тишины означают, что он застрял с пакетом на руках.
const stallLimit = 5 * time.Second

// watchStall вызывает fail, если цикл приёма не отмечался дольше limit. Завершается по закрытию stop.
// idle возвращает простой по монотонным часам: перевод системного времени сторожа не обманывает.
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

// packetQueue — то, что циклу приёма нужно от очереди пакетов.
type packetQueue interface {
	Recv() (nfq.Packet, error)
	Accept(id uint32) error
}

// maxQueueErrors — сколько сбоев очереди подряд означают, что она не работает.
const maxQueueErrors = 20

// pumpErrorPause — пауза после сбоя чтения; тесты её обнуляют.
var pumpErrorPause = 200 * time.Millisecond

// pump читает пакеты из очереди и на каждый выдаёт вердикт, что бы ни случилось в handle.
// Возвращает nil по сигналу остановки и ошибку, если очередь перестала работать: тогда
// демону лучше выйти — ядро начнёт пропускать пакеты само, а присмотр запустит его заново.
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
			logf("очередь: %v", err)
			if failures >= maxQueueErrors {
				return fmt.Errorf("очередь пакетов не работает: %w", err)
			}
			time.Sleep(pumpErrorPause)
			continue
		}
		safely(handle, p.Payload, logf)
		if err := q.Accept(p.ID); err != nil {
			failures++
			logf("вердикт: %v", err)
			if failures >= maxQueueErrors {
				return fmt.Errorf("ядро не принимает вердикты: %w", err)
			}
			continue
		}
		failures = 0
	}
	return nil
}

// safely вызывает handle и переживает его сбой: пакет после этого всё равно будет отпущен.
func safely(handle func(raw []byte), raw []byte, logf func(string, ...any)) {
	defer func() {
		if r := recover(); r != nil {
			logf("сбой при разборе пакета: %v", r)
		}
	}()
	handle(raw)
}

// parseOffset разбирает смещение от UTC в виде, который печатает «date +%z»: +0300, -0530.
func parseOffset(s string) (*time.Location, error) {
	if len(s) != 5 || s[0] != '+' && s[0] != '-' {
		return nil, fmt.Errorf("непонятное смещение времени %q", s)
	}
	h, err1 := strconv.Atoi(s[1:3])
	m, err2 := strconv.Atoi(s[3:5])
	if err1 != nil || err2 != nil || h > 14 || m > 59 {
		return nil, fmt.Errorf("непонятное смещение времени %q", s)
	}
	off := h*3600 + m*60
	if s[0] == '-' {
		off = -off
	}
	return time.FixedZone(s, off), nil
}

// useLocalTime переводит время в журнале и в ответах на местное. На роутере нет базы часовых
// поясов, поэтому смещение спрашивается у системной утилиты; не получилось — остаётся UTC.
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
	statePath := fs.String("state", "/tmp/trassa.state", "")
	rci := fs.String("rci", "http://127.0.0.1:79", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprint(errw, usage)
		return 2
	}
	if *queue > 65535 {
		fmt.Fprintln(errw, "-queue: номер очереди от 0 до 65535")
		return 2
	}
	tap := dataplane.DNSTap{LAN: *lan, Queue: uint16(*queue)}
	if *only != "" {
		a, err := netip.ParseAddr(*only)
		if err != nil || !a.Is4() {
			fmt.Fprintln(errw, "-only: нужен адрес IPv4, например 192.168.1.94")
			return 2
		}
		tap.Only = a
	}
	var sourceAddr netip.Addr
	if *source != "" {
		a, err := netip.ParseAddr(*source)
		if err != nil || !a.Is4() || !*route {
			fmt.Fprintln(errw, "-source: нужен адрес IPv4, и только вместе с -route")
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
		fmt.Fprintln(errw, "в файле правил ошибки, демон не запущен")
		return 1
	}
	var router *dataplane.Router
	var sink engine.Sink
	var validate func(*rules.Config) []rules.Problem
	var src exits.Source
	mode := "режим наблюдения"
	if *route {
		mode = "режим маршрутизации"
		if sourceAddr.IsValid() {
			mode += " для " + sourceAddr.String()
		}
		src = exits.RCI{Base: *rci, Client: &http.Client{Timeout: 3 * time.Second}}
		validate = func(c *rules.Config) []rules.Problem {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return exits.Validate(ctx, c, src)
		}
		if ps := validate(cfg); rules.HasErrors(ps) {
			printProblems(errw, ps)
			fmt.Fprintln(errw, "выходы не прошли проверку на роутере, демон не запущен")
			return 1
		}
		router = dataplane.NewRouter(dataplane.Exec{}, *lan, sourceAddr)
		sink = router
	}
	eng := engine.New(cfg, sink, logger.Printf, time.Now())
	reload := reloader(*rulesPath, eng, validate)

	// refreshExits спрашивает прошивку о туннелях и, если что-то изменилось, меняет маршруты.
	var current map[string]exits.Choice
	refreshExits := func() {
		if router == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		active, err := exits.Active(ctx, eng.Config(), src, current)
		if err != nil {
			logger.Printf("состояние туннелей неизвестно, маршруты не меняются: %v", err)
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
					logger.Printf("выход %s: живых туннелей нет", exit)
				} else {
					logger.Printf("выход %s: идёт через %s", exit, c.Interface)
				}
			}
		}
		eng.SetExits(names)
		if err := router.SetExits(systems); err != nil {
			// Прежнее состояние не забываем: на следующем шаге попытка повторится.
			logger.Printf("маршруты выходов: %v", err)
			return
		}
		current = active
	}

	// Сокет первым: он же проверяет, что другой экземпляр не запущен.
	// После перечитывания правил по сокету туннели перепроверяются сразу: новый выход иначе
	// считался бы недоступным до следующего опроса.
	kick := make(chan struct{}, 1)
	reloadAndKick := func() (string, error) {
		text, err := reload()
		select {
		case kick <- struct{}{}:
		default:
		}
		return text, err
	}
	srv, err := ctl.Serve(sockPath(), handler(eng, reloadAndKick))
	if err != nil {
		logger.Printf("сокет управления: %v", err)
		return 1
	}
	defer srv.Close()

	if router != nil {
		refreshExits()
		if f, err := os.Open(*statePath); err == nil {
			n := eng.LoadState(f, time.Now())
			f.Close()
			logger.Printf("из сохранённого состояния восстановлено претензий: %d", n)
		}
		if err := eng.Resync(); err != nil {
			// Строка об ошибке уже в журнале. Без списков и маршрутов режим маршрутизации не работает.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			dataplane.Teardown(ctx, dataplane.Exec{})
			cancel()
			fmt.Fprintln(errw, "списки и маршруты не построены, демон не запущен")
			return 1
		}
	}

	q, err := nfq.Open(tap.Queue)
	if err != nil {
		logger.Printf("очередь пакетов %d: %v", tap.Queue, err)
		if router != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			dataplane.Teardown(ctx, dataplane.Exec{})
			cancel()
		}
		return 1
	}

	// Цикл приёма и сторож запускаются до правила перехвата: с момента, когда правило
	// появилось, очередь уже кто-то читает.
	started := time.Now()
	var stopping atomic.Bool
	var beat atomic.Int64 // когда цикл приёма последний раз получал управление, от started
	stopWatch := make(chan struct{})
	go watchStall(func() time.Duration { return time.Since(started) - time.Duration(beat.Load()) }, stallLimit, time.Second, stopWatch,
		func(idle time.Duration) {
			// Выход закрывает сокет очереди, и ядро начинает пропускать DNS-ответы без демона.
			// Запись в журнал — в отдельном потоке: если застрял сам журнал, выход это не задержит.
			go logger.Printf("цикл приёма пакетов молчит %s — аварийное завершение", idle.Round(time.Second))
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
			logger.Printf("правило перехвата DNS: %v", err)
		}
	}
	ensure()
	if *pidPath != "" {
		os.WriteFile(*pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
	}
	logger.Printf("trassa запущен: %s, правил %d, очередь %d", mode, len(cfg.Rules), tap.Queue)

	// shutdown снимает правило, дожидается цикла приёма и закрывает очередь — в этом порядке:
	// пакеты не должны ждать вердикта, которого не будет.
	shutdown := func() {
		if router != nil {
			if err := saveState(*statePath, eng); err != nil {
				logger.Printf("состояние не сохранено: %v", err)
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

	// checkRoutes восстанавливает списки и маршруты, если прошивка их стёрла.
	checkRoutes := func() {
		if router == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if eng.NeedsResync() {
			logger.Print("списки расходятся с памятью после сбоя — строю заново")
			eng.Resync()
			return
		}
		switch err := router.Reconcile(ctx); {
		case errors.Is(err, dataplane.ErrMissing):
			logger.Printf("%v — строю заново", err)
			eng.Resync()
		case err != nil:
			logger.Printf("сверка правил и маршрутов: %v", err)
		}
	}

	sig := make(chan os.Signal, 8)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	exitsTick := time.NewTicker(5 * time.Second)
	defer exitsTick.Stop()
	stateTick := time.NewTicker(5 * time.Minute)
	defer stateTick.Stop()
	for {
		select {
		case err := <-failed:
			logger.Printf("%v — завершение", err)
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
					logger.Printf("состояние не сохранено: %v", err)
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
					logger.Printf("перечитывание правил: %v\n%s", err, text)
				} else {
					logger.Print(strings.TrimSpace(text))
					refreshExits()
				}
			default:
				shutdown()
				logger.Print("trassa остановлен")
				return 0
			}
		}
	}
}
