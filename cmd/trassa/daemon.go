package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	osexec "os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"trassa/internal/ctl"
	"trassa/internal/dataplane"
	"trassa/internal/engine"
	"trassa/internal/nfq"
	"trassa/internal/rules"
)

// reloader возвращает функцию, перечитывающую файл правил. При ошибках правила остаются прежними.
func reloader(path string, eng *engine.Engine) func() (string, error) {
	return func() (string, error) {
		var readErr bytes.Buffer
		cfg, ps, ok := load(path, &readErr)
		if !ok {
			return "", errors.New(strings.TrimSpace(readErr.String()) + "; оставлены прежние правила")
		}
		var b strings.Builder
		printProblems(&b, ps)
		if rules.HasErrors(ps) {
			return b.String(), errors.New("в файле правил ошибки; оставлены прежние правила")
		}
		eng.Reload(cfg)
		fmt.Fprintf(&b, "правила перечитаны: правил %d, выходов %d\n", len(cfg.Rules), len(cfg.Exits))
		return b.String(), nil
	}
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
func watchStall(beat func() time.Time, limit, every time.Duration, stop <-chan struct{}, fail func(idle time.Duration)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if idle := time.Since(beat()); idle > limit {
				fail(idle)
				return
			}
		}
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dataplane.DNSTap{}.Remove(ctx, dataplane.Exec{})
	return 0
}

func cmdRun(args []string, errw io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rulesPath := fs.String("rules", "/opt/etc/trassa/rules.conf", "")
	pidPath := fs.String("pid", "/tmp/trassa.pid", "")
	lan := fs.String("lan", "br0", "")
	queue := fs.Uint("queue", 5353, "")
	only := fs.String("only", "", "")
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
	eng := engine.New(cfg, nil, logger.Printf, time.Now())
	reload := reloader(*rulesPath, eng)

	// Сокет первым: он же проверяет, что другой экземпляр не запущен.
	srv, err := ctl.Serve(sockPath(), handler(eng, reload))
	if err != nil {
		logger.Printf("сокет управления: %v", err)
		return 1
	}
	defer srv.Close()

	// Сначала очередь, потом правило: пока очереди нет, правило пропускает пакеты само.
	q, err := nfq.Open(tap.Queue)
	if err != nil {
		logger.Printf("очередь пакетов %d: %v", tap.Queue, err)
		return 1
	}
	runner := dataplane.Exec{}
	ensure := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := tap.Ensure(ctx, runner); err != nil {
			logger.Printf("правило перехвата DNS: %v", err)
		}
	}
	ensure()
	os.WriteFile(*pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
	logger.Printf("trassa запущен: режим наблюдения, правил %d, очередь %d", len(cfg.Rules), tap.Queue)

	var stopping atomic.Bool
	var beat atomic.Int64 // когда цикл приёма последний раз получал управление
	beat.Store(time.Now().UnixNano())
	stopWatch := make(chan struct{})
	go watchStall(func() time.Time { return time.Unix(0, beat.Load()) }, stallLimit, time.Second, stopWatch, func(idle time.Duration) {
		// Выход закрывает сокет очереди, и ядро начинает пропускать DNS-ответы без демона.
		logger.Printf("цикл приёма пакетов молчит %s — аварийное завершение", idle.Round(time.Second))
		os.Exit(3)
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stopping.Load() {
			beat.Store(time.Now().UnixNano())
			p, err := q.Recv()
			if err == nfq.ErrTimeout {
				continue
			}
			if err != nil {
				logger.Printf("очередь: %v", err)
				time.Sleep(200 * time.Millisecond)
				continue
			}
			handle(eng, logger, p.Payload)
			if err := q.Accept(p.ID); err != nil {
				logger.Printf("вердикт: %v", err)
			}
		}
	}()

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGUSR1)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			eng.Tick(time.Now())
			ensure()
		case s := <-sig:
			switch s {
			case syscall.SIGUSR1:
				ensure()
			case syscall.SIGHUP:
				if text, err := reload(); err != nil {
					logger.Printf("перечитывание правил: %v\n%s", err, text)
				} else {
					logger.Print(strings.TrimSpace(text))
				}
			default:
				// Сначала снять правило, потом закрыть очередь: пакеты не должны ждать вердикта, которого не будет.
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
				os.Remove(*pidPath)
				logger.Print("trassa остановлен")
				return 0
			}
		}
	}
}

// handle учитывает пакет. Что бы ни случилось при разборе, пакет будет отпущен.
func handle(eng *engine.Engine, logger *log.Logger, raw []byte) {
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("сбой при разборе пакета: %v", r)
		}
	}()
	eng.HandlePacket(time.Now(), raw)
}
