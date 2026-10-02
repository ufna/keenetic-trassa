// Команда trassa: проверка файла правил и объяснение решений.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trassa/internal/ctl"
	"trassa/internal/rules"
)

const usage = `trassa — гибкая маршрутизация для домашнего роутера

Использование:
  trassa check <файл правил>                   проверить файл правил
  trassa why -f <файл правил> <имя или адрес>   решение по файлу правил, без демона
  trassa why <имя или адрес>                    решение и сведения из DNS у работающего демона
  trassa status                                 состояние демона
  trassa reload                                 перечитать правила без остановки
  trassa run [-rules файл] [-only адрес]        запустить демон (режим наблюдения)
  trassa cleanup                                снять правила перехвата DNS
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const defaultSock = "/tmp/trassa.sock"

// sockPath — путь сокета управления; переменная окружения нужна тестам.
func sockPath() string {
	if p := os.Getenv("TRASSA_SOCK"); p != "" {
		return p
	}
	return defaultSock
}

func run(args []string, out, errw io.Writer) int {
	if len(args) > 0 && args[0] == "run" {
		return cmdRun(args[1:], errw)
	}
	switch {
	case len(args) == 2 && args[0] == "check":
		return cmdCheck(args[1], out, errw)
	case len(args) == 4 && args[0] == "why" && args[1] == "-f":
		return cmdWhy(args[2], args[3], out, errw)
	case len(args) == 2 && args[0] == "why" && args[1] != "-f":
		return cmdLive("why", args[1], out, errw)
	case len(args) == 1 && (args[0] == "status" || args[0] == "reload"):
		return cmdLive(args[0], "", out, errw)
	case len(args) == 1 && args[0] == "cleanup":
		return cmdCleanup()
	}
	fmt.Fprint(errw, usage)
	return 2
}

// cmdLive передаёт команду работающему демону.
func cmdLive(cmd, arg string, out, errw io.Writer) int {
	text, err := ctl.Call(sockPath(), cmd, arg, 5*time.Second)
	fmt.Fprint(out, text)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	return 0
}

// load читает файл правил; пути в условиях @файл считаются от его каталога.
func load(path string, errw io.Writer) (*rules.Config, []rules.Problem, bool) {
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(errw, "не могу прочитать %s: %v\n", path, err)
		return nil, nil, false
	}
	dir := filepath.Dir(path)
	read := func(p string) (string, error) {
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		b, err := os.ReadFile(p)
		return string(b), err
	}
	cfg, ps := rules.Load(string(src), read)
	return cfg, ps, true
}

func printProblems(out io.Writer, ps []rules.Problem) (warnings int) {
	for _, p := range ps {
		fmt.Fprintln(out, p)
		if p.Severity == rules.Warning {
			warnings++
		}
	}
	return warnings
}

func cmdCheck(path string, out, errw io.Writer) int {
	cfg, ps, ok := load(path, errw)
	if !ok {
		return 1
	}
	warnings := printProblems(out, ps)
	if rules.HasErrors(ps) {
		fmt.Fprintf(out, "ошибок: %d — правила применять нельзя\n", len(ps)-warnings)
		return 1
	}
	fmt.Fprintf(out, "правил: %d, выходов: %d, ожиданий: %d, предупреждений: %d — ошибок нет\n",
		len(cfg.Rules), len(cfg.Exits), len(cfg.Tests), warnings)
	return 0
}

func cmdWhy(path, subject string, out, errw io.Writer) int {
	cfg, ps, ok := load(path, errw)
	if !ok {
		return 1
	}
	if rules.HasErrors(ps) {
		printProblems(out, ps)
		return 1
	}
	subject, d, err := cfg.MatchSubject(subject)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	fmt.Fprintf(out, "%s → %s\n", subject, d.Action)
	if d.Rule != nil {
		fmt.Fprintf(out, "правило, строка %d: %s\n", d.Rule.Line, d.Rule.Text)
	} else {
		fmt.Fprintf(out, "ни одно правило не подошло, действует default (строка %d)\n", cfg.DefaultLine)
	}
	if e, found := cfg.Exit(d.Action.Exit); found {
		fmt.Fprintf(out, "выход %s: %s\n", e.Name, strings.Join(e.Interfaces, ", "))
	} else {
		fmt.Fprintln(out, "выход direct: напрямую через провайдера")
	}
	return 0
}
