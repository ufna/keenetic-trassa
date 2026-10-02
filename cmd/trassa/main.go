// Команда trassa: проверка файла правил и объяснение решений.
package main

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"trassa/internal/rules"
)

const usage = `trassa — гибкая маршрутизация для домашнего роутера

Использование:
  trassa check <файл правил>                  проверить файл правил
  trassa why -f <файл правил> <имя или адрес>  куда пойдёт имя или адрес и по какому правилу
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	switch {
	case len(args) == 2 && args[0] == "check":
		return cmdCheck(args[1], out, errw)
	case len(args) == 4 && args[0] == "why" && args[1] == "-f":
		return cmdWhy(args[2], args[3], out, errw)
	}
	fmt.Fprint(errw, usage)
	return 2
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
	var d rules.Decision
	subject = strings.TrimSpace(subject)
	if a, err := netip.ParseAddr(subject); err == nil {
		d = cfg.MatchAddr(a)
	} else {
		name, err := rules.NormalizeName(subject)
		if err != nil {
			fmt.Fprintln(errw, err)
			return 1
		}
		subject, d = name, cfg.MatchName(name)
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
