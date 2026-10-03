package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"trassa/internal/ctl"
	"trassa/internal/exits"
	"trassa/internal/rules"
	"trassa/internal/store"
)

const (
	defaultDir = "/opt/etc/trassa"
	defaultRCI = "http://127.0.0.1:79"
	// reloadTimeout — сколько ждать демона, перечитывающего правила: проверка выходов у прошивки
	// и перестроение списков вместе укладываются в полминуты.
	reloadTimeout = 40 * time.Second
)

// newStore — каталог правил на роутере: выходы проверяются у прошивки, применяет демон.
func newStore(dir, rci string) *store.Store {
	src := exits.RCI{Base: rci, Client: &http.Client{Timeout: 3 * time.Second}}
	return &store.Store{
		Dir: dir,
		Validate: func(c *rules.Config) []rules.Problem {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return exits.Validate(ctx, c, src)
		},
		Apply: applyViaDaemon,
	}
}

// applyViaDaemon просит демон перечитать файл правил и переводит ответ в исход для store.
func applyViaDaemon() (store.Applied, string) {
	text, err := ctl.Call(sockPath(), "reload", "", reloadTimeout)
	switch {
	case err == nil:
		return store.Running, strings.TrimSpace(text)
	case errors.Is(err, ctl.ErrNoDaemon):
		return store.NotRunning, ""
	case errors.Is(err, ctl.ErrNoReply):
		return store.Unknown, err.Error()
	case errors.Is(err, ctl.ErrPartial):
		return store.Partly, strings.TrimSpace(text + "\n" + err.Error())
	}
	return store.Rejected, strings.TrimSpace(text + "\n" + err.Error())
}

// printResult печатает исход возврата версии. Код 0 — правила действуют или вступят в силу
// при запуске демона.
func printResult(out io.Writer, res store.Result) int {
	warnings := printProblems(out, res.Problems)
	switch {
	case rules.HasErrors(res.Problems):
		fmt.Fprintf(out, "ошибок: %d — версия не возвращена\n", len(res.Problems)-warnings)
		return 1
	case res.NeedConfirm:
		fmt.Fprintln(out, "есть предупреждения — версия не возвращена; вернуть всё равно: trassa rollback -y")
		return 1
	case res.Unchanged:
		fmt.Fprintln(out, "эта версия уже действует")
		return 0
	case !res.Saved:
		fmt.Fprintf(out, "версия не возвращена: %s\n", res.Message)
		return 1
	}
	fmt.Fprintf(out, "возвращена версия: правил %d, выходов %d, ожиданий %d\n%s\n", res.Rules, res.Exits, res.Tests, res.Message)
	if res.Applied == store.Running || res.Applied == store.NotRunning {
		return 0
	}
	return 1
}

func cmdRollback(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("y", false, "")
	dir := fs.String("dir", defaultDir, "")
	rci := fs.String("rci", defaultRCI, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprint(errw, usage)
		return 2
	}
	st := newStore(*dir, *rci)
	id, err := st.Previous()
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	res, err := st.Rollback(id, *yes)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	return printResult(out, res)
}
