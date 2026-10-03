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
	// reloadTimeout is how long to wait for the daemon to reload the rules: checking exits with
	// the firmware and rebuilding the address sets together fit into half a minute.
	reloadTimeout = 40 * time.Second
)

// newStore returns the rules directory on the router: exits are checked with the firmware and
// the daemon applies the rules.
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

// applyViaDaemon asks the daemon to reload the rules file and maps its answer to a store outcome.
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

// printResult prints the outcome of restoring a version. Exit code 0 means the rules are in effect
// or will take effect when the daemon starts.
func printResult(out io.Writer, res store.Result) int {
	warnings := printProblems(out, res.Problems)
	switch {
	case rules.HasErrors(res.Problems):
		fmt.Fprintf(out, "errors: %d — version not restored\n", len(res.Problems)-warnings)
		return 1
	case res.NeedConfirm:
		fmt.Fprintln(out, "there are warnings — version not restored; to restore it anyway: trassa rollback -y")
		return 1
	case res.Unchanged:
		fmt.Fprintln(out, "this version is already in effect")
		return 0
	case !res.Saved:
		fmt.Fprintf(out, "version not restored: %s\n", res.Message)
		return 1
	}
	fmt.Fprintf(out, "version restored: rules %d, exits %d, expectations %d\n%s\n", res.Rules, res.Exits, res.Tests, res.Message)
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
