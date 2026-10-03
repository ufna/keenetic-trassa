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
	"trassa/internal/devices"
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

// newStore returns the rules directory on the router: exits and device lists are checked with the
// firmware, and the daemon applies the rules.
func newStore(dir, rci string) *store.Store {
	client := &http.Client{Timeout: 3 * time.Second}
	src := exits.RCI{Base: rci, Client: client}
	devs := devices.RCI{Base: rci, Client: client}
	return &store.Store{
		Dir: dir,
		Validate: func(c *rules.Config) []rules.Problem {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return append(exits.Validate(ctx, c, src), devices.Check(ctx, c, devs)...)
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

// cmdPower turns trassa on or off, like the switch on the web page. Off: the mark is written
// first, then the daemon is asked to stop; the init script does not start it while the mark exists.
func cmdPower(on bool, args []string, out, errw io.Writer) int {
	name := "disable"
	if on {
		name = "enable"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultDir, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprint(errw, usage)
		return 2
	}
	st := &store.Store{Dir: *dir}
	if on {
		if err := st.Enable(); err != nil {
			fmt.Fprintln(errw, "trassa not turned on:", err)
			return 1
		}
		fmt.Fprintln(out, "trassa is turned on: the init script starts the daemon within a few seconds")
		return 0
	}
	if err := st.Disable(); err != nil {
		fmt.Fprintln(errw, "trassa not turned off:", err)
		return 1
	}
	if _, err := ctl.Call(sockPath(), "stop", "", 3*time.Second); err != nil && !errors.Is(err, ctl.ErrNoDaemon) {
		fmt.Fprintln(out, "trassa is turned off, but the daemon did not confirm the stop:", err)
		return 1
	}
	fmt.Fprintln(out, "trassa is turned off: the daemon removes its routes and stays off after a reboot; turn on: trassa enable")
	return 0
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
