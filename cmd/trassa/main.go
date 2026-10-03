// Command trassa is the flexible-routing daemon for the home router and its command-line tool.
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"trassa/internal/ctl"
	"trassa/internal/rules"
	"trassa/internal/store"
)

const usage = `trassa — flexible routing for the home router

Usage:
  trassa check <rules file>                     check a rules file
  trassa why -f <rules file> <name or address>  decision by a rules file, without the daemon
  trassa why <name, address or link>            decision and DNS details from the running daemon
  trassa status                                 daemon state
  trassa reload                                 reload the rules without stopping
  trassa rollback [-y] [-dir directory]         restore the previous rules version from history
  trassa run [-rules file] [-only address]      run the daemon in observe mode
  trassa run -route [-source address]           run the daemon in routing mode
  trassa web [-listen address] [-dir directory] web page for editing the rules (192.168.1.1:8090)
  trassa cleanup                                remove the DNS tap and routing rules
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const defaultSock = "/tmp/trassa.sock"

// sockPath is the control socket path; the environment variable is for tests.
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
	if len(args) > 0 && args[0] == "rollback" {
		return cmdRollback(args[1:], out, errw)
	}
	if len(args) > 0 && args[0] == "web" {
		return cmdWeb(args[1:], errw)
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

// cmdLive passes a command to the running daemon.
func cmdLive(cmd, arg string, out, errw io.Writer) int {
	// A short wait: the watchdog uses this same command to judge whether the daemon is alive.
	text, err := ctl.Call(sockPath(), cmd, arg, 3*time.Second)
	fmt.Fprint(out, text)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	return 0
}

// load reads a rules file; @path includes are read only from its directory.
func load(path string, errw io.Writer) (*rules.Config, []rules.Problem, bool) {
	cfg, ps, err := store.LoadFile(path)
	if err != nil {
		fmt.Fprintf(errw, "cannot read %s: %v\n", path, err)
		return nil, nil, false
	}
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
		fmt.Fprintf(out, "errors: %d — the rules cannot be applied\n", len(ps)-warnings)
		return 1
	}
	fmt.Fprintf(out, "rules: %d, exits: %d, expectations: %d, warnings: %d — no errors\n",
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
	text, err := cfg.Explain(subject)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	fmt.Fprint(out, text)
	return 0
}
