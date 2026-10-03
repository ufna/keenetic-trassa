// Package dataplane changes the router's network tables by running system utilities.
package dataplane

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner runs a system utility. Tests substitute it.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// InputRunner can also feed text to a utility's standard input.
type InputRunner interface {
	Runner
	RunInput(ctx context.Context, stdin, name string, args ...string) (string, error)
}

// Exec runs utilities for real.
type Exec struct{}

func (e Exec) Run(ctx context.Context, name string, args ...string) (string, error) {
	return e.RunInput(ctx, "", name, args...)
}

func (Exec) RunInput(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// A utility may leave behind a child process that holds the output stream; without this limit
	// waiting for the output would outlast the allotted time.
	cmd.WaitDelay = time.Second
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
