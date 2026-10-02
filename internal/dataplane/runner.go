// Package dataplane меняет сетевые таблицы роутера, вызывая системные утилиты.
package dataplane

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner запускает системную утилиту. В тестах подменяется.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// Exec запускает утилиты по-настоящему.
type Exec struct{}

func (Exec) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
