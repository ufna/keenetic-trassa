// Package dataplane меняет сетевые таблицы роутера, вызывая системные утилиты.
package dataplane

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner запускает системную утилиту. В тестах подменяется.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// InputRunner умеет ещё и подать утилите текст на вход.
type InputRunner interface {
	Runner
	RunInput(ctx context.Context, stdin, name string, args ...string) (string, error)
}

// Exec запускает утилиты по-настоящему.
type Exec struct{}

func (e Exec) Run(ctx context.Context, name string, args ...string) (string, error) {
	return e.RunInput(ctx, "", name, args...)
}

func (Exec) RunInput(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// Утилита может оставить дочерний процесс, который держит поток вывода; без этого предела
	// ожидание вывода длилось бы дольше отведённого времени.
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
