// Package ctl — локальный сокет, через который утилита trassa и веб-страница разговаривают с демоном.
package ctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// Handler выполняет команду. Текст возвращается клиенту и при ошибке.
type Handler func(cmd, arg string) (text string, err error)

var (
	// ErrNoDaemon — к сокету не подключиться: демон не запущен.
	ErrNoDaemon = errors.New("демон trassa не запущен")
	// ErrNoReply — демон принял команду, но не ответил вовремя: чем она кончилась, неизвестно.
	ErrNoReply = errors.New("демон trassa не ответил")
	// ErrPartial — команда выполнена не полностью: например, правила приняты, а списки ещё не построены.
	ErrPartial = errors.New("выполнено не полностью")
)

// replyTimeout — срок на чтение команды и, отдельно, на отправку ответа.
var replyTimeout = 10 * time.Second

type request struct {
	Cmd string `json:"cmd"`
	Arg string `json:"arg"`
}

type response struct {
	Text    string `json:"text"`
	Err     string `json:"err,omitempty"`
	Partial bool   `json:"partial,omitempty"`
}

// remoteError — ошибка, которую вернул демон.
type remoteError struct {
	msg     string
	partial bool
}

func (e *remoteError) Error() string { return e.msg }

func (e *remoteError) Unwrap() error {
	if e.partial {
		return ErrPartial
	}
	return nil
}

// Serve начинает слушать сокет. Возвращённый Closer останавливает приём и удаляет файл сокета.
func Serve(path string, h Handler) (io.Closer, error) {
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return nil, fmt.Errorf("trassa уже запущен: сокет %s отвечает", path)
	}
	os.Remove(path) // файл остался после аварийного завершения
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go serve(c, h)
		}
	}()
	return l, nil
}

func serve(c net.Conn, h Handler) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(replyTimeout))
	var rq request
	if err := json.NewDecoder(io.LimitReader(c, 64<<10)).Decode(&rq); err != nil {
		return
	}
	text, err := h(rq.Cmd, rq.Arg)
	rs := response{Text: text}
	if err != nil {
		rs.Err, rs.Partial = err.Error(), errors.Is(err, ErrPartial)
	}
	// Команда могла выполняться долго: на ответ — свой срок.
	c.SetDeadline(time.Now().Add(replyTimeout))
	json.NewEncoder(c).Encode(rs)
}

// Call отправляет команду демону и возвращает текст ответа.
func Call(path, cmd, arg string, timeout time.Duration) (string, error) {
	c, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return "", fmt.Errorf("%w (%s): %v", ErrNoDaemon, path, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(c).Encode(request{Cmd: cmd, Arg: arg}); err != nil {
		return "", fmt.Errorf("%w (%s): %v", ErrNoReply, path, err)
	}
	var rs response
	if err := json.NewDecoder(c).Decode(&rs); err != nil {
		return "", fmt.Errorf("%w (%s): %v", ErrNoReply, path, err)
	}
	if rs.Err != "" {
		return rs.Text, &remoteError{rs.Err, rs.Partial}
	}
	return rs.Text, nil
}
