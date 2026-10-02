// Package ctl — локальный сокет, через который утилита trassa разговаривает с демоном.
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

type request struct {
	Cmd string `json:"cmd"`
	Arg string `json:"arg"`
}

type response struct {
	Text string `json:"text"`
	Err  string `json:"err,omitempty"`
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
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var rq request
	if err := json.NewDecoder(io.LimitReader(c, 64<<10)).Decode(&rq); err != nil {
		return
	}
	text, err := h(rq.Cmd, rq.Arg)
	rs := response{Text: text}
	if err != nil {
		rs.Err = err.Error()
	}
	json.NewEncoder(c).Encode(rs)
}

// Call отправляет команду демону и возвращает текст ответа.
func Call(path, cmd, arg string, timeout time.Duration) (string, error) {
	c, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return "", fmt.Errorf("демон trassa не отвечает (%s): %v", path, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(c).Encode(request{Cmd: cmd, Arg: arg}); err != nil {
		return "", fmt.Errorf("демон trassa не отвечает (%s): %v", path, err)
	}
	var rs response
	if err := json.NewDecoder(c).Decode(&rs); err != nil {
		return "", fmt.Errorf("демон trassa не отвечает (%s): %v", path, err)
	}
	if rs.Err != "" {
		return rs.Text, errors.New(rs.Err)
	}
	return rs.Text, nil
}
