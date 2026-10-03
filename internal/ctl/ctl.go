// Package ctl is the local control socket through which the trassa utility and the web page talk to the daemon.
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

// Handler executes a command. The text is returned to the client even on error.
type Handler func(cmd, arg string) (text string, err error)

var (
	// ErrNoDaemon means the socket cannot be reached: the daemon is not running.
	ErrNoDaemon = errors.New("trassa daemon is not running")
	// ErrNoReply means the daemon accepted the command but did not reply in time: its outcome is unknown.
	ErrNoReply = errors.New("trassa daemon did not reply")
	// ErrPartial means the command was only partly done: e.g. the rules were accepted, but the address sets are not built yet.
	ErrPartial = errors.New("partially done")
)

// replyTimeout is the deadline for reading a command and, separately, for sending the reply.
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

// remoteError is an error returned by the daemon.
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

// Serve starts listening on the socket. The returned Closer stops accepting and removes the socket file.
func Serve(path string, h Handler) (io.Closer, error) {
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return nil, fmt.Errorf("trassa is already running: socket %s responds", path)
	}
	os.Remove(path) // file left over after a crash
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
	// The command may have taken a long time: the reply gets its own deadline.
	c.SetDeadline(time.Now().Add(replyTimeout))
	json.NewEncoder(c).Encode(rs)
}

// Call sends a command to the daemon and returns the reply text.
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
