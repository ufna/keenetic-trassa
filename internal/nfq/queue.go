package nfq

import (
	"errors"
	"fmt"
	"syscall"
)

const (
	netlinkNetfilter = 12
	solNetlink       = 270
	netlinkNoEnobufs = 5
	queueMaxLen      = 256
	// copyRange is how many bytes of a packet the kernel passes to the daemon. In practice a DNS response
	// over UDP is never longer; a longer packet arrives truncated and is let through without parsing.
	copyRange = 4096
)

// ErrTimeout means no packets arrived within the wait. It is not a failure: the caller checks whether it is time to stop.
var ErrTimeout = errors.New("nfq: no packets")

// Queue is a bound packet queue. It is not safe for concurrent use.
type Queue struct {
	fd      int
	num     uint16
	seq     uint32
	buf     []byte
	pending []Packet
}

var kernel = &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}

// Open binds queue num. If the daemon stops reading the queue, after queueMaxLen
// pending packets the kernel starts letting them through without a verdict.
func Open(num uint16) (*Queue, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, netlinkNetfilter)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	q := &Queue{fd: fd, num: num, buf: make([]byte, 128<<10)}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("binding netlink socket: %w", err)
	}
	// A one-second read timeout: the receive loop regularly gets control back.
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)
	syscall.SetsockoptInt(fd, solNetlink, netlinkNoEnobufs, 1)

	steps := []struct {
		what  string
		build func(seq uint32) []byte
	}{
		{"binding queue", func(s uint32) []byte { return configCmd(num, cfgCmdBind, s) }},
		{"copy mode", func(s uint32) []byte { return configParams(num, copyPacket, copyRange, s) }},
		{"queue length", func(s uint32) []byte { return configMaxLen(num, queueMaxLen, s) }},
		{"fail-open on overflow", func(s uint32) []byte { return configFlags(num, flagFailOpen, flagFailOpen, s) }},
	}
	for _, st := range steps {
		if err := q.request(st.build); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("%s: %w", st.what, err)
		}
	}
	return q, nil
}

// request sends a configuration request and waits for the acknowledgement. Packets arriving meanwhile are set aside.
func (q *Queue) request(build func(seq uint32) []byte) error {
	q.seq++
	seq := q.seq
	if err := syscall.Sendto(q.fd, build(seq), 0, kernel); err != nil {
		return err
	}
	for {
		n, _, err := syscall.Recvfrom(q.fd, q.buf, 0)
		if err != nil {
			return fmt.Errorf("kernel did not acknowledge the request: %w", err)
		}
		rs, err := parse(q.buf[:n])
		if err != nil {
			return err
		}
		done, failed := false, error(nil)
		for _, r := range rs {
			switch {
			case r.packet != nil:
				q.keep(r.packet)
			case r.ack && r.seq == seq:
				done = true
				if r.errno != 0 {
					failed = syscall.Errno(-r.errno)
				}
			}
		}
		if done {
			return failed
		}
	}
}

func (q *Queue) keep(p *Packet) {
	q.pending = append(q.pending, Packet{ID: p.ID, Payload: append([]byte(nil), p.Payload...)})
}

// Recv returns the next packet, or ErrTimeout if nothing arrived within a second.
func (q *Queue) Recv() (Packet, error) {
	for len(q.pending) == 0 {
		n, _, err := syscall.Recvfrom(q.fd, q.buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				return Packet{}, ErrTimeout
			}
			return Packet{}, err
		}
		rs, err := parse(q.buf[:n])
		for _, r := range rs {
			if r.packet != nil {
				q.keep(r.packet)
			}
		}
		if err != nil && len(q.pending) == 0 {
			return Packet{}, err
		}
	}
	p := q.pending[0]
	q.pending = q.pending[1:]
	return p, nil
}

// Accept lets the packet continue.
func (q *Queue) Accept(id uint32) error {
	return syscall.Sendto(q.fd, verdict(q.num, id, verdictAccept), 0, kernel)
}

// Close unbinds the queue and closes the socket. After that, a rule with --queue-bypass lets packets through.
func (q *Queue) Close() error {
	q.seq++
	syscall.Sendto(q.fd, configCmd(q.num, cfgCmdUnbind, q.seq), 0, kernel)
	return syscall.Close(q.fd)
}
