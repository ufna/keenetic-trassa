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
	// copyRange — сколько байт пакета ядро передаёт демону. DNS-ответ по UDP длиннее не бывает
	// на практике; более длинный пакет придёт обрезанным и будет отпущен без разбора.
	copyRange = 4096
)

// ErrTimeout — за время ожидания пакетов не пришло. Это не ошибка: вызывающий проверяет, не пора ли остановиться.
var ErrTimeout = errors.New("nfq: пакетов нет")

// Queue — привязанная очередь пакетов. Не потокобезопасна.
type Queue struct {
	fd      int
	num     uint16
	seq     uint32
	buf     []byte
	pending []Packet
}

var kernel = &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}

// Open привязывает очередь num. Если демон перестанет читать очередь, ядро после
// queueMaxLen ожидающих пакетов начнёт пропускать их без вердикта.
func Open(num uint16) (*Queue, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, netlinkNetfilter)
	if err != nil {
		return nil, fmt.Errorf("сокет netlink: %w", err)
	}
	q := &Queue{fd: fd, num: num, buf: make([]byte, 128<<10)}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("привязка сокета netlink: %w", err)
	}
	// Секундный таймаут чтения: цикл приёма регулярно получает управление.
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)
	syscall.SetsockoptInt(fd, solNetlink, netlinkNoEnobufs, 1)

	steps := []struct {
		what  string
		build func(seq uint32) []byte
	}{
		{"привязка очереди", func(s uint32) []byte { return configCmd(num, cfgCmdBind, s) }},
		{"режим копирования", func(s uint32) []byte { return configParams(num, copyPacket, copyRange, s) }},
		{"длина очереди", func(s uint32) []byte { return configMaxLen(num, queueMaxLen, s) }},
		{"пропуск при переполнении", func(s uint32) []byte { return configFlags(num, flagFailOpen, flagFailOpen, s) }},
	}
	for _, st := range steps {
		if err := q.request(st.build); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("%s: %w", st.what, err)
		}
	}
	return q, nil
}

// request отправляет запрос настройки и ждёт подтверждения. Пакеты, пришедшие тем временем, откладываются.
func (q *Queue) request(build func(seq uint32) []byte) error {
	q.seq++
	seq := q.seq
	if err := syscall.Sendto(q.fd, build(seq), 0, kernel); err != nil {
		return err
	}
	for {
		n, _, err := syscall.Recvfrom(q.fd, q.buf, 0)
		if err != nil {
			return fmt.Errorf("ядро не подтвердило запрос: %w", err)
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

// Recv возвращает следующий пакет либо ErrTimeout, если за секунду ничего не пришло.
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

// Accept отпускает пакет дальше.
func (q *Queue) Accept(id uint32) error {
	return syscall.Sendto(q.fd, verdict(q.num, id, verdictAccept), 0, kernel)
}

// Close отвязывает очередь и закрывает сокет. После этого правило с --queue-bypass пропускает пакеты.
func (q *Queue) Close() error {
	q.seq++
	syscall.Sendto(q.fd, configCmd(q.num, cfgCmdUnbind, q.seq), 0, kernel)
	return syscall.Close(q.fd)
}
