// Package dnsmsg разбирает DNS-ответы: вопрос, записи A, AAAA и CNAME.
package dnsmsg

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"
)

const (
	TypeA     uint16 = 1
	TypeCNAME uint16 = 5
	TypeAAAA  uint16 = 28
)

var ErrMalformed = errors.New("повреждённое DNS-сообщение")

type Answer struct {
	Name   string
	Type   uint16
	TTL    uint32
	Addr   netip.Addr // для A и AAAA
	Target string     // для CNAME
}

type Message struct {
	ID        uint16
	Response  bool
	Truncated bool
	RCode     int
	Question  string
	QType     uint16
	Answers   []Answer
}

// Parse разбирает DNS-сообщение (полезную нагрузку UDP). Разделы после ответов не читаются.
func Parse(b []byte) (*Message, error) {
	if len(b) < 12 {
		return nil, ErrMalformed
	}
	flags := binary.BigEndian.Uint16(b[2:])
	m := &Message{
		ID:        binary.BigEndian.Uint16(b),
		Response:  flags&0x8000 != 0,
		Truncated: flags&0x0200 != 0,
		RCode:     int(flags & 0x000f),
	}
	if binary.BigEndian.Uint16(b[4:]) != 1 {
		return nil, ErrMalformed
	}
	answers := int(binary.BigEndian.Uint16(b[6:]))
	name, off, err := readName(b, 12)
	if err != nil {
		return nil, err
	}
	if off+4 > len(b) {
		return nil, ErrMalformed
	}
	m.Question, m.QType = name, binary.BigEndian.Uint16(b[off:])
	off += 4
	for i := 0; i < answers; i++ {
		name, next, err := readName(b, off)
		if err != nil {
			return nil, err
		}
		if next+10 > len(b) {
			return nil, ErrMalformed
		}
		a := Answer{
			Name: name,
			Type: binary.BigEndian.Uint16(b[next:]),
			TTL:  binary.BigEndian.Uint32(b[next+4:]),
		}
		rdlen := int(binary.BigEndian.Uint16(b[next+8:]))
		rd := next + 10
		if rd+rdlen > len(b) {
			return nil, ErrMalformed
		}
		switch a.Type {
		case TypeA:
			if rdlen != 4 {
				return nil, ErrMalformed
			}
			a.Addr = netip.AddrFrom4([4]byte(b[rd : rd+4]))
		case TypeAAAA:
			if rdlen != 16 {
				return nil, ErrMalformed
			}
			a.Addr = netip.AddrFrom16([16]byte(b[rd : rd+16]))
		case TypeCNAME:
			if a.Target, _, err = readName(b, rd); err != nil {
				return nil, err
			}
		}
		m.Answers = append(m.Answers, a)
		off = rd + rdlen
	}
	return m, nil
}

// readName читает имя с учётом сжатия. Возвращает имя в нижнем регистре и позицию после него.
func readName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	next, jumps := -1, 0
	for {
		if off >= len(b) {
			return "", 0, ErrMalformed
		}
		l := int(b[off])
		switch {
		case l == 0:
			if next < 0 {
				next = off + 1
			}
			return sb.String(), next, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(b) {
				return "", 0, ErrMalformed
			}
			if next < 0 {
				next = off + 2
			}
			if jumps++; jumps > 32 {
				return "", 0, ErrMalformed
			}
			off = (l&0x3F)<<8 | int(b[off+1])
		case l&0xC0 != 0:
			return "", 0, ErrMalformed
		default:
			if off+1+l > len(b) {
				return "", 0, ErrMalformed
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			for _, c := range b[off+1 : off+1+l] {
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				sb.WriteByte(c)
			}
			if sb.Len() > 255 {
				return "", 0, ErrMalformed
			}
			off += 1 + l
		}
	}
}

// Resolve возвращает цепочку имён (запрошенное имя и его CNAME-цели по порядку),
// IPv4-адреса последнего имени цепочки и наименьший TTL среди этих адресов.
func (m *Message) Resolve() (names []string, addrs []netip.Addr, ttl uint32) {
	names = []string{m.Question}
	cur := m.Question
	for {
		next := ""
		for _, a := range m.Answers {
			if a.Type == TypeCNAME && a.Name == cur && !slices.Contains(names, a.Target) {
				next = a.Target
				break
			}
		}
		if next == "" {
			break
		}
		names = append(names, next)
		cur = next
	}
	for _, a := range m.Answers {
		if a.Type != TypeA || a.Name != cur {
			continue
		}
		if len(addrs) == 0 || a.TTL < ttl {
			ttl = a.TTL
		}
		addrs = append(addrs, a.Addr)
	}
	return names, addrs, ttl
}
