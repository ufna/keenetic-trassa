// Package dnsmsg parses DNS responses: the question and A, AAAA, CNAME, SVCB and HTTPS records.
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
	TypeSVCB  uint16 = 64
	TypeHTTPS uint16 = 65
)

var ErrMalformed = errors.New("malformed DNS message")

type Answer struct {
	Name   string
	Type   uint16
	TTL    uint32
	Addr   netip.Addr   // for A and AAAA
	Target string       // for CNAME
	Hints  []netip.Addr // ipv4hint of SVCB and HTTPS
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

// Parse parses a DNS message (a UDP payload). Sections after the answers are not read.
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
		case TypeSVCB, TypeHTTPS:
			a.Hints = parseHints(b, rd, rd+rdlen)
		}
		m.Answers = append(m.Answers, a)
		off = rd + rdlen
	}
	return m, nil
}

// parseHints reads the ipv4hint parameter of an SVCB or HTTPS record (RFC 9460): addresses a
// client may connect to for the owner name without asking for A records. A malformed record
// yields no hints and does not spoil the rest of the answer.
func parseHints(b []byte, start, end int) []netip.Addr {
	if end-start < 3 {
		return nil
	}
	_, off, err := readName(b, start+2) // target name
	if err != nil || off > end {
		return nil
	}
	var hints []netip.Addr
	for off < end {
		if off+4 > end {
			return nil
		}
		key, l := binary.BigEndian.Uint16(b[off:]), int(binary.BigEndian.Uint16(b[off+2:]))
		off += 4
		if off+l > end {
			return nil
		}
		if key == 4 {
			if l%4 != 0 {
				return nil
			}
			for i := off; i < off+l; i += 4 {
				hints = append(hints, netip.AddrFrom4([4]byte(b[i:i+4])))
			}
		}
		off += l
	}
	return hints
}

// readName reads a name, following compression. It returns the lowercased name and the offset after it.
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

// Resolve returns the name chain (the queried name and its CNAME targets in order), the IPv4
// addresses of the last name in the chain together with the ipv4hint addresses of SVCB and HTTPS
// records of any name in the chain, and the smallest TTL among the records they came from.
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
	for _, a := range m.Answers {
		if (a.Type != TypeHTTPS && a.Type != TypeSVCB) || len(a.Hints) == 0 || !slices.Contains(names, a.Name) {
			continue
		}
		if len(addrs) == 0 || a.TTL < ttl {
			ttl = a.TTL
		}
		for _, h := range a.Hints {
			if !slices.Contains(addrs, h) {
				addrs = append(addrs, h)
			}
		}
	}
	return names, addrs, ttl
}
