package ippkt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func udp(sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	copy(b[8:], payload)
	return b
}

// v4 собирает пакет IPv4 с заголовком длиной ihl 32-битных слов.
func v4(src, dst string, proto byte, ihl int, body []byte) []byte {
	b := make([]byte, ihl*4+len(body))
	b[0] = 0x40 | byte(ihl)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8], b[9] = 64, proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	copy(b[ihl*4:], body)
	return b
}

func v6(src, dst string, next byte, body []byte) []byte {
	b := make([]byte, 40+len(body))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(body)))
	b[6], b[7] = next, 64
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	copy(b[40:], body)
	return b
}

func TestParseUDPv4(t *testing.T) {
	for _, ihl := range []int{5, 6, 15} {
		u, err := ParseUDP(v4("192.168.1.1", "192.168.1.94", 17, ihl, udp(53, 40000, []byte("dns"))))
		if err != nil {
			t.Fatalf("ihl %d: %v", ihl, err)
		}
		if u.Src != netip.MustParseAddr("192.168.1.1") || u.Dst != netip.MustParseAddr("192.168.1.94") ||
			u.SrcPort != 53 || u.DstPort != 40000 || !bytes.Equal(u.Payload, []byte("dns")) {
			t.Errorf("ihl %d: %+v", ihl, u)
		}
	}
}

func TestParseUDPv6(t *testing.T) {
	u, err := ParseUDP(v6("fdbd:8531:7fce::1", "fdbd:8531:7fce::94", 17, udp(53, 40000, []byte("dns"))))
	if err != nil {
		t.Fatal(err)
	}
	if u.Src != netip.MustParseAddr("fdbd:8531:7fce::1") || u.Dst != netip.MustParseAddr("fdbd:8531:7fce::94") ||
		u.SrcPort != 53 || !bytes.Equal(u.Payload, []byte("dns")) {
		t.Errorf("%+v", u)
	}
}

func TestParseUDPIgnoresTrailingBytes(t *testing.T) {
	pkt := append(v4("1.1.1.1", "2.2.2.2", 17, 5, udp(53, 1, []byte("abc"))), 0xEE, 0xEE)
	u, err := ParseUDP(pkt)
	if err != nil || !bytes.Equal(u.Payload, []byte("abc")) {
		t.Errorf("хвост после пакета: %+v, %v", u, err)
	}
}

func TestParseUDPRejects(t *testing.T) {
	good := v4("1.1.1.1", "2.2.2.2", 17, 5, udp(53, 1, []byte("abc")))
	frag := append([]byte{}, good...)
	binary.BigEndian.PutUint16(frag[6:], 0x2000) // есть продолжение
	frag2 := append([]byte{}, good...)
	binary.BigEndian.PutUint16(frag2[6:], 0x0010) // не первый фрагмент
	badUDPLen := append([]byte{}, good...)
	binary.BigEndian.PutUint16(badUDPLen[24:], 200)
	badTotal := append([]byte{}, good...)
	binary.BigEndian.PutUint16(badTotal[2:], 500)
	lowIHL := append([]byte{}, good...)
	lowIHL[0] = 0x44

	cases := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"пусто", nil, ErrTruncated},
		{"короче заголовка", good[:19], ErrTruncated},
		{"TCP", v4("1.1.1.1", "2.2.2.2", 6, 5, udp(53, 1, nil)), ErrNotUDP},
		{"не IP", []byte{0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}, ErrNotUDP},
		{"фрагмент с продолжением", frag, ErrFragment},
		{"не первый фрагмент", frag2, ErrFragment},
		{"длина UDP больше пакета", badUDPLen, ErrTruncated},
		{"общая длина больше пакета", badTotal, ErrTruncated},
		{"заголовок короче 20 байт", lowIHL, ErrTruncated},
		{"обрезан заголовок UDP", good[:24], ErrTruncated},
		{"IPv6 короче заголовка", v6("::1", "::2", 17, udp(53, 1, nil))[:39], ErrTruncated},
		{"IPv6 не UDP", v6("::1", "::2", 6, udp(53, 1, nil)), ErrNotUDP},
		{"IPv6 длина больше пакета", v6("::1", "::2", 17, udp(53, 1, []byte("abc")))[:45], ErrTruncated},
	}
	for _, c := range cases {
		if _, err := ParseUDP(c.pkt); !errors.Is(err, c.want) {
			t.Errorf("%s: ошибка %v, ожидалась %v", c.name, err, c.want)
		}
	}
}

func TestParseUDPNeverPanics(t *testing.T) {
	for _, base := range [][]byte{
		v4("1.1.1.1", "2.2.2.2", 17, 6, udp(53, 1, []byte("abcdef"))),
		v6("::1", "::2", 17, udp(53, 1, []byte("abcdef"))),
	} {
		for i := 0; i <= len(base); i++ {
			ParseUDP(base[:i])
		}
	}
}
