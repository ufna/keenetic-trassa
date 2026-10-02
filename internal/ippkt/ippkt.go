// Package ippkt достаёт полезную нагрузку UDP из пакета IPv4 или IPv6.
package ippkt

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var (
	ErrNotUDP    = errors.New("не UDP поверх IP")
	ErrFragment  = errors.New("фрагмент IP-пакета")
	ErrTruncated = errors.New("обрезанный пакет")
)

const protoUDP = 17

type UDP struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Payload          []byte // ссылается на исходный буфер
}

// ParseUDP разбирает пакет, начинающийся с заголовка IP. Заголовки расширения IPv6 не поддерживаются.
func ParseUDP(b []byte) (UDP, error) {
	if len(b) < 20 {
		return UDP{}, ErrTruncated
	}
	var u UDP
	var seg []byte
	switch b[0] >> 4 {
	case 4:
		if b[9] != protoUDP {
			return UDP{}, ErrNotUDP
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:]))
		if ihl < 20 || total < ihl || total > len(b) {
			return UDP{}, ErrTruncated
		}
		// Бит «есть продолжение» или ненулевое смещение: это фрагмент, UDP-заголовка в нём может не быть.
		if binary.BigEndian.Uint16(b[6:])&0x3fff != 0 {
			return UDP{}, ErrFragment
		}
		u.Src, u.Dst = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		seg = b[ihl:total]
	case 6:
		if len(b) < 40 {
			return UDP{}, ErrTruncated
		}
		if b[6] != protoUDP {
			return UDP{}, ErrNotUDP
		}
		plen := int(binary.BigEndian.Uint16(b[4:]))
		if 40+plen > len(b) {
			return UDP{}, ErrTruncated
		}
		u.Src, u.Dst = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
		seg = b[40 : 40+plen]
	default:
		return UDP{}, ErrNotUDP
	}
	if len(seg) < 8 {
		return UDP{}, ErrTruncated
	}
	ulen := int(binary.BigEndian.Uint16(seg[4:]))
	if ulen < 8 || ulen > len(seg) {
		return UDP{}, ErrTruncated
	}
	u.SrcPort, u.DstPort = binary.BigEndian.Uint16(seg[0:]), binary.BigEndian.Uint16(seg[2:])
	u.Payload = seg[8:ulen]
	return u, nil
}
