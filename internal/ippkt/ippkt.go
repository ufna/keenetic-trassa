// Package ippkt extracts the UDP payload from an IPv4 or IPv6 packet.
package ippkt

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var (
	ErrNotUDP    = errors.New("not UDP over IP")
	ErrFragment  = errors.New("IP packet fragment")
	ErrTruncated = errors.New("truncated packet")
)

const protoUDP = 17

type UDP struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Payload          []byte // points into the original buffer
}

// ParseUDP parses a packet that starts with an IP header. IPv6 extension headers are not supported.
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
		// The "more fragments" bit or a non-zero offset: this is a fragment and may lack the UDP header.
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
