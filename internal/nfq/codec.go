// Package nfq works with the kernel packet queue (nfnetlink_queue) without third-party libraries.
package nfq

import (
	"encoding/binary"
	"errors"
)

const (
	nlHdrLen    = 16 // netlink header
	nfgenLen    = 4  // nfnetlink header
	nlMsgError  = 2
	nlFRequest  = 0x01
	nlFAck      = 0x04
	subsysQueue = 3

	msgPacket  = 0
	msgVerdict = 1
	msgConfig  = 2

	cfgCmdBind   = 1
	cfgCmdUnbind = 2

	attrCfgCmd    = 1
	attrCfgParams = 2
	attrCfgMaxLen = 3
	attrCfgMask   = 4
	attrCfgFlags  = 5

	attrPacketHdr  = 1
	attrVerdictHdr = 2
	attrPayload    = 10

	copyPacket   = 2 // copy the packet contents
	flagFailOpen = 1 // when the queue overflows, let packets through instead of dropping them

	verdictAccept = 1
	afInet        = 2
)

var errMalformed = errors.New("nfq: malformed kernel message")

// Packet is a packet awaiting a verdict. Payload starts with the IP header.
type Packet struct {
	ID      uint32
	Payload []byte
}

func align4(n int) int { return (n + 3) &^ 3 }

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func attr(typ uint16, value []byte) []byte {
	b := make([]byte, align4(4+len(value)))
	binary.LittleEndian.PutUint16(b[0:], uint16(4+len(value)))
	binary.LittleEndian.PutUint16(b[2:], typ)
	copy(b[4:], value)
	return b
}

func message(typ, flags uint16, seq uint32, queue uint16, attrs ...[]byte) []byte {
	n := nlHdrLen + nfgenLen
	for _, a := range attrs {
		n += len(a)
	}
	b := make([]byte, n)
	binary.LittleEndian.PutUint32(b[0:], uint32(n))
	binary.LittleEndian.PutUint16(b[4:], subsysQueue<<8|typ)
	binary.LittleEndian.PutUint16(b[6:], flags)
	binary.LittleEndian.PutUint32(b[8:], seq)
	binary.BigEndian.PutUint16(b[18:], queue)
	off := nlHdrLen + nfgenLen
	for _, a := range attrs {
		off += copy(b[off:], a)
	}
	return b
}

func configCmd(queue uint16, cmd byte, seq uint32) []byte {
	return message(msgConfig, nlFRequest|nlFAck, seq, queue, attr(attrCfgCmd, []byte{cmd, 0, 0, afInet}))
}

func configParams(queue uint16, mode byte, copyRange uint32, seq uint32) []byte {
	return message(msgConfig, nlFRequest|nlFAck, seq, queue, attr(attrCfgParams, append(be32(copyRange), mode)))
}

func configMaxLen(queue uint16, n uint32, seq uint32) []byte {
	return message(msgConfig, nlFRequest|nlFAck, seq, queue, attr(attrCfgMaxLen, be32(n)))
}

func configFlags(queue uint16, flags, mask uint32, seq uint32) []byte {
	return message(msgConfig, nlFRequest|nlFAck, seq, queue, attr(attrCfgFlags, be32(flags)), attr(attrCfgMask, be32(mask)))
}

func verdict(queue uint16, id uint32, v uint32) []byte {
	return message(msgVerdict, nlFRequest, 0, queue, attr(attrVerdictHdr, append(be32(v), be32(id)...)))
}

// reply is a single kernel message: a queued packet or a request acknowledgement.
type reply struct {
	packet *Packet
	ack    bool
	seq    uint32
	errno  int32 // 0 on success, otherwise the negated error code
}

// parse parses a chunk of data read from the socket: it may hold several messages.
func parse(b []byte) ([]reply, error) {
	var out []reply
	for len(b) > 0 {
		if len(b) < nlHdrLen {
			return out, errMalformed
		}
		n := int(binary.LittleEndian.Uint32(b[0:]))
		if n < nlHdrLen || n > len(b) {
			return out, errMalformed
		}
		body := b[nlHdrLen:n]
		switch binary.LittleEndian.Uint16(b[4:]) {
		case nlMsgError:
			if len(body) < 4 {
				return out, errMalformed
			}
			out = append(out, reply{ack: true, seq: binary.LittleEndian.Uint32(b[8:]), errno: int32(binary.LittleEndian.Uint32(body))})
		case subsysQueue<<8 | msgPacket:
			p, err := parsePacket(body)
			if err != nil {
				return out, err
			}
			out = append(out, reply{packet: p})
		}
		b = b[min(align4(n), len(b)):]
	}
	return out, nil
}

func parsePacket(body []byte) (*Packet, error) {
	if len(body) < nfgenLen {
		return nil, errMalformed
	}
	p, hasID := &Packet{}, false
	for a := body[nfgenLen:]; len(a) > 0; {
		if len(a) < 4 {
			return nil, errMalformed
		}
		l := int(binary.LittleEndian.Uint16(a[0:]))
		if l < 4 || l > len(a) {
			return nil, errMalformed
		}
		value := a[4:l]
		switch binary.LittleEndian.Uint16(a[2:]) & 0x3fff { // the top two bits are flags
		case attrPacketHdr:
			if len(value) < 4 {
				return nil, errMalformed
			}
			p.ID, hasID = binary.BigEndian.Uint32(value), true
		case attrPayload:
			p.Payload = value
		}
		a = a[min(align4(l), len(a)):]
	}
	if !hasID {
		return nil, errMalformed
	}
	return p, nil
}
