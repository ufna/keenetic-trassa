package dnsmsg

import (
	"encoding/hex"
	"testing"
)

func FuzzParse(f *testing.F) {
	seed, _ := hex.DecodeString(examplePacket)
	f.Add(seed)
	f.Add(build("www.youtube.com", TypeA, 0x8180,
		rr{"www.youtube.com", TypeCNAME, 60, wireName("youtube-ui.l.google.com")},
		rr{"youtube-ui.l.google.com", TypeA, 60, []byte{1, 2, 3, 4}}))
	f.Add([]byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil {
			return
		}
		names, addrs, _ := m.Resolve()
		if len(names) == 0 || len(names) > len(m.Answers)+1 || len(addrs) > len(m.Answers) {
			t.Fatalf("Resolve вернул невозможное: имён %d, адресов %d, записей %d", len(names), len(addrs), len(m.Answers))
		}
	})
}
