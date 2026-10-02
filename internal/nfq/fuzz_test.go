package nfq

import "testing"

func FuzzParse(f *testing.F) {
	f.Add(kernelPacket(42, []byte("hello")))
	f.Add(append(kernelPacket(1, []byte("a")), kernelPacket(2, []byte("bcd"))...))
	f.Add(configCmd(5353, cfgCmdBind, 1))
	f.Fuzz(func(t *testing.T, b []byte) {
		rs, _ := parse(b)
		for _, r := range rs {
			if r.packet != nil && len(r.packet.Payload) > len(b) {
				t.Fatalf("полезная нагрузка длиннее входа: %d > %d", len(r.packet.Payload), len(b))
			}
		}
	})
}
