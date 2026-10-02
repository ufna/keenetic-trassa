package ippkt

import "testing"

func FuzzParseUDP(f *testing.F) {
	f.Add(v4("192.168.1.1", "192.168.1.94", 17, 5, udp(53, 40000, []byte("dns"))))
	f.Add(v6("fdbd::1", "fdbd::94", 17, udp(53, 40000, []byte("dns"))))
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := ParseUDP(b)
		if err == nil && len(u.Payload) > len(b) {
			t.Fatalf("полезная нагрузка длиннее пакета: %d > %d", len(u.Payload), len(b))
		}
	})
}
