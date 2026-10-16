package engine

import (
	"testing"
	"time"

	"github.com/ufna/keenetic-trassa/internal/rules"
)

func FuzzHandlePacket(f *testing.F) {
	f.Add(answer("video.example", "1.1.1.1", "2.2.2.2"))
	f.Add(ipv6(53, dns("yandex.ru", 0x8180, a("yandex.ru", 60, "5.5.5.5"))))
	f.Add([]byte("not a packet"))
	cfg, ps := rules.Load(src, nil)
	if rules.HasErrors(ps) {
		f.Fatalf("rules: %v", ps)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		e := New(cfg, &fakeSink{}, func(string, ...any) {}, t0)
		e.HandlePacket(t0, b)
		e.Tick(t0.Add(25 * time.Hour))
		if s := e.Stats(); s.Packets != 1 {
			t.Fatalf("packet not counted: %+v", s)
		}
		_ = e.Status(t0)
	})
}
