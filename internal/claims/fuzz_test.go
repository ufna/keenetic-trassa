package claims

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"trassa/internal/rules"
)

func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{"a":"1.1.1.1","n":["video.example"],"e":1790000000}`))
	f.Add([]byte("{\"a\":\"1.1.1.1\",\"n\":[\"VIDEO.example.\"],\"e\":9999999999}\nnot json\n"))
	cfg, ps := rules.Load("exit vpn = W\ndefault direct\nvideo.example -> vpn\n", nil)
	if rules.HasErrors(ps) {
		f.Fatal(ps)
	}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, b []byte) {
		s := New(cfg, time.Hour)
		n := s.Load(bytes.NewReader(b), now)
		if lines := strings.Count(string(b), "\n") + 1; n > lines || s.Total() != n {
			t.Fatalf("accepted %d of %d lines, total %d", n, lines, s.Total())
		}
	})
}
