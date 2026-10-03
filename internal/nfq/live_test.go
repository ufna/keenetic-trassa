package nfq

import (
	"os"
	"testing"
	"time"
)

// TestLiveFailOpen checks on a real kernel that an overflowing queue lets packets through
// instead of dropping them. It is run by hand on the router as root: queue 5354 is opened
// with length 8 and not read for twelve seconds. Packets are steered into it by a separate rule
// that whoever runs the check adds and removes (see docs/observe-rollout-2026-10.md).
func TestLiveFailOpen(t *testing.T) {
	if os.Getenv("TRASSA_NFQ_LIVE") == "" {
		t.Skip("live kernel check: only on the router, with TRASSA_NFQ_LIVE=1")
	}
	const num = 5354
	q, err := Open(num)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.request(func(s uint32) []byte { return configMaxLen(num, 8, s) }); err != nil {
		t.Fatal(err)
	}
	t.Log("queue 5354 open, length 8; not reading packets for twelve seconds")
	time.Sleep(12 * time.Second)
	stats, _ := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	t.Logf("kernel queues (number, peer, waiting, mode, copy range, dropped, user dropped, total, …):\n%s", stats)
}
