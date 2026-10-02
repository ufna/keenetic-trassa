package nfq

import (
	"os"
	"testing"
	"time"
)

// TestLiveFailOpen проверяет на настоящем ядре, что переполненная очередь пропускает пакеты,
// а не теряет их. Запускается вручную на роутере от имени root: очередь 5354 открывается
// с длиной 8 и двенадцать секунд не читается. Пакеты в неё направляет отдельное правило,
// которое ставит и снимает тот, кто проводит проверку (см. docs/observe-rollout-2026-10.md).
func TestLiveFailOpen(t *testing.T) {
	if os.Getenv("TRASSA_NFQ_LIVE") == "" {
		t.Skip("проверка на живом ядре: только на роутере, с TRASSA_NFQ_LIVE=1")
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
	t.Log("очередь 5354 открыта, длина 8; двенадцать секунд пакеты не читаются")
	time.Sleep(12 * time.Second)
	stats, _ := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	t.Logf("очереди ядра (номер, получатель, ждут, режим, копия, потеряно, потеряно при передаче, всего, …):\n%s", stats)
}
