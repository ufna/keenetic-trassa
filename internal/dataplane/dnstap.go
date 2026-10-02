package dataplane

import (
	"context"
	"net/netip"
	"strconv"
)

const tapChain = "TRASSA_DNS"

// maxJumps — сколько одинаковых прыжков снимается за раз: больше одного бывает только после сбоя.
const maxJumps = 4

// DNSTap — правило, направляющее DNS-ответы домашней сети в очередь trassa.
type DNSTap struct {
	LAN   string     // интерфейс домашней сети
	Queue uint16     // номер очереди
	Only  netip.Addr // если задан — наблюдать ответы только этому адресу IPv4
}

func mangle(args ...string) []string { return append([]string{"-w", "-t", "mangle"}, args...) }

func (t DNSTap) spec(only netip.Addr) []string {
	var a []string
	if only.IsValid() {
		a = append(a, "-d", only.String())
	}
	return append(a, "-o", t.LAN, "-p", "udp", "--sport", "53",
		"-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(t.Queue)), "--queue-bypass")
}

// Ensure приводит правила к нужному виду. Если всё на месте, ничего не меняет.
func (t DNSTap) Ensure(ctx context.Context, r Runner) error {
	if err := t.ensure(ctx, r, "iptables", t.Only); err != nil {
		return err
	}
	if t.Only.IsValid() {
		remove(ctx, r, "ip6tables")
		return nil
	}
	return t.ensure(ctx, r, "ip6tables", netip.Addr{})
}

func (t DNSTap) ensure(ctx context.Context, r Runner, bin string, only netip.Addr) error {
	if _, err := r.Run(ctx, bin, mangle("-S", tapChain)...); err != nil {
		if _, err := r.Run(ctx, bin, mangle("-N", tapChain)...); err != nil {
			return err
		}
	}
	spec := t.spec(only)
	if _, err := r.Run(ctx, bin, mangle(append([]string{"-C", tapChain}, spec...)...)...); err != nil {
		if _, err := r.Run(ctx, bin, mangle("-F", tapChain)...); err != nil {
			return err
		}
		if _, err := r.Run(ctx, bin, mangle(append([]string{"-A", tapChain}, spec...)...)...); err != nil {
			return err
		}
	}
	if _, err := r.Run(ctx, bin, mangle("-C", "POSTROUTING", "-j", tapChain)...); err != nil {
		// В конец цепочки: вердикт из очереди обходит правила, стоящие после нашего.
		if _, err := r.Run(ctx, bin, mangle("-A", "POSTROUTING", "-j", tapChain)...); err != nil {
			return err
		}
	}
	return nil
}

// Remove снимает правила перехвата в обеих таблицах. Отсутствие правил ошибкой не считается.
func (DNSTap) Remove(ctx context.Context, r Runner) {
	remove(ctx, r, "iptables")
	remove(ctx, r, "ip6tables")
}

func remove(ctx context.Context, r Runner, bin string) {
	for i := 0; i < maxJumps; i++ {
		if _, err := r.Run(ctx, bin, mangle("-D", "POSTROUTING", "-j", tapChain)...); err != nil {
			break
		}
	}
	r.Run(ctx, bin, mangle("-F", tapChain)...)
	r.Run(ctx, bin, mangle("-X", tapChain)...)
}
