package dataplane

import (
	"context"
	"net/netip"
	"strconv"
)

const tapChain = "TRASSA_DNS"

// maxJumps is how many identical jumps are removed at once: more than one only happens after a failure.
const maxJumps = 4

// DNSTap is the rule that sends DNS answers on the home network to the trassa queue.
type DNSTap struct {
	LAN   string     // home network interface
	Queue uint16     // queue number
	Only  netip.Addr // if set, observe answers only to this IPv4 address
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

// Ensure brings the rules to the desired state. If everything is in place, it changes nothing.
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
		// At the end of the chain: the queue verdict skips rules that come after ours.
		if _, err := r.Run(ctx, bin, mangle("-A", "POSTROUTING", "-j", tapChain)...); err != nil {
			return err
		}
	}
	return nil
}

// Remove deletes the tap rules in both tables. Missing rules are not an error.
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
