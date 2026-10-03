package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// fakeRunner records commands. A command whose line contains one of the fail keys fails.
type fakeRunner struct {
	calls []string
	fail  []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	for _, k := range f.fail {
		if strings.Contains(line, k) {
			return "", errors.New("no such rule")
		}
	}
	return "", nil
}

func (f *fakeRunner) changed() []string {
	var out []string
	for _, c := range f.calls {
		if !strings.Contains(c, " -S ") && !strings.Contains(c, " -C ") {
			out = append(out, c)
		}
	}
	return out
}

func equal(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

const rule = "-o br0 -p udp --sport 53 -j NFQUEUE --queue-num 5353 --queue-bypass"

var tap = DNSTap{LAN: "br0", Queue: 5353}

func TestEnsureFromScratch(t *testing.T) {
	r := &fakeRunner{fail: []string{" -S ", " -C "}}
	if err := tap.Ensure(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	equal(t, r.changed(), []string{
		"iptables -w -t mangle -N TRASSA_DNS",
		"iptables -w -t mangle -F TRASSA_DNS",
		"iptables -w -t mangle -A TRASSA_DNS " + rule,
		"iptables -w -t mangle -A POSTROUTING -j TRASSA_DNS",
		"ip6tables -w -t mangle -N TRASSA_DNS",
		"ip6tables -w -t mangle -F TRASSA_DNS",
		"ip6tables -w -t mangle -A TRASSA_DNS " + rule,
		"ip6tables -w -t mangle -A POSTROUTING -j TRASSA_DNS",
	})
}

func TestEnsureIsIdempotent(t *testing.T) {
	r := &fakeRunner{}
	if err := tap.Ensure(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	equal(t, r.changed(), nil)
}

func TestEnsureRestoresMissingJump(t *testing.T) {
	// The firmware rewrote the table: the chain and its rule are intact, the jump is gone.
	r := &fakeRunner{fail: []string{"-C POSTROUTING"}}
	if err := tap.Ensure(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	equal(t, r.changed(), []string{
		"iptables -w -t mangle -A POSTROUTING -j TRASSA_DNS",
		"ip6tables -w -t mangle -A POSTROUTING -j TRASSA_DNS",
	})
}

func TestEnsureRewritesChangedRule(t *testing.T) {
	// The chain exists, but its rule differs (the observed device address changed).
	r := &fakeRunner{fail: []string{"-C TRASSA_DNS"}}
	only := DNSTap{LAN: "br0", Queue: 5353, Only: netip.MustParseAddr("192.168.1.94")}
	if err := only.Ensure(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	equal(t, r.changed(), []string{
		"iptables -w -t mangle -F TRASSA_DNS",
		"iptables -w -t mangle -A TRASSA_DNS -d 192.168.1.94 " + rule,
		// A single device is observed over IPv4: the IPv6 rules are removed.
		"ip6tables -w -t mangle -D POSTROUTING -j TRASSA_DNS",
		"ip6tables -w -t mangle -D POSTROUTING -j TRASSA_DNS",
		"ip6tables -w -t mangle -D POSTROUTING -j TRASSA_DNS",
		"ip6tables -w -t mangle -D POSTROUTING -j TRASSA_DNS",
		"ip6tables -w -t mangle -F TRASSA_DNS",
		"ip6tables -w -t mangle -X TRASSA_DNS",
	})
}

func TestEnsureReportsFailure(t *testing.T) {
	r := &fakeRunner{fail: []string{" -S ", " -N "}}
	if err := tap.Ensure(context.Background(), r); err == nil {
		t.Error("failing to create the chain must be an error")
	}
}

func TestRemove(t *testing.T) {
	// The jump is present once: the second delete attempt fails and the loop stops.
	r := &countingRunner{deletesLeft: map[string]int{"iptables": 1, "ip6tables": 0}}
	tap.Remove(context.Background(), r)
	equal(t, r.calls, []string{
		"iptables -w -t mangle -D POSTROUTING -j TRASSA_DNS",
		"iptables -w -t mangle -D POSTROUTING -j TRASSA_DNS",
		"iptables -w -t mangle -F TRASSA_DNS",
		"iptables -w -t mangle -X TRASSA_DNS",
		"ip6tables -w -t mangle -D POSTROUTING -j TRASSA_DNS",
		"ip6tables -w -t mangle -F TRASSA_DNS",
		"ip6tables -w -t mangle -X TRASSA_DNS",
	})
}

// countingRunner allows deleting the jump a given number of times, after which -D fails.
type countingRunner struct {
	calls       []string
	deletesLeft map[string]int
}

func (c *countingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	c.calls = append(c.calls, name+" "+strings.Join(args, " "))
	if len(args) > 3 && args[3] == "-D" {
		if c.deletesLeft[name] == 0 {
			return "", errors.New("no such rule")
		}
		c.deletesLeft[name]--
	}
	return "", nil
}
