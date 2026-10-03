package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"trassa/internal/claims"
	"trassa/internal/rules"
)

// scripted records commands along with their input and answers from a script.
type scripted struct {
	calls []string
	out   map[string]string // command line prefix → its output
	fail  []string          // a command containing a key fails
}

func (s *scripted) RunInput(_ context.Context, stdin, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	if stdin != "" {
		line += " <<\n" + stdin
	}
	s.calls = append(s.calls, line)
	for _, k := range s.fail {
		if strings.Contains(line, k) {
			return "", errors.New("utility failure")
		}
	}
	for k, v := range s.out {
		if strings.HasPrefix(line, k) {
			return v, nil
		}
	}
	return "", nil
}

func (s *scripted) Run(ctx context.Context, name string, args ...string) (string, error) {
	return s.RunInput(ctx, "", name, args...)
}

// changed returns the commands that change something (no state reads).
func (s *scripted) changed() []string {
	var out []string
	for _, c := range s.calls {
		if strings.HasPrefix(c, "ip rule list") || strings.HasPrefix(c, "ipset list") || strings.Contains(c, " -S ") || strings.Contains(c, " -C ") {
			continue
		}
		out = append(out, c)
	}
	return out
}

func cfgOf(t *testing.T, s string) *rules.Config {
	t.Helper()
	cfg, ps := rules.Load(s, nil)
	if rules.HasErrors(ps) {
		t.Fatalf("rules: %v", ps)
	}
	return cfg
}

const twoExits = `exit vpn = W
exit alt = W
default direct
x.com -> vpn
1.2.3.0/24 9.9.9.9 -> vpn strict
y.com -> alt
10.0.0.0/8 -> direct
`

const oneExit = "exit vpn = W\ndefault direct\nx.com -> vpn\n"

// marksOf returns the slot marks of a layout: expectations must not depend on the generation.
func marksOf(t *testing.T, src string) []string {
	t.Helper()
	l, err := NewLayout(cfgOf(t, src))
	if err != nil {
		t.Fatal(err)
	}
	var m []string
	for _, s := range l.Slots {
		m = append(m, s.Mark())
	}
	return m
}

func vpn(strict bool) rules.Action { return rules.Action{Exit: "vpn", Strict: strict} }

func TestRebuildFromScratch(t *testing.T) {
	run := &scripted{fail: []string{" -C "}}
	r := NewRouter(run, "br0", netip.MustParseAddr("192.168.1.94"))
	if err := r.SetExits(map[string]string{"vpn": "nwg2", "alt": ""}); err != nil {
		t.Fatal(err)
	}
	entries := []claims.Entry{
		{Addr: netip.MustParseAddr("5.5.5.5"), Action: vpn(false)},
		{Addr: netip.MustParseAddr("6.6.6.6"), Action: rules.Action{Exit: "direct"}},
	}
	if err := r.Rebuild(cfgOf(t, twoExits), entries); err != nil {
		t.Fatal(err)
	}
	m := marksOf(t, twoExits)
	equal(t, run.changed(), []string{
		"ipset restore <<\n" +
			"create trassa_d0 hash:ip -exist\nflush trassa_d0\n" +
			"create trassa_d1 hash:ip -exist\nflush trassa_d1\n" +
			"create trassa_d2 hash:ip -exist\nflush trassa_d2\n" +
			"create trassa_d3 hash:ip -exist\nflush trassa_d3\n" +
			"create trassa_d4 hash:ip -exist\nflush trassa_d4\n" +
			"create trassa_s1 hash:net -exist\nflush trassa_s1\nadd trassa_s1 1.2.3.0/24 -exist\nadd trassa_s1 9.9.9.9/32 -exist\n" +
			"create trassa_s3 hash:net -exist\nflush trassa_s3\nadd trassa_s3 10.0.0.0/8 -exist\n" +
			"add trassa_d1 5.5.5.5 -exist\nadd trassa_d0 6.6.6.6 -exist\n",
		"iptables-restore -n <<\n" +
			"*mangle\n:TRASSA - [0:0]\n" +
			"-A TRASSA -m mark ! --mark 0x0 -j RETURN\n" +
			"-A TRASSA -m connmark --mark 0x54520000/0xffff0000 -j CONNMARK --restore-mark\n" +
			"-A TRASSA -m mark ! --mark 0x0 -j RETURN\n" +
			"-A TRASSA -m mark --mark 0x0 -m conntrack --ctstate NEW -m set --match-set trassa_d0 dst -j MARK --set-mark 0x54520000\n" +
			"-A TRASSA -m mark --mark 0x0 -m conntrack --ctstate NEW -m set --match-set trassa_d1 dst -j MARK --set-mark " + m[1] + "\n" +
			"-A TRASSA -m mark --mark 0x0 -m conntrack --ctstate NEW -m set --match-set trassa_d2 dst -j MARK --set-mark " + m[2] + "\n" +
			"-A TRASSA -m mark --mark 0x0 -m conntrack --ctstate NEW -m set --match-set trassa_d3 dst -j MARK --set-mark " + m[3] + "\n" +
			"-A TRASSA -m mark --mark 0x0 -m conntrack --ctstate NEW -m set --match-set trassa_d4 dst -j MARK --set-mark " + m[4] + "\n" +
			"-A TRASSA -m mark --mark 0x0 -m conntrack --ctstate NEW -m set --match-set trassa_s1 dst -j MARK --set-mark " + m[2] + "\n" +
			"-A TRASSA -m mark --mark 0x0 -m conntrack --ctstate NEW -m set --match-set trassa_s3 dst -j MARK --set-mark 0x54520000\n" +
			"-A TRASSA -m mark --mark 0x54520000/0xffff0000 -j CONNMARK --save-mark\n" +
			"COMMIT\n",
		"ip rule add fwmark 0x54520000/0xffffffff lookup main pref 199",
		"ip rule add fwmark " + m[1] + "/0xffffffff lookup 541 pref 201",
		"ip rule add fwmark " + m[2] + "/0xffffffff lookup 542 pref 202",
		"ip rule add fwmark " + m[3] + "/0xffffffff lookup 543 pref 203",
		"ip rule add fwmark " + m[4] + "/0xffffffff lookup 544 pref 204",
		"ip rule add fwmark 0x54520000/0xffff0000 lookup 599 pref 299",
		"ip route replace blackhole default table 599",
		"ip route replace default dev nwg2 table 541",
		"ip route replace blackhole default table 542 metric 1000",
		"ip route replace default dev nwg2 table 542",
		"ip route flush table 543",
		"ip route replace blackhole default table 544 metric 1000",
		"ip route replace blackhole default table 544",
		// The jump comes last: marks start being set once the rules and routes exist.
		"iptables -w -t mangle -A PREROUTING -s 192.168.1.94 -i br0 -j TRASSA",
	})
}

func TestRebuildIsIdempotent(t *testing.T) {
	m := marksOf(t, oneExit)
	run := &scripted{out: map[string]string{
		"ip rule list": "0:\tfrom all lookup local \n199:\tfrom all fwmark 0x54520000 lookup main \n201:\tfrom all fwmark " + m[1] +
			" lookup 541 \n202:\tfrom all fwmark " + m[2] + " lookup 542 \n299:\tfrom all fwmark 0x54520000/0xffff0000 lookup 599 \n32766:\tfrom all lookup main \n",
		"iptables -w -t mangle -S PREROUTING": "-P PREROUTING ACCEPT\n-A PREROUTING -j _NDM_VPN_PREROUTING\n-A PREROUTING -i br0 -j TRASSA\n",
		"ipset list -n":                       "_NDM_OGDN_4@default:do-1\ntrassa_d0\ntrassa_d1\ntrassa_d2\n",
	}}
	r := NewRouter(run, "br0", netip.Addr{})
	r.SetExits(map[string]string{"vpn": "nwg2"})
	if err := r.Rebuild(cfgOf(t, "exit vpn = W\ndefault direct\nx.com -> vpn\n"), nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range run.changed() {
		if strings.Contains(c, "ip rule add") || strings.Contains(c, "PREROUTING") || strings.Contains(c, "destroy") {
			t.Errorf("unexpected command on rebuild: %s", c)
		}
	}
}

func TestDefaultThroughTunnelSkipsLocalNetworks(t *testing.T) {
	run := &scripted{}
	r := NewRouter(run, "br0", netip.Addr{})
	if err := r.Rebuild(cfgOf(t, "exit vpn = W\ndefault vpn\nru -> direct\n"), nil); err != nil {
		t.Fatal(err)
	}
	script := ""
	for _, c := range run.calls {
		if strings.HasPrefix(c, "iptables-restore") {
			script = c
		}
	}
	tail := script[strings.Index(script, "trassa_d2 dst"):]
	want := "-A TRASSA -m mark --mark 0x0 -d 0.0.0.0/8 -j RETURN\n" +
		"-A TRASSA -m mark --mark 0x0 -d 10.0.0.0/8 -j RETURN\n" +
		"-A TRASSA -m mark --mark 0x0 -d 100.64.0.0/10 -j RETURN\n" +
		"-A TRASSA -m mark --mark 0x0 -d 127.0.0.0/8 -j RETURN\n" +
		"-A TRASSA -m mark --mark 0x0 -d 169.254.0.0/16 -j RETURN\n" +
		"-A TRASSA -m mark --mark 0x0 -d 172.16.0.0/12 -j RETURN\n" +
		"-A TRASSA -m mark --mark 0x0 -d 192.168.0.0/16 -j RETURN\n" +
		"-A TRASSA -m mark --mark 0x0 -d 224.0.0.0/3 -j RETURN\n" +
		"-A TRASSA -m mark --mark 0x0 -m conntrack --ctstate NEW -j MARK --set-mark " + marksOf(t, "exit vpn = W\ndefault vpn\n")[1] + "\n" +
		"-A TRASSA -m mark --mark 0x54520000/0xffff0000 -j CONNMARK --save-mark\nCOMMIT\n"
	if !strings.HasSuffix(tail, want) {
		t.Errorf("chain tail:\n%s\nwant ending:\n%s", tail, want)
	}
}

func TestRebuildAfterExitsChange(t *testing.T) {
	// The previous layout left sets, a rule and a jump with a different source.
	m := marksOf(t, oneExit)
	run := &scripted{out: map[string]string{
		"ip rule list":                        "201:\tfrom all fwmark " + m[1] + " lookup 541 \n205:\tfrom all fwmark 0x54520005 lookup 545 \n1150:\tfrom all fwmark 0xffffaaa lookup 4096 \n",
		"iptables -w -t mangle -S PREROUTING": "-A PREROUTING -s 192.168.1.50/32 -i br0 -j TRASSA\n-A PREROUTING -i br0 -j TRASSA\n",
		"ipset list -n":                       "trassa_d0\ntrassa_d1\ntrassa_d2\ntrassa_d5\ntrassa_s7\n_NDM_X\n",
	}}
	r := NewRouter(run, "br0", netip.Addr{})
	r.SetExits(map[string]string{"vpn": "nwg2"})
	if err := r.Rebuild(cfgOf(t, "exit vpn = W\ndefault direct\nx.com -> vpn\n"), nil); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(run.changed(), "\n")
	for _, want := range []string{
		"iptables -w -t mangle -D PREROUTING -s 192.168.1.50/32 -i br0 -j TRASSA",
		"ip rule del pref 205",
		"ip route flush table 545",
		"ipset destroy trassa_d5",
		"ipset destroy trassa_s7",
		"ip rule add fwmark " + m[2] + "/0xffffffff lookup 542 pref 202",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no command %q in\n%s", want, got)
		}
	}
	for _, bad := range []string{"-A PREROUTING", "pref 1150", "_NDM_X", "destroy trassa_d1", "pref 201\n"} {
		if strings.Contains(got, bad) {
			t.Errorf("unexpected command with %q in\n%s", bad, got)
		}
	}
	// Stale objects are removed after the chain stops referencing them.
	if strings.Index(got, "ipset destroy") < strings.Index(got, "iptables-restore") {
		t.Error("sets are removed before the chain is replaced")
	}
}

func TestApply(t *testing.T) {
	run := &scripted{}
	r := NewRouter(run, "br0", netip.Addr{})
	if err := r.Apply([]claims.Change{{Addr: netip.MustParseAddr("1.1.1.1")}}); err == nil {
		t.Error("a change before the sets are built must be an error")
	}
	r.Rebuild(cfgOf(t, twoExits), nil)
	run.calls = nil
	direct, strict, alt := rules.Action{Exit: "direct"}, vpn(true), rules.Action{Exit: "alt"}
	err := r.Apply([]claims.Change{
		{Addr: netip.MustParseAddr("1.1.1.1"), New: &strict},
		{Addr: netip.MustParseAddr("2.2.2.2"), Old: &strict, New: &alt},
		{Addr: netip.MustParseAddr("3.3.3.3"), Old: &direct},
	})
	if err != nil {
		t.Fatal(err)
	}
	equal(t, run.calls, []string{"ipset restore <<\n" +
		"add trassa_d2 1.1.1.1 -exist\n" +
		"del trassa_d2 2.2.2.2 -exist\nadd trassa_d3 2.2.2.2 -exist\n" +
		"del trassa_d0 3.3.3.3 -exist\n"})
}

func TestApplyFailureIsReported(t *testing.T) {
	run := &scripted{}
	r := NewRouter(run, "br0", netip.Addr{})
	r.Rebuild(cfgOf(t, twoExits), nil)
	run.fail = []string{"ipset restore"}
	a := vpn(false)
	if err := r.Apply([]claims.Change{{Addr: netip.MustParseAddr("1.1.1.1"), New: &a}}); err == nil {
		t.Error("a utility failure must be returned as an error")
	}
}

func TestRoutesFollowExits(t *testing.T) {
	run := &scripted{}
	r := NewRouter(run, "br0", netip.Addr{})
	r.SetExits(map[string]string{"vpn": "nwg2"})
	r.Rebuild(cfgOf(t, "exit vpn = W\ndefault direct\nx.com -> vpn\n"), nil)

	run.calls = nil
	r.SetExits(map[string]string{"vpn": ""}) // all tunnels are down
	equal(t, run.calls, []string{
		"ip route replace blackhole default table 599",
		"ip route flush table 541",
		"ip route replace blackhole default table 542 metric 1000",
		"ip route replace blackhole default table 542",
	})

	run.calls = nil
	r.SetExits(map[string]string{"vpn": "nwg0"}) // the backup came up
	equal(t, run.calls, []string{
		"ip route replace blackhole default table 599",
		"ip route replace default dev nwg0 table 541",
		"ip route replace blackhole default table 542 metric 1000",
		"ip route replace default dev nwg0 table 542",
	})
}

func TestCheckDetectsMissingJump(t *testing.T) {
	run := &scripted{}
	r := NewRouter(run, "br0", netip.MustParseAddr("192.168.1.94"))
	if err := r.Reconcile(context.Background()); !errors.Is(err, ErrMissing) {
		t.Errorf("nothing to reconcile before the build: %v", err)
	}
	r.SetExits(map[string]string{"vpn": "nwg2"})
	r.Rebuild(cfgOf(t, "exit vpn = W\ndefault direct\nx.com -> vpn\n"), nil)
	run.calls = nil
	if err := r.Reconcile(context.Background()); err != nil {
		t.Errorf("the jump is in place, but Reconcile returned %v", err)
	}
	// Reconcile reapplies rules and routes: the kernel removes a route when its interface goes down.
	m := marksOf(t, oneExit)
	equal(t, run.changed(), []string{
		"ip rule add fwmark 0x54520000/0xffffffff lookup main pref 199",
		"ip rule add fwmark " + m[1] + "/0xffffffff lookup 541 pref 201",
		"ip rule add fwmark " + m[2] + "/0xffffffff lookup 542 pref 202",
		"ip rule add fwmark 0x54520000/0xffff0000 lookup 599 pref 299",
		"ip route replace blackhole default table 599",
		"ip route replace default dev nwg2 table 541",
		"ip route replace blackhole default table 542 metric 1000",
		"ip route replace default dev nwg2 table 542",
	})
	run.fail = []string{" -C "}
	if err := r.Reconcile(context.Background()); !errors.Is(err, ErrMissing) {
		t.Errorf("missing jump not detected: %v", err)
	}
}

func TestTeardown(t *testing.T) {
	run := &scripted{out: map[string]string{
		"ip rule list":                        "0:\tfrom all lookup local \n201:\tfrom all fwmark 0x54520001 lookup 541 \n202:\tfrom all fwmark 0x54520002 lookup 542 \n1150:\tfrom all fwmark 0xffffaaa lookup 4096 \n",
		"iptables -w -t mangle -S PREROUTING": "-A PREROUTING -j _NDM_VPN_PREROUTING\n-A PREROUTING -s 192.168.1.94/32 -i br0 -j TRASSA\n",
		"ipset list -n":                       "_NDM_X\ntrassa_d0\ntrassa_s3\n",
	}}
	Teardown(context.Background(), run)
	equal(t, run.changed(), []string{
		"iptables -w -t mangle -D PREROUTING -s 192.168.1.94/32 -i br0 -j TRASSA",
		"iptables -w -t mangle -F TRASSA",
		"iptables -w -t mangle -X TRASSA",
		"ip rule del pref 201 fwmark 0x54520001 lookup 541",
		"ip route flush table 541",
		"ip rule del pref 202 fwmark 0x54520002 lookup 542",
		"ip route flush table 542",
		"ipset destroy trassa_d0",
		"ipset destroy trassa_s3",
	})
}

func TestFailedRebuildLeavesNoStaleLayout(t *testing.T) {
	run := &scripted{}
	r := NewRouter(run, "br0", netip.Addr{})
	if err := r.Rebuild(cfgOf(t, "exit vpn = W\ndefault direct\nx.com -> vpn\n"), nil); err != nil {
		t.Fatal(err)
	}
	// New rules with a different set of exits; replacing the chain failed.
	run.fail = []string{"iptables-restore"}
	if err := r.Rebuild(cfgOf(t, twoExits), nil); err == nil {
		t.Fatal("an iptables-restore failure must be returned as an error")
	}
	// The previous layout is no longer valid: with it an address would land in another exit's set.
	alt := rules.Action{Exit: "alt", Strict: true}
	if err := r.Apply([]claims.Change{{Addr: netip.MustParseAddr("1.1.1.1"), New: &alt}}); err == nil {
		t.Error("after a failed build, changes must be rejected until the build is retried")
	}
	run.fail = nil
	if err := r.Rebuild(cfgOf(t, twoExits), nil); err != nil {
		t.Fatal(err)
	}
	if err := r.Apply([]claims.Change{{Addr: netip.MustParseAddr("1.1.1.1"), New: &alt}}); err != nil {
		t.Errorf("after a successful build: %v", err)
	}
}

func TestApplyRejectsUnknownExit(t *testing.T) {
	run := &scripted{}
	r := NewRouter(run, "br0", netip.Addr{})
	r.Rebuild(cfgOf(t, "exit vpn = W\ndefault direct\nx.com -> vpn\n"), nil)
	run.calls = nil
	ghost := rules.Action{Exit: "ghost"}
	if err := r.Apply([]claims.Change{{Addr: netip.MustParseAddr("1.1.1.1"), New: &ghost}}); err == nil {
		t.Error("an action with an exit missing from the layout must be an error")
	}
	if len(run.calls) != 0 {
		t.Errorf("sets must not be touched for an unknown exit: %v", run.calls)
	}
}

func TestTeardownFlushesOnlyOwnTables(t *testing.T) {
	// A line with a trassa mark but a foreign table: the rule is deleted, the main table is not flushed.
	run := &scripted{out: map[string]string{
		"ip rule list": "201:\tfrom all fwmark 0x54520001 lookup main \n202:\tfrom all fwmark 0x54520002 lookup 542 \n",
	}}
	Teardown(context.Background(), run)
	got := strings.Join(run.changed(), "\n")
	if strings.Contains(got, "flush table main") || !strings.Contains(got, "ip route flush table 542") || !strings.Contains(got, "ip rule del pref 201") {
		t.Errorf("commands:\n%s", got)
	}
}

func TestExecHonoursTimeoutWithLingeringChild(t *testing.T) {
	// The utility timed out, but its child process holds the output stream.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Exec{}.Run(ctx, "sh", "-c", "sleep 5 & sleep 5")
	if err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("error %v, took %s; want a failure within two seconds", err, time.Since(start).Round(time.Millisecond))
	}
}

func markOf(t *testing.T, s string) uint32 {
	t.Helper()
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(v)
}

func TestMarksCarryLayoutGeneration(t *testing.T) {
	a, _ := NewLayout(cfgOf(t, "exit vpn = W\nexit alt = W\ndefault direct\n"))
	b, _ := NewLayout(cfgOf(t, "exit alt = W\nexit vpn = W\ndefault direct\n"))
	same, _ := NewLayout(cfgOf(t, "exit vpn = W2, W3\nexit alt = W\ndefault direct\nx.com -> vpn\n"))
	if a.Slots[0].Mark() != "0x54520000" || b.Slots[0].Mark() != "0x54520000" {
		t.Errorf("the direct mark must not depend on the layout: %s, %s", a.Slots[0].Mark(), b.Slots[0].Mark())
	}
	if a.Slots[1].Mark() == b.Slots[1].Mark() {
		t.Error("reordered exits must give different marks")
	}
	for i := range a.Slots {
		if a.Slots[i].Mark() != same.Slots[i].Mark() {
			t.Errorf("slot %d: the same exits in the same order must keep their marks across rule changes", i)
		}
	}
	for _, s := range a.Slots[1:] {
		m := markOf(t, s.Mark())
		if m&0xffff0000 != markBase || m&0x3f != uint32(s.Index) || m == markBase {
			t.Errorf("slot %d: mark %s", s.Index, s.Mark())
		}
	}
}

func TestMarksOfAnotherLayoutGoNowhere(t *testing.T) {
	run := &scripted{fail: []string{" -C "}}
	r := NewRouter(run, "br0", netip.Addr{})
	if err := r.Rebuild(cfgOf(t, twoExits), nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip rule add fwmark 0x54520000/0xffffffff lookup main pref 199",
		"ip rule add fwmark 0x54520000/0xffff0000 lookup 599 pref 299",
		"ip route replace blackhole default table 599",
	} {
		if !slices.Contains(run.changed(), want) {
			t.Errorf("missing %q in %q", want, run.changed())
		}
	}
}

func TestRulesOfAnotherLayoutAreReplaced(t *testing.T) {
	l, _ := NewLayout(cfgOf(t, twoExits))
	run := &scripted{fail: []string{" -C "}, out: map[string]string{
		"ip rule list": "201:\tfrom all fwmark 0x54520001 lookup 541 \n",
	}}
	r := NewRouter(run, "br0", netip.Addr{})
	// Live tunnels: otherwise syncRoutes empties table 541 legitimately (no tunnel for the exit).
	if err := r.SetExits(map[string]string{"vpn": "nwg2", "alt": "nwg3"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Rebuild(cfgOf(t, twoExits), nil); err != nil {
		t.Fatal(err)
	}
	add := "ip rule add fwmark " + l.Slots[1].Mark() + "/0xffffffff lookup 541 pref 201"
	del := "ip rule del pref 201 fwmark 0x54520001 lookup 541"
	c := run.changed()
	ia, id := slices.Index(c, add), slices.Index(c, del)
	if ia < 0 || id < 0 || id < ia {
		t.Errorf("the new rule must be added before the old one is removed: %q", c)
	}
	if slices.Contains(c, "ip route flush table 541") {
		t.Error("table 541 is still in use and must not be flushed")
	}
}
