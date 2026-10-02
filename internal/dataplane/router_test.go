package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"trassa/internal/claims"
	"trassa/internal/rules"
)

// scripted запоминает команды вместе с тем, что им подано на вход, и отвечает по сценарию.
type scripted struct {
	calls []string
	out   map[string]string // начало строки команды → её вывод
	fail  []string          // команда, содержащая ключ, завершается ошибкой
}

func (s *scripted) RunInput(_ context.Context, stdin, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	if stdin != "" {
		line += " <<\n" + stdin
	}
	s.calls = append(s.calls, line)
	for _, k := range s.fail {
		if strings.Contains(line, k) {
			return "", errors.New("сбой утилиты")
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

// changed — команды, которые что-то меняют (без чтения состояния).
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
		t.Fatalf("правила: %v", ps)
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
			"-A TRASSA -m mark --mark 0x0 -m set --match-set trassa_d0 dst -j MARK --set-mark 0x54520000\n" +
			"-A TRASSA -m mark --mark 0x0 -m set --match-set trassa_d1 dst -j MARK --set-mark 0x54520001\n" +
			"-A TRASSA -m mark --mark 0x0 -m set --match-set trassa_d2 dst -j MARK --set-mark 0x54520002\n" +
			"-A TRASSA -m mark --mark 0x0 -m set --match-set trassa_d3 dst -j MARK --set-mark 0x54520003\n" +
			"-A TRASSA -m mark --mark 0x0 -m set --match-set trassa_d4 dst -j MARK --set-mark 0x54520004\n" +
			"-A TRASSA -m mark --mark 0x0 -m set --match-set trassa_s1 dst -j MARK --set-mark 0x54520002\n" +
			"-A TRASSA -m mark --mark 0x0 -m set --match-set trassa_s3 dst -j MARK --set-mark 0x54520000\n" +
			"-A TRASSA -m mark --mark 0x54520000/0xffff0000 -j CONNMARK --save-mark\n" +
			"COMMIT\n",
		"iptables -w -t mangle -A PREROUTING -s 192.168.1.94 -i br0 -j TRASSA",
		"ip rule add fwmark 0x54520001/0xffffffff lookup 541 pref 201",
		"ip rule add fwmark 0x54520002/0xffffffff lookup 542 pref 202",
		"ip rule add fwmark 0x54520003/0xffffffff lookup 543 pref 203",
		"ip rule add fwmark 0x54520004/0xffffffff lookup 544 pref 204",
		"ip route replace default dev nwg2 table 541",
		"ip route replace default dev nwg2 table 542",
		"ip route flush table 543",
		"ip route replace blackhole default table 544",
	})
}

func TestRebuildIsIdempotent(t *testing.T) {
	run := &scripted{out: map[string]string{
		"ip rule list":                        "0:\tfrom all lookup local \n201:\tfrom all fwmark 0x54520001 lookup 541 \n202:\tfrom all fwmark 0x54520002 lookup 542 \n32766:\tfrom all lookup main \n",
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
			t.Errorf("лишняя команда при повторном построении: %s", c)
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
		"-A TRASSA -m mark --mark 0x0 -j MARK --set-mark 0x54520001\n" +
		"-A TRASSA -m mark --mark 0x54520000/0xffff0000 -j CONNMARK --save-mark\nCOMMIT\n"
	if !strings.HasSuffix(tail, want) {
		t.Errorf("хвост цепочки:\n%s\nожидалось окончание:\n%s", tail, want)
	}
}

func TestRebuildAfterExitsChange(t *testing.T) {
	// Прежняя раскладка оставила списки, правило и прыжок с другим источником.
	run := &scripted{out: map[string]string{
		"ip rule list":                        "201:\tfrom all fwmark 0x54520001 lookup 541 \n205:\tfrom all fwmark 0x54520005 lookup 545 \n1150:\tfrom all fwmark 0xffffaaa lookup 4096 \n",
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
		"ip rule add fwmark 0x54520002/0xffffffff lookup 542 pref 202",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("нет команды %q в\n%s", want, got)
		}
	}
	for _, bad := range []string{"-A PREROUTING", "pref 1150", "_NDM_X", "destroy trassa_d1", "pref 201\n"} {
		if strings.Contains(got, bad) {
			t.Errorf("лишняя команда с %q в\n%s", bad, got)
		}
	}
	// Лишнее удаляется после того, как цепочка перестала на него ссылаться.
	if strings.Index(got, "ipset destroy") < strings.Index(got, "iptables-restore") {
		t.Error("списки удаляются раньше, чем заменена цепочка")
	}
}

func TestApply(t *testing.T) {
	run := &scripted{}
	r := NewRouter(run, "br0", netip.Addr{})
	if err := r.Apply([]claims.Change{{Addr: netip.MustParseAddr("1.1.1.1")}}); err == nil {
		t.Error("изменение до построения списков должно быть ошибкой")
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
		t.Error("сбой утилиты должен вернуться ошибкой")
	}
}

func TestRoutesFollowExits(t *testing.T) {
	run := &scripted{}
	r := NewRouter(run, "br0", netip.Addr{})
	r.SetExits(map[string]string{"vpn": "nwg2"})
	r.Rebuild(cfgOf(t, "exit vpn = W\ndefault direct\nx.com -> vpn\n"), nil)

	run.calls = nil
	r.SetExits(map[string]string{"vpn": ""}) // все туннели упали
	equal(t, run.calls, []string{"ip route flush table 541", "ip route replace blackhole default table 542"})

	run.calls = nil
	r.SetExits(map[string]string{"vpn": "nwg0"}) // поднялся запасной
	equal(t, run.calls, []string{"ip route replace default dev nwg0 table 541", "ip route replace default dev nwg0 table 542"})
}

func TestCheckDetectsMissingJump(t *testing.T) {
	run := &scripted{}
	r := NewRouter(run, "br0", netip.MustParseAddr("192.168.1.94"))
	if err := r.Check(context.Background()); err != nil {
		t.Errorf("прыжок на месте, а Check вернул %v", err)
	}
	equal(t, run.calls, []string{"iptables -w -t mangle -C PREROUTING -s 192.168.1.94 -i br0 -j TRASSA"})
	run.fail = []string{" -C "}
	if err := r.Check(context.Background()); err == nil {
		t.Error("пропавший прыжок не замечен")
	}
}

func TestTooManyExits(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 30; i++ {
		b.WriteString("exit e" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + " = W\n")
	}
	b.WriteString("default direct\n")
	if err := NewRouter(&scripted{}, "br0", netip.Addr{}).Rebuild(cfgOf(t, b.String()), nil); err == nil {
		t.Error("тридцать выходов должны быть отклонены")
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
		"ip rule del pref 201",
		"ip route flush table 541",
		"ip rule del pref 202",
		"ip route flush table 542",
		"ipset destroy trassa_d0",
		"ipset destroy trassa_s3",
	})
}
