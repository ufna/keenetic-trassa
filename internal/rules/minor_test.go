package rules

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

const base = "exit vpn = W\ndefault direct\n"

func wantError(t *testing.T, src, want string) {
	t.Helper()
	if _, ps := Parse(src, nil); !HasErrors(ps) || !strings.Contains(fmt.Sprint(ps), want) {
		t.Errorf("%q: %v, want %q", src, ps, want)
	}
}

func TestDeviceLineWithTab(t *testing.T) {
	c := devConfig(t, base+"device\ttv = \"TV #2\" # a comment\n")
	if got := c.Devices[0].Members[0].Name; got != "TV #2" {
		t.Errorf("name %q", got)
	}
}

func TestDeviceNameLengthIsInCharacters(t *testing.T) {
	devConfig(t, base+`device tv = "`+strings.Repeat("Ж", 64)+`"`+"\n")
	wantError(t, base+`device tv = "`+strings.Repeat("Ж", 65)+`"`+"\n", "at most 64 characters")
}

func TestDeviceNameSpacesTrimmed(t *testing.T) {
	if got := devConfig(t, base+`device tv = " Pixel "`+"\n").Devices[0].Members[0].Name; got != "Pixel" {
		t.Errorf("name %q", got)
	}
}

func TestDeviceListedTwice(t *testing.T) {
	for _, list := range []string{"1.2.3.4, 1.2.3.4", `"Pixel", "pixel"`, "aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF"} {
		wantError(t, base+"device tv = "+list+"\n", "is listed twice")
	}
	// The same device in two lists is fine: that is how a device gets into several lists.
	devConfig(t, base+"device tv = 1.2.3.4\ndevice kids = 1.2.3.4\n")
}

func TestReservedWords(t *testing.T) {
	wantError(t, "exit for = W\ndefault direct\n", `"for" is a reserved word`)
	wantError(t, "exit strict = W\ndefault direct\n", `"strict" is a reserved word`)
	wantError(t, base+"device for = 1.2.3.4\n", `"for" is a reserved word`)
	wantError(t, base+"device tv = 1.2.3.4\nx.example -> vpn for tv strict\n", "strict goes before for")
	wantError(t, base+"device tv = 1.2.3.4\nx.example -> vpn for strict\n", "strict goes before for")
	wantError(t, base+"device tv = 1.2.3.4\nx.example -> vpn for for\n", `"for" is a reserved word`)
	wantError(t, "default direct\nx.example -> \n", "expected an exit: direct, none or <exit name>")
}

func TestDeviceLimitsExactly(t *testing.T) {
	var b strings.Builder
	b.WriteString(base)
	for i := 0; i < MaxDeviceLists; i++ {
		fmt.Fprintf(&b, "device d%d = 10.0.0.%d\n", i, i+1)
	}
	devConfig(t, b.String())
	fmt.Fprintf(&b, "device d16 = 10.0.1.1\n")
	if _, ps := Parse(b.String(), nil); len(ps) != 1 || ps[0].Line != 19 {
		t.Errorf("the 17th list must be the error, on its own line: %v", ps)
	}
	var addrs []string
	for i := 0; i < MaxDevices; i++ {
		addrs = append(addrs, fmt.Sprintf("10.1.%d.%d", i/200, i%200+1))
	}
	devConfig(t, base+"device a = "+strings.Join(addrs, ", ")+"\n")
	if _, ps := Parse(base+"device a = 1.2.3.4\nx.example -> vpn for b\n", nil); len(ps) != 1 || ps[0].Line != 4 {
		t.Errorf("an unknown list is an error on the rule's line: %v", ps)
	}
}

func TestDeviceLinesForAddressesAndLinks(t *testing.T) {
	c := devConfig(t, withDevices)
	for _, s := range []string{"91.108.4.7", "https://91.108.4.7/x"} {
		if got := c.DeviceLines(s, []View{tv, phones}); got != "for tv: vpn (line 9)\n" {
			t.Errorf("%s: %q", s, got)
		}
	}
	if got := c.DeviceLines("149.154.167", []View{tv}); got != "" {
		t.Errorf("a malformed subject: %q", got)
	}
	// A view with the same decision as everyone else is not listed.
	if got := c.DeviceLines("telegram.org", []View{tv, phones, office}); got != "" {
		t.Errorf("telegram.org: %q", got)
	}
}

// coversDevices answers "does r apply to every device o applies to" by trying the combinations of
// the lists the two name; this checks it against all views of up to 5 lists for random rules.
func TestCoversDevicesAgainstAllViews(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	mask := func() View { return View(rng.Intn(1 << 5)) }
	for i := 0; i < 20000; i++ {
		r := Rule{forMask: mask(), notMask: mask()}
		o := Rule{forMask: mask(), notMask: mask()}
		want := true
		for v := View(0); v < 1<<5; v++ {
			if o.AppliesTo(v) && !r.AppliesTo(v) {
				want = false
				break
			}
		}
		if got := r.coversDevices(&o); got != want {
			t.Fatalf("r %+v, o %+v: covers %v, want %v", r, o, got, want)
		}
	}
}
