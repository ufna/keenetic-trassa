// Package devices asks the firmware which devices are on the home network and finds where the
// devices of the rules' device lists are.
package devices

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"trassa/internal/rules"
)

// Host is a device the firmware knows.
type Host struct {
	MAC      string     // lowercase with colons
	IP       netip.Addr // invalid if the device has no address
	Name     string     // the name given to the device in the firmware's device list; may be empty
	Hostname string     // the name the device reports about itself; may be empty
	Online   bool       // on the network now, or holding a DHCP lease
}

// Label is how the device is shown: its firmware name, else its own name.
func (h Host) Label() string {
	if h.Name != "" {
		return h.Name
	}
	return h.Hostname
}

// Source lists the devices the firmware knows. Tests substitute it.
type Source interface {
	Hosts(ctx context.Context) ([]Host, error)
}

// RCI asks the firmware at its local address.
type RCI struct {
	Base   string // e.g. http://127.0.0.1:79
	Client *http.Client
}

type hostJSON struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Active   bool   `json:"active"`
	DHCP     struct {
		Expires int64 `json:"expires"`
	} `json:"dhcp"`
}

func (r RCI) Hosts(ctx context.Context) ([]Host, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.Base+"/rci/show/ip/hotspot", nil)
	if err != nil {
		return nil, err
	}
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("firmware does not respond: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("firmware answered with code %d", resp.StatusCode)
	}
	var j struct {
		Host *[]hostJSON `json:"host"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&j); err != nil {
		return nil, fmt.Errorf("cannot parse firmware answer: %w", err)
	}
	// An answer without the list (an error from the firmware) is a failure, not an empty network:
	// the caller then keeps the device addresses it knew.
	if j.Host == nil {
		return nil, fmt.Errorf("firmware answer has no device list")
	}
	hosts := make([]Host, 0, len(*j.Host))
	for _, h := range *j.Host {
		host := Host{MAC: strings.ToLower(h.MAC), Name: h.Name, Hostname: h.Hostname, Online: h.Active || h.DHCP.Expires > 0}
		if a, err := netip.ParseAddr(h.IP); err == nil && a.Is4() && !a.IsUnspecified() {
			host.IP = a
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func byName(hosts []Host, name string) []Host {
	var out []Host
	for _, h := range hosts {
		if h.Name != "" && strings.EqualFold(h.Name, name) {
			out = append(out, h)
		}
	}
	return out
}

func byMAC(hosts []Host, mac string) *Host {
	for i := range hosts {
		if hosts[i].MAC == mac {
			return &hosts[i]
		}
	}
	return nil
}

// Validate checks the device lists against the firmware's devices: a name must match exactly one
// device. A MAC the firmware has never seen is only a warning: the device may not have joined yet.
// An address written in the rules is not checked.
func Validate(cfg *rules.Config, hosts []Host) []rules.Problem {
	var ps []rules.Problem
	add := func(line int, sev rules.Severity, format string, args ...any) {
		ps = append(ps, rules.Problem{Line: line, Severity: sev, Msg: fmt.Sprintf(format, args...)})
	}
	for _, d := range cfg.Devices {
		for _, m := range d.Members {
			switch {
			case m.Name != "":
				switch n := len(byName(hosts, m.Name)); {
				case n == 0:
					add(d.Line, rules.Error, "device %q is not in the router's device list: give the device this name in the router settings, or write its MAC or address", m.Name)
				case n > 1:
					add(d.Line, rules.Error, "device name %q matches %d devices in the router's device list: rename them, or write the MAC", m.Name, n)
				}
			case m.MAC != "":
				if byMAC(hosts, m.MAC) == nil {
					add(d.Line, rules.Warning, "device %s has never been seen by the router: check the MAC", m.MAC)
				}
			}
		}
	}
	return ps
}

// Check asks the firmware for its devices and validates the device lists. Without device lists
// it does not ask.
func Check(ctx context.Context, cfg *rules.Config, src Source) []rules.Problem {
	if len(cfg.Devices) == 0 {
		return nil
	}
	hosts, err := src.Hosts(ctx)
	if err != nil {
		return []rules.Problem{{Line: cfg.Devices[0].Line, Severity: rules.Error, Msg: "cannot read the router's device list: " + err.Error()}}
	}
	return Validate(cfg, hosts)
}

// Member is a device of a device list and where it is now.
type Member struct {
	Ref   rules.DeviceRef
	Label string     // the device's name in the firmware, if known
	IP    netip.Addr // invalid if the device has no address now
}

// List is a device list and its devices.
type List struct {
	Name    string
	Members []Member
}

// Map is where the devices of the device lists are now.
type Map struct {
	Views  map[netip.Addr]rules.View // device address → its device lists; only listed devices
	Labels map[netip.Addr]string     // device address → its name, for every device the firmware knows
	Lists  []List                    // in declaration order
}

// Resolve finds the addresses of the device lists' devices. An address written in the rules counts
// always; a name or a MAC counts while the device is on the network or holds a DHCP lease.
func Resolve(cfg *rules.Config, hosts []Host) Map {
	m := Map{Views: map[netip.Addr]rules.View{}, Labels: map[netip.Addr]string{}}
	for _, h := range hosts {
		if h.IP.IsValid() && h.Label() != "" {
			m.Labels[h.IP] = h.Label()
		}
	}
	for i, d := range cfg.Devices {
		if i >= rules.MaxDeviceLists {
			break
		}
		l := List{Name: d.Name}
		for _, ref := range d.Members {
			mem := Member{Ref: ref}
			switch {
			case ref.Addr.IsValid():
				mem.IP, mem.Label = ref.Addr, m.Labels[ref.Addr]
			case ref.MAC != "":
				if h := byMAC(hosts, ref.MAC); h != nil {
					mem.Label = h.Label()
					if h.Online {
						mem.IP = h.IP
					}
				}
			default:
				if hs := byName(hosts, ref.Name); len(hs) == 1 {
					mem.Label = hs[0].Label()
					if hs[0].Online {
						mem.IP = hs[0].IP
					}
				}
			}
			if mem.IP.IsValid() {
				m.Views[mem.IP] |= 1 << i
			}
			l.Members = append(l.Members, mem)
		}
		m.Lists = append(m.Lists, l)
	}
	return m
}

// ViewList returns the distinct views of the listed devices, ascending, without 0.
func (m Map) ViewList() []rules.View {
	var out []rules.View
	for _, v := range m.Views {
		if v != 0 && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

// Sources groups the listed devices' addresses by view, each group ascending.
func (m Map) Sources() map[rules.View][]netip.Addr {
	out := map[rules.View][]netip.Addr{}
	for a, v := range m.Views {
		if v != 0 {
			out[v] = append(out[v], a)
		}
	}
	for _, addrs := range out {
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	}
	return out
}
