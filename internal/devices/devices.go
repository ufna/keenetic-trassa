// Package devices asks the firmware which devices are on the home network and finds where the
// devices of the rules' device lists are.
package devices

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/ufna/keenetic-trassa/internal/rules"
)

// Host is a device the firmware knows.
type Host struct {
	MAC      string     // lowercase with colons
	IP       netip.Addr // invalid if the device has no address
	Name     string     // the name given to the device in the firmware's device list; may be empty
	Hostname string     // the name the device reports about itself; may be empty
	Online   bool       // on the network now, or holding a DHCP lease
	// IP6 are its IPv6 addresses, from the firmware's list and the router's neighbour table: a
	// device that asks DNS over IPv6 is still this device.
	IP6 []netip.Addr
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

// maxAnswer bounds the firmware's answer: a home network's device list is far smaller.
const maxAnswer = 4 << 20

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
	// IP6 is read as it comes: its shape has been seen only as a list of strings, and a field of
	// another shape must not cost the whole device list.
	IP6  json.RawMessage `json:"ip6"`
	DHCP struct {
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read firmware answer: %w", err)
	}
	if len(body) > maxAnswer {
		return nil, fmt.Errorf("firmware answer is larger than %d MiB", maxAnswer>>20)
	}
	if err := json.Unmarshal(body, &j); err != nil {
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
		if mac, err := net.ParseMAC(h.MAC); err == nil {
			host.MAC = mac.String() // the form the rules use, whatever the firmware writes
		}
		if a, err := netip.ParseAddr(h.IP); err == nil && a.Is4() && !a.IsUnspecified() {
			host.IP = a
		}
		var ip6 []string
		_ = json.Unmarshal(h.IP6, &ip6) // another shape: no IPv6 addresses from the firmware
		for _, s := range ip6 {
			// A zone ("%br0") is dropped: packets carry the address without it.
			if a, err := netip.ParseAddr(s); err == nil && a.Is6() && !a.Is4In6() {
				host.IP6 = append(host.IP6, a.WithZone(""))
			}
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

// byHostname finds a device by the name it reports about itself.
func byHostname(hosts []Host, name string) *Host {
	for i := range hosts {
		if hosts[i].Hostname != "" && strings.EqualFold(hosts[i].Hostname, name) {
			return &hosts[i]
		}
	}
	return nil
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
				switch hs := byName(hosts, m.Name); {
				case len(hs) == 0 && byHostname(hosts, m.Name) != nil:
					h := byHostname(hosts, m.Name)
					add(d.Line, rules.Error, "device %q has no name in the router settings: it calls itself %s; give it this name in the router settings, or write its MAC %s", m.Name, h.Hostname, h.MAC)
				case len(hs) == 0:
					add(d.Line, rules.Error, "device %q is not in the router's device list: give the device this name in the router settings, or write its MAC or address", m.Name)
				case len(hs) > 1:
					macs := make([]string, len(hs))
					for i, h := range hs {
						macs[i] = h.MAC
					}
					add(d.Line, rules.Error, "device name %q matches %d devices in the router's device list (%s): rename them, or write the MAC", m.Name, len(hs), strings.Join(macs, ", "))
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
	names, macs := false, false
	for _, d := range cfg.Devices {
		for _, m := range d.Members {
			names = names || m.Name != ""
			macs = macs || m.MAC != ""
		}
	}
	// Addresses need no firmware; MACs only ever give warnings, so an unreachable firmware does too.
	if !names && !macs {
		return nil
	}
	hosts, err := src.Hosts(ctx)
	if err != nil {
		sev := rules.Error
		if !names {
			sev = rules.Warning
		}
		return []rules.Problem{{Line: cfg.Devices[0].Line, Severity: sev, Msg: "cannot read the router's device list: " + err.Error()}}
	}
	return Validate(cfg, hosts)
}

// Member is a device of a device list and where it is now.
type Member struct {
	Ref   rules.DeviceRef
	Label string     // the device's name in the firmware, if known
	IP    netip.Addr // invalid if the device has no address now
	State string     // on the network, not on the network, not in the router's device list, or matches N devices
}

const (
	stateOn      = "on the network"
	stateOff     = "not on the network"
	stateUnknown = "not in the router's device list"
	stateUnread  = "device list not read yet"
)

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

	ipv4   map[netip.Addr]netip.Addr // an IPv6 address of a device → its IPv4 address
	macIP4 map[string]netip.Addr     // a device's MAC → its IPv4 address
}

// Device returns the IPv4 address of the device at a, which may be one of its IPv6 addresses; an
// address of no known device is returned as it is. A link-local address built from the MAC
// (EUI-64) is recognised even when no table lists it.
func (m Map) Device(a netip.Addr) netip.Addr {
	if a.Is4() {
		return a
	}
	if v, ok := m.ipv4[a]; ok {
		return v
	}
	if mac, ok := eui64MAC(a); ok {
		if v, ok := m.macIP4[mac]; ok {
			return v
		}
	}
	return a
}

// eui64MAC returns the MAC an IPv6 address was built from, if it was (the "ff:fe" in the middle of
// its interface part, the universal/local bit flipped).
func eui64MAC(a netip.Addr) (string, bool) {
	if !a.Is6() || !a.IsLinkLocalUnicast() {
		return "", false
	}
	b := a.As16()
	if b[11] != 0xff || b[12] != 0xfe {
		return "", false
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[8]^2, b[9], b[10], b[13], b[14], b[15]), true
}

// Neighbor is an entry of the router's IPv6 neighbour table: an address and the MAC behind it.
type Neighbor struct {
	IP  netip.Addr
	MAC string
}

// ParseNeighbors reads the output of "ip -6 neigh show"; entries without a MAC are skipped.
func ParseNeighbors(out string) []Neighbor {
	var n []Neighbor
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil || !a.Is6() || a.Is4In6() {
			continue
		}
		a = a.WithZone("")
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "lladdr" {
				if mac, err := net.ParseMAC(f[i+1]); err == nil {
					n = append(n, Neighbor{IP: a, MAC: mac.String()})
				}
				break
			}
		}
	}
	return n
}

// WithNeighbors adds to the devices the IPv6 addresses the neighbour table has for their MACs.
func WithNeighbors(hosts []Host, n []Neighbor) []Host {
	out := slices.Clone(hosts)
	for _, x := range n {
		for i := range out {
			if out[i].MAC == x.MAC && !slices.Contains(out[i].IP6, x.IP) {
				out[i].IP6 = append(slices.Clone(out[i].IP6), x.IP)
			}
		}
	}
	return out
}

// Resolve finds the addresses of the device lists' devices. An address written in the rules counts
// always; a name or a MAC counts while the device is on the network or holds a DHCP lease. nil hosts
// means the firmware's list has not been read yet.
func Resolve(cfg *rules.Config, hosts []Host) Map {
	m := Map{Views: map[netip.Addr]rules.View{}, Labels: map[netip.Addr]string{},
		ipv4: map[netip.Addr]netip.Addr{}, macIP4: map[string]netip.Addr{}}
	for _, h := range hosts {
		// An address may still be listed for a device gone from the network: the one there now wins.
		if _, have := m.Labels[h.IP]; h.IP.IsValid() && h.Label() != "" && (!have || h.Online) {
			m.Labels[h.IP] = h.Label()
		}
		if h.IP.IsValid() {
			if _, have := m.macIP4[h.MAC]; !have || h.Online {
				m.macIP4[h.MAC] = h.IP
			}
			for _, a := range h.IP6 {
				if _, have := m.ipv4[a]; !have || h.Online {
					m.ipv4[a] = h.IP
				}
			}
		}
	}
	for i, d := range cfg.Devices {
		if i >= rules.MaxDeviceLists {
			break
		}
		l := List{Name: d.Name}
		for _, ref := range d.Members {
			mem := Member{Ref: ref, State: stateUnknown}
			if hosts == nil {
				mem.State = stateUnread // the firmware has not answered yet
			}
			found := func(h *Host) {
				mem.Label, mem.State = h.Label(), stateOff
				if h.Online && h.IP.IsValid() {
					mem.IP, mem.State = h.IP, stateOn
				}
			}
			switch {
			case ref.Addr.IsValid():
				mem.IP, mem.Label, mem.State = ref.Addr, m.Labels[ref.Addr], stateOn
			case ref.MAC != "":
				if h := byMAC(hosts, ref.MAC); h != nil {
					found(h)
				}
			default:
				switch hs := byName(hosts, ref.Name); {
				case len(hs) == 1:
					found(&hs[0])
				case len(hs) > 1:
					mem.State = fmt.Sprintf("matches %d devices in the router's device list", len(hs))
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
