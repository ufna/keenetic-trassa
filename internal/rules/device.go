package rules

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

const (
	// MaxDeviceLists is how many device lists can be declared: a device's lists are a 16-bit mask.
	MaxDeviceLists = 16
	// MaxDevices is how many devices all device lists may name together.
	MaxDevices = 64
	// maxDeviceName is the longest device name accepted: firmware names are short.
	maxDeviceName = 64
)

// View is the set of device lists a device belongs to: bit i means Config.Devices[i].
// 0 is a device in no list: rules without "for" and with "for !list" apply to it.
type View uint16

// DeviceRef is one device of a device list. Exactly one field is set.
type DeviceRef struct {
	Addr netip.Addr // an IPv4 address, taken as is
	MAC  string     // a MAC address, lowercase with colons; its address comes from the firmware
	Name string     // a name from the firmware's device list; its address comes from the firmware
}

func (d DeviceRef) String() string {
	switch {
	case d.Addr.IsValid():
		return d.Addr.String()
	case d.MAC != "":
		return d.MAC
	}
	return strconv.Quote(d.Name)
}

// DeviceList is a "device <name> = <device>, <device>..." line.
type DeviceList struct {
	Name    string
	Members []DeviceRef
	Line    int
}

// DeviceList returns the position of the device list with this name.
func (c *Config) DeviceList(name string) (int, bool) {
	for i, d := range c.Devices {
		if d.Name == name {
			return i, true
		}
	}
	return 0, false
}

// ViewName names a view by its device lists, "tv, phones"; "" for a device in no list.
func (c *Config) ViewName(v View) string {
	var names []string
	for i, d := range c.Devices {
		if i < MaxDeviceLists && v&(1<<i) != 0 {
			names = append(names, d.Name)
		}
	}
	return strings.Join(names, ", ")
}

// AppliesTo reports whether the rule applies to a device whose lists are v: the device is in one
// of the "for" lists (or there are none) and in none of the "for !" lists.
func (r *Rule) AppliesTo(v View) bool {
	return (r.forMask == 0 || v&r.forMask != 0) && v&r.notMask == 0
}

func (p *parser) device(n int, rest string) {
	name, list, ok := strings.Cut(rest, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		p.errf(n, "expected: device <name> = <device>, <device>...")
		return
	}
	if !validIdent(name) {
		p.errf(n, "device list name %q: only lowercase Latin letters, digits, - and _ are allowed", name)
		return
	}
	if _, dup := p.cfg.DeviceList(name); dup {
		p.errf(n, "device list %q is already declared", name)
		return
	}
	items, err := splitDevices(list)
	if err != nil {
		p.errf(n, "%v", err)
		return
	}
	d := DeviceList{Name: name, Line: n}
	for _, it := range items {
		ref, err := parseDevice(it)
		if err != nil {
			p.errf(n, "%v", err)
			return
		}
		d.Members = append(d.Members, ref)
	}
	p.cfg.Devices = append(p.cfg.Devices, d)
}

type deviceItem struct {
	text   string
	quoted bool
}

// splitDevices splits a comma-separated device list. A name in double quotes may contain spaces,
// commas and #.
func splitDevices(s string) ([]deviceItem, error) {
	var out []deviceItem
	i := 0
	skip := func() {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
	}
	for {
		skip()
		var it deviceItem
		if i < len(s) && s[i] == '"' {
			end := strings.IndexByte(s[i+1:], '"')
			if end < 0 {
				return nil, errors.New("a device name in quotes has no closing quote")
			}
			it = deviceItem{text: s[i+1 : i+1+end], quoted: true}
			i += end + 2
		} else {
			end := strings.IndexByte(s[i:], ',')
			if end < 0 {
				end = len(s) - i
			}
			it = deviceItem{text: strings.TrimSpace(s[i : i+end])}
			i += end
		}
		if strings.TrimSpace(it.text) == "" {
			return nil, errors.New("empty device in the list, or a missing comma")
		}
		out = append(out, it)
		skip()
		if i == len(s) {
			return out, nil
		}
		if s[i] != ',' {
			return nil, fmt.Errorf("a comma is missing after device %q", it.text)
		}
		i++
	}
}

// parseDevice recognizes an IPv4 address, a MAC or a device name. A quoted item is always a name.
func parseDevice(it deviceItem) (DeviceRef, error) {
	if !it.quoted {
		if a, err := netip.ParseAddr(it.text); err == nil {
			if !a.Is4() {
				return DeviceRef{}, fmt.Errorf("device %s: IPv6 is not supported yet", it.text)
			}
			return DeviceRef{Addr: a}, nil
		}
		if looksNumeric(it.text) {
			return DeviceRef{}, fmt.Errorf("device %q looks like an address but is malformed", it.text)
		}
		if mac, err := net.ParseMAC(it.text); err == nil && len(mac) == 6 {
			return DeviceRef{MAC: mac.String()}, nil
		}
		if strings.ContainsAny(it.text, " \t") {
			return DeviceRef{}, fmt.Errorf("device %q: a name with spaces goes in double quotes; or a comma is missing", it.text)
		}
	}
	if len(it.text) > maxDeviceName || strings.ContainsFunc(it.text, unicode.IsControl) {
		return DeviceRef{}, fmt.Errorf("device name %q: at most %d characters, no control characters", it.text, maxDeviceName)
	}
	return DeviceRef{Name: it.text}, nil
}

// forLists parses the device lists after "for": "tv, phones", "!office".
func (p *parser) forLists(n int, s string, r *Rule) bool {
	if strings.TrimSpace(s) == "" {
		p.errf(n, "for needs device list names: for tv, phones or for !office")
		return false
	}
	seen := map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		neg := strings.HasPrefix(item, "!")
		name := strings.TrimPrefix(item, "!")
		switch {
		case name == "":
			p.errf(n, "for: empty device list name, or a missing comma")
			return false
		case strings.ContainsAny(name, " \t"):
			p.errf(n, "for: a comma is missing in %q", item)
			return false
		case !validIdent(name):
			p.errf(n, "for: device list name %q: only lowercase Latin letters, digits, - and _ are allowed", name)
			return false
		case seen[name]:
			p.errf(n, "for: device list %q is named twice", name)
			return false
		}
		seen[name] = true
		if neg {
			r.NotFor = append(r.NotFor, name)
		} else {
			r.For = append(r.For, name)
		}
	}
	return true
}

// finishDevices checks the limits and ties the rules' "for" lists to the declared device lists.
// Device lists may be declared anywhere in the file, like exits.
func (p *parser) finishDevices() {
	if len(p.cfg.Devices) > MaxDeviceLists {
		p.errf(p.cfg.Devices[MaxDeviceLists].Line, "%d device lists: at most %d are supported", len(p.cfg.Devices), MaxDeviceLists)
	}
	total := 0
	for _, d := range p.cfg.Devices {
		total += len(d.Members)
		if total > MaxDevices {
			p.errf(d.Line, "more than %d devices in all device lists together", MaxDevices)
			break
		}
	}
	mask := func(line int, names []string) View {
		var m View
		for _, name := range names {
			k, ok := p.cfg.DeviceList(name)
			if !ok {
				p.errf(line, "device list %q is not declared (add a line: device %s = <devices>)", name, name)
				continue
			}
			if k < MaxDeviceLists {
				m |= 1 << k
			}
		}
		return m
	}
	for i := range p.cfg.Rules {
		r := &p.cfg.Rules[i]
		r.forMask, r.notMask = mask(r.Line, r.For), mask(r.Line, r.NotFor)
	}
}
