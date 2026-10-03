package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"trassa/internal/devices"
	"trassa/internal/engine"
)

// flakySource answers with its hosts, or fails while fail is set.
type flakySource struct {
	fail  bool
	hosts []devices.Host
}

func (f *flakySource) Hosts(context.Context) ([]devices.Host, error) {
	if f.fail {
		return nil, errors.New("firmware does not respond")
	}
	return f.hosts, nil
}

func TestDevicePoller(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": "exit vpn = W\ndevice tv = \"Living room TV\"\ndefault direct\nx.example -> vpn for tv\n"})
	cfg, _, _ := load(path, os.Stderr)
	eng := engine.New(cfg, nil, func(string, ...any) {}, time.Now())
	var log []string
	src := &flakySource{fail: true, hosts: []devices.Host{{MAC: "aa:bb:cc:00:00:01", IP: netip.MustParseAddr("192.168.1.40"), Name: "Living room TV", Online: true}}}
	p := &devicePoller{src: src, eng: eng, logf: func(f string, a ...any) { log = append(log, f) }}
	p.poll()
	p.poll()
	src.fail = false
	p.poll()
	src.fail = true
	p.poll()
	p.poll()
	got := strings.Join(log, "\n")
	if strings.Count(got, "not found until the router answers") != 1 || strings.Count(got, "the last known device addresses stay") != 1 {
		t.Errorf("one line per series of failures, saying what stays:\n%s", got)
	}
	if !strings.Contains(eng.Status(time.Now()), "devices tv: Living room TV (192.168.1.40)") {
		t.Errorf("the list did not reach the engine:\n%s", eng.Status(time.Now()))
	}
}
