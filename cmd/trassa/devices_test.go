package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRCIHosts answers like fakeRCI, and with these devices for the firmware's device list.
func fakeRCIHosts(t *testing.T, hosts string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rci/show/ip/hotspot" {
			fmt.Fprint(w, hosts)
			return
		}
		fmt.Fprint(w, `{"id":"W","index":2,"type":"Wireguard","link":"up","connected":"yes","wireguard":{"peer":[{"online":true}]}}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestSaveChecksDevicesWithTheRouter(t *testing.T) {
	noDaemon(t)
	dir := filepath.Dir(write(t, map[string]string{"rules.conf": live}))
	const text = "exit vpn = W\ndevice tv = \"Living room TV\"\ndefault direct\nx.example -> vpn for tv\n"
	res, err := newStore(dir, fakeRCIHosts(t, `{"host":[]}`)).Save(text, false)
	if err != nil || res.Saved || !strings.Contains(fmt.Sprint(res.Problems), "is not in the router's device list") {
		t.Errorf("unknown device: saved %v, %v, %v", res.Saved, res.Problems, err)
	}
	tv := `{"host":[{"mac":"aa:bb:cc:00:00:01","ip":"192.168.1.40","name":"Living room TV","active":true}]}`
	if res, err = newStore(dir, fakeRCIHosts(t, tv)).Save(text, false); err != nil || !res.Saved {
		t.Errorf("known device: saved %v, %v, %v", res.Saved, res.Problems, err)
	}
}

func TestWhyFileShowsDeviceLists(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": "exit vpn = W\ndevice tv = 192.168.1.40\ndefault direct\nx.example -> vpn for tv\n"})
	code, out, errOut := exec("why", "-f", path, "x.example")
	if code != 0 || !strings.Contains(out, "x.example → direct") || !strings.Contains(out, "for tv: vpn (line 4)") {
		t.Errorf("code %d, output %q, stderr %q", code, out, errOut)
	}
}
