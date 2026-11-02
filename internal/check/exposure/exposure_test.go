package exposure

import (
	"testing"

	"github.com/mikekosulin/kanareika/internal/check/checktest"
)

// TestGolden: recorded on stream9 (firewalld, docker, sudo), centos6 (CentOS 6 iptables, old ss), ubuntu24
// (Ubuntu 24.04, nftables/ufw), via-jump (behind NAT); synthetic: docker + firewalld, no firewall, denied.
func TestGolden(t *testing.T) {
	for _, c := range checktest.Cases(t) {
		t.Run(c.Host.Name, func(t *testing.T) { checktest.Check(t, c, Run, "raw.txt") })
	}
}

func TestIsPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "10.1.2.3": false, "100.64.0.1": false, "192.0.0.9": true, "192.0.2.1": false,
		"2a00:1450:4001::1": true, "2001:db8::1": false, "fe80::1": false, "::ffff:8.8.8.8": true,
		"::ffff:10.0.0.1": false, "2001:20::1": true, "": false, "*": false, "1.2.3.04": false,
	} {
		if got := IsPublic(ip); got != want {
			t.Errorf("%s: got %v", ip, got)
		}
	}
}

func TestNetwork(t *testing.T) {
	for v, want := range map[string]string{
		"1.2.3.4": "1.2.3.4/32", "10.0.0.7/8": "10.0.0.0/8", "10.1.0.0/255.255.0.0": "10.1.0.0/16",
		"10.0.0.0/0.0.0.255": "10.0.0.0/24", "https://[2a00::1]:443/x": "2a00::1/128", " 5.6.7.8 ": "5.6.7.8/32", //nolint:gocritic // the spaces are the point
		"host.example.org": "", "1.2.3.4/33": "", "1.2.3.4/255.0.255.0": "",
	} {
		p, ok := network(v)
		if got := p.String(); (ok && got != want) || (!ok && want != "") {
			t.Errorf("%q: got %v %v, want %q", v, p, ok, want)
		}
	}
}
