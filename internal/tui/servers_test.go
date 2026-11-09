package tui

import "testing"

// TestServers: the view the TUI opens on: every server with its fixes per priority, its state and scan age; a
// failed one says why; Enter opens the host card; g goes on to fix and CVE.
func TestServers(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	if New(Options{}).view != vServers {
		t.Fatal("the TUI opens on Servers")
	}
	h.size(160, 40)
	h.key("1")
	h.has("Servers(acme/production)", "group by  server  fix  CVE", "web-01", "CentOS Stream 9", "internet")
	var hosts []*tnode
	for _, r := range h.m.treeRows() {
		hosts = append(hosts, r.n)
	}
	hosts[0].State, hosts[0].LastScan = "clean", "2026-11-07T08:00:00Z"
	hosts[1].State, hosts[1].Error = "failed", "the server refused the login"
	hosts[2].State, hosts[2].Kids, hosts[2].Counts = "clean", nil, map[string]int{}
	h.has("· 2 ✓ · 1 ✗", "the server refused the login", "not checked", "nothing to fix", "4h")
	h.key("home", "enter")
	h.has("Details(", "to fix", "scanned", "SSH and logins")
	h.key("esc", "g")
	if h.m.by[vServers] != "fix" || h.m.by[vActions] != "fix" {
		t.Fatal(h.m.by)
	}
}
