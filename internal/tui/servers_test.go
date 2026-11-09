package tui

import "testing"

// TestServers: the view the TUI opens on: every server with its fixes per priority, its state and scan age; one the
// scan did not reach says why (in the interface's language); Enter opens the host card; g goes on to fix and CVE.
func TestServers(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	if New(Options{}).view != vServers {
		t.Fatal("the TUI opens on Servers")
	}
	h.size(160, 40)
	h.key("1")
	h.has("Servers(acme/production)[5]", "· 1 ! · 1 ✗", "group by  server  fix  CVE",
		"app-01              Ubuntu 18.04             2 • 1 • 3 • 0      12      KEV          5d",
		"web-01              CentOS Stream 9  Public  3 • 4 • 2 • 4", "✗  dead-01             The last scan did not reach it", "not checked")
	// the details of the server under the cursor: its card
	h.has("to fix  P1 ", "scanned  5 d ago as audit")
	for h.m.curNode().Label != "dead-01" {
		h.key("down")
	}
	h.key("enter")
	h.has("Details(dead-01", "✗ The last scan did not reach it")
	// a state without the server's words: said by the TUI
	n := h.m.curNode()
	n.Problem, n.ProblemMsg = "", ""
	h.has("✗ failed")
	h.key("esc", "g")
	if h.m.by[vServers] != "fix" || h.m.by[vActions] != "fix" {
		t.Fatal(h.m.by)
	}
	h.has("Servers(acme/production)")
}
