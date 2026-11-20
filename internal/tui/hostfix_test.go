package tui

import (
	"net/http"
	"strings"
	"testing"
)

// TestCardFixes: a server's card lists what to fix on it (as the web page's server page) with the priorities
// counted from that list; at the end each fix with its CVEs and the command for this server; its runs that changed
// something on it; and y copies a task about that server only.
func TestCardFixes(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(140, 60)
	card(h)
	hd := h.m.hostFixes("web-01")
	if hd == nil || hd.d.ID == "" || len(hd.d.Fixes) == 0 || len(hd.d.Details) != len(hd.d.Fixes) {
		t.Fatalf("the card's fixes did not load: %+v", hd)
	}
	h.has("Fixes", "↓ Fix details")
	h.hasNot("Update OS packages") // the run's actions, the card's list before the fixes came
	h.key("G")                     // the end: each fix with its CVEs and the command for this server
	h.has("CVE-", "$ ")

	hd.runs = []hostRun{
		{RunID: "2026-11-03_120000", State: "failed"},
		{RunID: "2026-11-03_110000", State: "ok"},
		{RunID: "2026-11-03_100000", State: "ok", New: []hostChange{{Pkg: "openssl", Priority: "P2"}}, Resolved: []hostChange{{Pkg: "sudo"}}},
	}
	h.key("g")
	h.size(140, 200)
	h.has("History", "not reached", "+openssl", "−sudo", "Fix details")
	if lines := h.m.historyLines(hd.runs); len(lines) != 2 {
		t.Fatalf("a quiet run is left out: %q", lines)
	}

	h.key("y")
	if text := clipText(t, h); !strings.HasPrefix(text, "TASK production en ") {
		t.Fatalf("task: %q", text)
	}
}

// TestCardWithoutHostAPI: against a server without /api/host (before 0.8) the card keeps the run's own lists, and
// nothing is asked again for the same host.
func TestCardWithoutHostAPI(t *testing.T) {
	m := New(Options{Client: Local(http.NotFoundHandler())})
	m.org, m.env, m.run, m.host = "acme", "production", "current", "web-01"
	m.rund = &runResp{}
	m.pending = map[string]string{}
	cmd := m.fetchHost()
	if cmd == nil {
		t.Fatal("nothing asked")
	}
	msg, ok := cmd().(hostMsg)
	if !ok || msg.d != nil {
		t.Fatalf("%#v", msg)
	}
	m.update(msg)
	if m.hostFixes("web-01") != nil || m.fetchHost() != nil {
		t.Fatal("a server without /api/host: the card's own lists, asked once")
	}
	if m.hostTask("web-01") != nil {
		t.Fatal("no task without the host's fixes")
	}
}
