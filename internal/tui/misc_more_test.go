package tui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestZoneMarkersCut: escape sequences measured whole, also cut short or ended by ST; a zone marker cut off by a
// line's end never shows, and a zone still open at the end of its line reaches to there.
func TestZoneMarkersCut(t *testing.T) {
	for s, want := range map[string]int{"\x1b": 1, "\x1b[31": 4, "\x1b[31m": 5, "\x1b]0;t\x1b\\x": 7, "\x1b]0;t": 5, "\x1b]0;t\a": 6, "\x1bc": 2} {
		if got := escLen(s); got != want {
			t.Errorf("%q: %d, want %d", s, got, want)
		}
	}
	m := New(Options{})
	lines := m.scanZones([]string{"ab" + zoneOpen + "x", zoneOpen + "z\aabc", "plain"})
	if lines[0] != "ab" || lines[1] != "abc" || lines[2] != "plain" {
		t.Fatalf("%q", lines)
	}
	if len(m.zones) != 1 || m.zones[0] != (hitZone{id: "z", y: 1, x0: 0, x1: 3}) {
		t.Fatalf("%+v", m.zones)
	}
}

// TestHintClicks: a click on a key hint does what its key does: space selects, [ ] picks the next command; a click on
// a row the tree no longer has (it changed since the frame) does nothing.
func TestHintClicks(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	h.click("space select")
	if len(h.m.picked()) != 1 {
		t.Fatal("space by a click", h.m.sel)
	}
	h.key("home", "enter")
	n := h.m.curNode()
	h.m.nodes[h.m.treeKey+"#"+n.ID].Apply = []applyStep{{OS: "CentOS Stream 9", Command: "dnf update openssl"}, {OS: "Debian 12", Command: "apt-get install openssl"}}
	h.click("[ ] command")
	if h.m.cmdCur != 1 {
		t.Fatal("[ ] by a click", h.m.cmdCur)
	}
	h.key("esc")
	h.m.sel = map[string]bool{}
	x, y := h.where("rsync 3.2.3 → 3.2.8")
	h.m.tree.Nodes = h.m.tree.Nodes[:1] // a new tree, one row
	h.mouse(x, y, tea.MouseButtonLeft)
	if len(h.m.sel) != 0 || h.m.full {
		t.Fatal("a click on a row that is gone did something")
	}
}

// TestStubLenses: a server without lenses (404): Servers offers the views that showed them, w goes to the next; once
// the server has them, the lens on screen is the server's; a lens for another screen is loading.
func TestStubLenses(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(160, 40)
	sc := script(h.m.c)
	sc.fail["GET /api/lens"] = &APIError{Status: http.StatusNotFound}
	h.m.c = sc
	h.m.lensData, h.m.lensAPI, h.m.lensFor = nil, false, ""
	delete(h.m.pending, "lens")
	h.key("1")
	if !h.m.lensNone {
		t.Fatal("404: no lenses")
	}
	h.has("show  priorities  logins  network  health  w")
	h.key("w")
	if h.m.lens != "logins" || h.m.view != vAccess {
		t.Fatal(h.m.lens, h.m.view)
	}
	// the server has them now (updated): r asks again, the server's lens replaces the view
	delete(sc.fail, "GET /api/lens")
	h.key("r")
	if h.m.view != vLens || !h.m.lensAPI {
		t.Fatal("the server's lens", h.m.view)
	}
	h.key("G")
	if n := len(h.m.lensData.Rows); n == 0 || h.m.cur[vLens] != n-1 {
		t.Fatal("G: the last row", h.m.cur[vLens])
	}
	h.m.lensFor = "elsewhere"
	h.m.pending["lens"] = h.m.lensKey()
	h.has("loading")
}

// TestHistoryRunning: History lists the scan running in the env and the scans started here above the runs, each
// with its last line.
func TestHistoryRunning(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(140, 40)
	h.m.envd.Live = &liveInfo{State: "running", Hosts: map[string]liveHost{"web-01": {State: "running", Module: "os_packages"}}}
	h.m.jobs.Jobs = []jobInfo{{ID: "j1", State: "running", Request: scanRequest{Org: "acme", Env: "production"}, Output: []string{"first", "web-01: trivy sbom"}},
		{ID: "j0", State: "done", Request: scanRequest{Org: "acme", Env: "production"}, Output: []string{"finished-line"}},
		{ID: "j2", State: "running", Request: scanRequest{Org: "acme", Env: "staging"}}}
	h.key("3")
	h.has("Scan running", "acme/production  web-01: trivy sbom  S output", "acme/staging", "2026-11-02 11:00")
	h.hasNot("finished-line")
}

// TestFirewallRulesRead: the rules the run read, as the card shows them: by name, the empty ones left out.
func TestFirewallRulesRead(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 200)
	card(h)
	sc := script(h.m.c)
	sc.body["GET /api/hostfile"] = `{"firewall_raw": {"nft": "table inet filter {\n}\n", "ufw": "  \n", "iptables": "-P INPUT DROP"}}`
	h.m.c = sc
	h.m.rund.Exposure["web-01"] = map[string]any{"firewall": map[string]any{"readable": true, "has_input_filtering": true}}
	delete(h.m.fwRules, h.m.fwKey("web-01"))
	delete(h.m.pending, "fw")
	h.run(h.m.fetchFirewall())
	if got := h.m.fwRules[h.m.fwKey("web-01")]; got != "## iptables\n-P INPUT DROP\n## nft\ntable inet filter {\n}\n" {
		t.Fatalf("%q", got)
	}
	h.key("G")
	h.has("## iptables", "-P INPUT DROP", "## nft")
	h.hasNot("## ufw")
}

// TestHostCardMore: an authorized key's options; a kernel log class without a key of its own, by its name; a
// health row short of memory.
func TestHostCardMore(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(140, 120)
	rd := h.m.rund
	rd.Access["web-01"] = map[string]any{"keys": []any{map[string]any{"user": "deploy", "type": "ssh-ed25519", "comment": "ci@example.com", "options": `from="192.0.2.0/24"`}}}
	rd.Health["web-01"] = map[string]any{"mem": map[string]any{"available_mb": 40.0, "total_mb": 1000.0},
		"dmesg": map[string]any{"classes": map[string]any{"segfault": map[string]any{"count": 2.0, "last": "app[42]: segfault"}}}}
	card(h)
	h.has(`ci@example.com [from="192.0.2.0/24"]`, "segfault ×2  app[42]: segfault")
	h.key("esc")
	h.show(vHealth)
	h.has("4%")
}

// TestRescanMore: R on an open host card scans that host; on a run that reached every host, or on a read-only
// dashboard, it starts nothing (the latter says why).
func TestRescanMore(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	card(h)
	h.key("R")
	h.eventually("Scans[1]", "acme/production")
	if r := h.scan.requests(); len(r) != 1 || len(r[0].Hosts) != 1 || r[0].Hosts[0] != "web-01" {
		t.Fatalf("%+v", r)
	}
	close(h.scan.release)
	h.waitJob("done")
	h.key("3", "home")
	for i := 0; i < 20 && func() bool { l := h.m.runList(); c := h.m.cur[vRuns]; return c < len(l) && len(l[c].Failed) > 0 }(); i++ {
		h.key("down")
	}
	sc := script(h.m.c)
	h.m.c = sc
	h.key("R")
	if sc.count("POST /api/scan") != 0 {
		t.Fatal("a rescan of no host")
	}
	ro := newHarness(t, Options{Org: "acme", Env: "production"}, false)
	card(ro)
	ro.key("R")
	ro.has("Scans can't be started here (read-only)")
}

// TestScanFormLimits: a limit the org file sets is shown as such and not changed here; another one goes up; when
// the new limits can't be saved, no scan starts with limits the user did not get.
func TestScanFormLimits(t *testing.T) {
	p := fixture(t)
	f := filepath.Join(p.Orgs, "acme.yml")
	b, err := os.ReadFile(f)
	must(t, err)
	must(t, os.WriteFile(f, []byte(strings.Replace(string(b), "access:\n", "access:\n  parallel: 4\n", 1)), 0o644))
	must(t, os.MkdirAll(p.Policy, 0o755))
	must(t, os.WriteFile(filepath.Join(p.Policy, "settings.yml"), []byte("scan: fast\n"), 0o644))
	h := newHarnessAt(t, p, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	h.key("s")
	h.has("4   set in the org file or by a flag", "‹ 2 ›")
	for h.m.form.items[h.m.form.cur].value != "parallel" {
		h.key("down")
	}
	h.key("left")
	h.has("4   set in the org file")
	h.key("down", "right")
	h.has("‹ 3 ›")
	sc := script(h.m.c)
	h.m.c = sc
	h.key("enter")
	if sc.count("POST /api/settings/scan") != 1 || sc.count("POST /api/scan") != 0 || !strings.Contains(h.m.err, "not a mapping") {
		t.Fatalf("saved %d, scans %d, err %q", sc.count("POST /api/settings/scan"), sc.count("POST /api/scan"), h.m.err)
	}
}

// TestSmallScreens: the panel settings cut to a low terminal; a list taller than the screen drawn over what fits;
// the jump palette of an env without runs asks for no trees.
func TestSmallScreens(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(80, 12)
	h.show(vPackages)
	h.key("o")
	h.has("Panels(Packages)", "Layout")
	h.hasNot("due by")
	h.key("esc")
	h.size(80, 8) // the jump list is taller than that
	h.key("2", ":")
	h.has("Jump to")
	h.key("esc")
	s := newHarness(t, Options{Org: "acme", Env: "staging"}, true)
	s.key(":")
	s.has("Jump to")
	if len(s.m.menu.trees) != 0 || s.m.fetchJumpTrees() != nil {
		t.Fatal("trees of an env without runs")
	}
}

// TestRunTotals: a run with totals shows them (over the plan counts of older runs) in the env list and History; a
// form's problems read as one error.
func TestRunTotals(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(140, 40)
	h.m.orgs.Orgs[0].Envs[0].Last.Totals = &totals{P1: 71, P2: 72, P3: 73}
	h.key("E")
	h.has("P1 71", "P2 72", "P3 73")
	h.key("esc")
	h.m.envd.Runs[len(h.m.envd.Runs)-1].Totals = &totals{P1: 81, P2: 82, P3: 83}
	h.key("3")
	h.has("81", "82", "83")
	if c, ok := (*runInfo)(nil).counts(); c != nil || ok {
		t.Fatal("no run: no counts")
	}
	if (&APIError{Status: 400, Errors: []string{"no hosts", "bad line"}}).Error() != "no hosts; bad line" {
		t.Fatal("a form's problems")
	}
}

// TestRawKeptAndTTY: raw JSON in an answer is kept as it came (it is never drawn as such); a terminal passed through
// the frame writer stays readable and closable.
func TestRawKeptAndTTY(t *testing.T) {
	c := Local(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"raw": {"a": "\u001b[2J"}, "s": "x\u001b[2Jy"}`)
	}))
	var out struct {
		Raw json.RawMessage `json:"raw"`
		S   string          `json:"s"`
	}
	must(t, c.Get(context.Background(), "/x", &out))
	if string(out.Raw) != `{"a": "\u001b[2J"}` || out.S != "x[2Jy" {
		t.Fatalf("%s %q", out.Raw, out.S)
	}
	f, err := os.CreateTemp(t.TempDir(), "tty")
	must(t, err)
	_, err = f.WriteString("abc")
	must(t, err)
	_, err = f.Seek(0, io.SeekStart)
	must(t, err)
	w, ok := SyncWriter(f).(io.ReadWriteCloser)
	if !ok {
		t.Fatal("not a terminal any more")
	}
	b := make([]byte, 3)
	if n, err := w.Read(b); err != nil || string(b[:n]) != "abc" {
		t.Fatal(n, err)
	}
	must(t, w.Close())
	if _, err := f.WriteString("x"); err == nil {
		t.Fatal("not closed")
	}
}
