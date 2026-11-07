package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func (h *harness) size(w, ht int) { h.m.Update(tea.WindowSizeMsg{Width: w, Height: ht}) }

func (h *harness) hasNot(parts ...string) {
	h.t.Helper()
	s := h.screen()
	for _, p := range parts {
		if strings.Contains(s, p) {
			h.t.Fatalf("%q on screen:\n%s", p, s)
		}
	}
}

// TestNarrow: on a small terminal the header folds to a line and the least needed columns go, the rest are whole.
func TestNarrow(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("2")
	h.has("Org:", "HOSTS", "DUE BY", "Update OS packages (8)", "<?> help")

	h.size(60, 18)
	h.has("acme/production │ P1 5 P2 12 P3 18 P4 3", "<?> help", "ACTION", "CVE", "Update OS packages (8)")
	h.hasNot("Org:", "HOSTS")
	h.size(40, 18)
	h.has(" acme/production ", "<?> help", "Update OS")
	h.hasNot("DUE BY", "Kanareika", "P1 5")

	h.key("4")
	h.has("PACKAGE", "FIXED IN", "nginx")
	h.hasNot("WHERE", "INSTALLED")

	// a running scan shows in the one-line header too
	h.size(120, 18)
	h.key("s", "enter")
	h.has("running: 1")
	close(h.scan.release)
	h.eventually("done")

	// the full header on 80 columns keeps the gauges and ends its keys with help
	h.size(80, 24)
	h.key("3")
	h.has("Org:", "P1 ■", "44 CVE", "<?> help", "CHART")
}

func TestTooSmall(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(30, 7)
	h.has("30×7 < 40×8", "make the terminal bigger")
	h.size(40, 8)
	h.hasNot("make the terminal bigger")
}

// TestHelpScrolls: on a low terminal the help scrolls; its long lines wrap.
func TestHelpScrolls(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(60, 12)
	h.key("?")
	h.has("1-6, tab", "packages, runs, scans")
	h.hasNot("any key closes this")
	for i := 0; i < 40; i++ {
		h.key("down")
	}
	h.has("any key closes this")
	h.hasNot("1-6, tab")
	h.key("up", "k", "j", "x")
	h.hasNot("any key closes this")
	h.has("To do(")
}

// TestPanels: the panel settings change the header and the columns and are kept for the next session.
func TestPanels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conf", "tui.json")
	h := newHarness(t, Options{Org: "acme", Env: "production", Settings: path}, true)
	h.key("3", "o")
	h.has("Panels(Hosts)", "header: < auto >", "[ ] show P4 too", "[x] OS", "[x] chart")
	h.hasNot("[x] host") // never switched off

	h.key("space") // header: auto -> six lines
	h.has("header: < six lines >")
	h.key("right", "l") // -> one line -> hidden
	h.has("header: < hidden >")
	h.key("left") // back to one line
	h.has("header: < one line >")

	h.key("down", "down", "space") // P4 (past the tabs)
	h.has("[x] show P4 too")
	h.key("down", "down", "space", "down", "x", "k", "up", "up", "up", "up", "up", "up") // OS and P3 off; up stops at the first item
	h.has("[ ] OS", "[ ] P3")
	h.key("esc")
	h.has("Hosts(acme/production)", "CHART", "<?> help")
	h.hasNot("Org:", "OS ", "Debian")
	for _, l := range strings.Split(h.screen(), "\n") {
		if strings.Contains(l, "HOST") && strings.Contains(l, "P3") {
			t.Fatal("P3 column still there: " + l)
		}
	}

	b, err := os.ReadFile(path)
	must(t, err)
	for _, want := range []string{`"header": "compact"`, `"show_p4": true`, `"hosts": [`, `"OS"`, `"P3"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("%s not in the settings:\n%s", want, b)
		}
	}

	// the next session starts with them; P4 shows in the lists
	h2 := newHarness(t, Options{Org: "acme", Env: "production", Settings: path}, true)
	h2.key("3")
	h2.hasNot("Debian", "Org:")
	h2.key("2")
	h2.has(" P4 ")

	// switched back on, the column returns and the view's entry leaves the file
	h2.key("3", "o", "down", "down", "down", "down", "space", "q")
	h2.has("Debian")
	h2.key("p") // P4 off from the Hosts view too
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), `"OS"`) || strings.Contains(string(b), "show_p4") {
		t.Fatalf("settings not updated:\n%s", b)
	}
	h2.key("o", "space", "o") // one line -> hidden header
	h2.hasNot("<?> help", "Org:")
	h2.has("┌")
}

func TestSettingsFile(t *testing.T) {
	if DefaultSettingsPath() == "" {
		t.Fatal("no default settings path")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	must(t, os.WriteFile(bad, []byte(`{"header":"huge","show_p4":true}`), 0o600))
	if s := loadSettings(bad); s.Header != headerAuto || !s.ShowP4 {
		t.Fatalf("%+v", s)
	}
	if s := loadSettings(""); s.Header != headerAuto || s.ShowP4 {
		t.Fatal(s)
	}
	must(t, saveSettings("", Settings{}))

	// can't be written: the error shows, the session goes on
	blocker := filepath.Join(dir, "file")
	must(t, os.WriteFile(blocker, nil, 0o600))
	h := newHarness(t, Options{Org: "acme", Env: "production", Settings: filepath.Join(blocker, "tui.json")}, true)
	h.key("2", "p")
	h.has("not a directory")
}

// TestWideScript: Chinese takes two cells a character; every frame is still exactly the terminal's size.
func TestWideScript(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production", Lang: "zh"}, true)
	for _, sz := range [][2]int{{41, 9}, {61, 18}, {80, 24}, {161, 40}} {
		h.size(sz[0], sz[1])
		for _, k := range []string{"1", "2", "enter", "3", "4", "5", "6", "o", "esc", "?", "x", "s", "esc"} {
			h.key(k)
			h.screen()
		}
	}
	h.size(120, 30)
	h.key("2")
	h.has("组织", "<?>")
}

// TestTabsAndZone: the tab line shows the views and marks the open one; it and the time zone are panel settings
// (z switches the zone directly); run times follow the zone.
func TestTabsAndZone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tui.json")
	h := newHarness(t, Options{Org: "acme", Env: "production", Settings: path, Zone: time.FixedZone("MSK", 3*3600)}, true)
	h.size(120, 30)
	h.key("5")
	h.has(" 1 Organizations ", " 2 To do ", " 5 Runs ", "2026-11-02 14:00") // the run of 11:00 UTC, in MSK
	h.size(44, 20)
	h.has(" 5 Runs ", " 1 ")
	h.hasNot("Organizations ")
	h.size(120, 30)

	h.key("z")
	h.has("2026-11-02 11:00", "times in UTC")
	h.key("2")
	h.has("UTC")
	h.key("o", "down", "down", "down", "space") // the zone from the settings: back to the system's
	h.has("time zone: < system >")
	h.key("up", "up", "space", "esc") // tabs off
	h.hasNot(" 1 Organizations ")
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"no_tabs": true`) || strings.Contains(string(b), `"utc"`) {
		t.Fatalf("%s", b)
	}
	h2 := newHarness(t, Options{Org: "acme", Env: "production", Settings: path, Zone: time.UTC}, true)
	h2.size(120, 30)
	h2.hasNot(" 1 Organizations ")
	h2.size(120, 11) // too low for tabs anyway
	h2.screen()
}

// TestLiveProgress: modules done, counts by state, time spent and left; the host lines say what each is doing.
func TestLiveProgress(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.m.envd.Live = &liveInfo{State: "running", Started: "2026-11-07T11:50:00Z", Hosts: map[string]liveHost{
		"web-01": {State: "ok", Step: 4, Steps: 4}, "db-01": {State: "running", Module: "os_packages", Last: "os_packages: 117 packages", Step: 2, Steps: 4},
		"app-01": {State: "failed", Errors: 2, Step: 1, Steps: 4, Last: "unreachable"}, "new-01": {State: "pending"}}}
	h.size(140, 30)
	h.key("6")
	// web-01 1 + app-01 1 + db-01 (2-0.5)/4 of 4 hosts: 59%; 10 min spent
	h.has("Scan running acme/production", " 59% ", "✓1", "✗1", "▸1", "2/4 hosts", "10m0s", "~6m51s left", " 6 Scans ● ",
		"os_packages", "2/4", "117 packages", "unreachable")
	s := h.screen()
	if strings.Index(s, "db-01") > strings.Index(s, "new-01") || strings.Index(s, "new-01") > strings.Index(s, "app-01") {
		t.Fatalf("running, then waiting, then finished:\n%s", s)
	}
	h.size(44, 24) // the bar goes to a line of its own; the bars per host give way
	h.has("10m0s", " 59% ")
	h.hasNot("MODULES")
	if lastSaid(liveHost{Module: "docker", Last: "docker ..."}) != "" || lastSaid(liveHost{Last: "x"}) != "x" {
		t.Fatal("lastSaid")
	}
	if bar(0.5, 0) != "" || !strings.Contains(bar(2, 3), "███") {
		t.Fatal("bar")
	}
}
