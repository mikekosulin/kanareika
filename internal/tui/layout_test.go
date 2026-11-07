package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	h.key("down", "space") // P4
	h.has("[x] show P4 too")
	h.key("down", "space", "down", "x", "k", "up", "up", "up", "up") // OS and P3 off; up stops at the first item
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
	h2.key("3", "o", "down", "down", "space", "q")
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
