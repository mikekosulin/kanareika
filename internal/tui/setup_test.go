package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mikekosulin/kanareika/internal/config"
)

// typeText: runes into the field that has the keyboard (a paste: several at once, newlines too).
func (h *harness) typeText(s string) {
	_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s), Paste: true})
	h.run(cmd)
}

// TestSetup: no organization yet: the form, its problems next to the fields, the org file, the SSH check of every
// host with what to do about failures, then the first scan and ToDo when it ends.
func TestSetup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(home, "no-feeds"))
	h := newHarnessAt(t, config.PathsAt(home), Options{}, true)
	h.size(120, 40)
	h.has("New organization", "organization id", "only reads: it changes nothing", "(•) no", "(•) none",
		"[ ] I am allowed to audit these servers", "Create the organization", "<ctrl+s> create")
	if os.Getenv("ZZS") != "" {
		t.Log("\n" + h.screen())
	}
	// nothing filled in: the server's problems, each at its field
	h.key("ctrl+s")
	h.has("✗ organization id: a-z", "✗ organization name is empty", "✗ SSH user: a login name like audit",
		"✗ say where the permission", "✗ confirm that you are allowed", "✗ no hosts")
	if h.m.setup.cur != 0 {
		t.Fatal("the cursor to the first field with a problem", h.m.setup.cur)
	}
	h.typeText("Demo")
	h.key("backspace", "backspace", "backspace", "backspace")
	h.typeText("demo")
	h.key("enter")
	h.typeText("Demo Ltd")
	h.key("tab", "tab") // env stays production; the hosts
	h.typeText("web-01 127.0.0.1:1\n127.0.0.1:2")
	h.key("up", "home", "end", "left", "right", "down", "down") // in the text area, then out of it
	if h.m.setup.cur != 4 {
		t.Fatal("down from the last line: the next field", h.m.setup.cur)
	}
	h.key("space", "tab") // internet-facing: yes
	h.typeText("audit")
	h.key("tab", "right", "tab", "tab", "tab") // sudo; no key; port 22
	h.typeText("ticket SEC-1")
	h.key("tab", "space", "tab") // confirmed; the button
	if os.Getenv("ZZS") != "" {
		t.Log("\n" + h.screen())
	}
	h.key("enter")
	h.has("Access check(demo/production)", "0 of 2 hosts answered", "connection refused",
		"nothing listens on that port") // 127.0.0.1:1 refuses, :2 too
	if os.Getenv("ZZS") != "" {
		t.Log("\n" + h.screen())
	}
	b, err := os.ReadFile(filepath.Join(home, "orgs", "demo.yml"))
	must(t, err)
	for _, want := range []string{"Demo Ltd", "sudo", "ticket SEC-1", "web-01"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("%q not in the org file:\n%s", want, b)
		}
	}
	h.key("r")
	h.has("hosts answered")
	h.key("enter") // the first scan
	h.has("Scans[1]", "demo/production")
	close(h.scan.release)
	h.waitJob("done")
	if h.m.view != vActions || h.m.firstScan != "" {
		t.Fatal("ToDo after the first scan", h.m.view)
	}
}
