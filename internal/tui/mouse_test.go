package tui

import (
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/mikekosulin/kanareika/internal/config"
)

// where: the cell of the first occurrence of text on screen (the frame just drawn).
func (h *harness) where(text string) (int, int) {
	h.t.Helper()
	for y, l := range strings.Split(h.screen(), "\n") {
		if i := strings.Index(l, text); i >= 0 {
			return ansi.StringWidth(l[:i]), y
		}
	}
	h.t.Fatalf("%q not on screen:\n%s", text, h.screen())
	return 0, 0
}

func (h *harness) mouse(x, y int, b tea.MouseButton) {
	_, cmd := h.m.Update(tea.MouseMsg{X: x, Y: y, Button: b, Action: tea.MouseActionPress})
	h.run(cmd)
}

// click: a left click on text (at its first cell, or dx cells into it).
func (h *harness) click(text string, dx ...int) {
	h.t.Helper()
	x, y := h.where(text)
	if len(dx) > 0 {
		x += dx[0]
	}
	h.mouse(x, y, tea.MouseButtonLeft)
}

func (h *harness) wheel(text string, down bool) {
	h.t.Helper()
	x, y := h.where(text)
	b := tea.MouseButtonWheelUp
	if down {
		b = tea.MouseButtonWheelDown
	}
	h.mouse(x, y, b)
}

// TestMouseTree: tabs, the grouping, rows (the check, the caret, a second click for the details), the details pane
// with its commands and wheel, on a wide terminal and on a narrow one.
func TestMouseTree(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(160, 40)
	h.click("1 Servers")
	if h.m.view != vServers {
		t.Fatal("tab", h.m.view)
	}
	h.click("2 ToDo")
	h.click(" CVE ")
	if h.m.by[vActions] != "cve" {
		t.Fatal("group by", h.m.by)
	}
	h.click(" fix ")
	h.has("openssl (CentOS Stream 9, X) 3.0.1 → 3.0.10")
	// a row: the cursor there; the check selects; the caret opens
	h.click("kernel-modules")
	if n := h.m.curNode(); n == nil || !strings.HasPrefix(n.ID, "pkg:os:kernel-modules") {
		t.Fatal("cursor", n)
	}
	row, y := h.where("○ ▸ P1 os     kernel-modules")
	x := row + 20
	h.mouse(row, y, tea.MouseButtonLeft) // ○
	if len(h.m.picked()) != 1 {
		t.Fatal("check", h.m.sel)
	}
	h.mouse(row+2, y, tea.MouseButtonLeft) // ▸
	h.has("● ▾ P1 os     kernel-modules")
	h.mouse(row+2, y, tea.MouseButtonLeft)
	h.has("● ▸ P1 os     kernel-modules")
	// the details pane: its commands, the copy, the wheel
	h.click("openssl (CentOS Stream 9, X) 3.0.1 → 3.0.10")
	h.has("$ dnf update openssl", "c copy")
	h.click("$ dnf update openssl") // the chosen one: copied
	if clipText(t, h) != "dnf update openssl" {
		t.Fatal("click on the chosen command")
	}
	h.click("c copy")
	if clipText(t, h) != "dnf update openssl" {
		t.Fatal("copy")
	}
	h.size(160, 16)
	h.wheel("WHY P1", true)
	if h.m.detOff == 0 {
		t.Fatal("wheel over the details pane")
	}
	h.wheel("Details", false)
	h.size(160, 40)
	// the wheel over the list moves the cursor; a second click on the cursor's row opens the details
	h.mouse(x, y, tea.MouseButtonWheelDown)
	if h.m.cur[vActions] < 3 {
		t.Fatal("wheel", h.m.cur[vActions])
	}
	h.size(100, 30)
	h.click("openssl (CentOS Stream 9, X) 3.0.1 → 3.0.10")
	h.click("openssl (CentOS Stream 9, X) 3.0.1 → 3.0.10")
	h.has("Details(openssl (CentOS Stream 9, X) 3.0.1 → 3.0.10)")
	h.wheel("WHY P1", true)
	h.wheel("APPLY", false)
	h.size(160, 40)
	h.click("esc back") // a key hint: what its key does
	if h.m.full {
		t.Fatal("hint")
	}
	// a click where nothing is: nothing happens
	h.mouse(150, 0, tea.MouseButtonLeft)
	h.mouse(1, 1, tea.MouseButtonRight)
	h.click("? all keys")
	h.has("Hotkeys", "Shift+drag")
	h.wheel("Hotkeys", true)
	if h.m.helpOff == 0 {
		t.Fatal("wheel in the help")
	}
}

// TestMouseBars: the status bar opens the org and env lists, a click picks an item, outside closes; the filters toggle
// by click; the DB update starts from the status bar; the mouse can be turned off.
func TestMouseBars(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production", Settings: filepath.Join(t.TempDir(), "tui.json")}, true)
	h.size(160, 40)
	h.click(" acme ")
	h.has("Organizations")
	h.mouse(0, 20, tea.MouseButtonLeft) // outside: closed
	if h.m.menu != nil {
		t.Fatal("click outside")
	}
	h.click(" production ")
	h.has("Environments")
	h.wheel("Environments", true)
	h.click("staging     1 host")
	if h.m.env != "staging" {
		t.Fatal("env", h.m.env)
	}
	h.click(" acme  staging ", 7)
	h.click("production  4 hosts")
	h.key("f")
	h.click("[ ] in CISA KEV")
	h.has("[x] in CISA KEV")
	h.click("Filters") // inside, not on an item: open
	if h.m.menu == nil || !h.m.flt["kev"] {
		t.Fatal("filters", h.m.flt)
	}
	h.key("esc")
	// a newer DB: a click updates it, as U
	h.m.db.DBs[0].Outdated = true
	h.click("newer DB out")
	h.has("Updating vulnerability DBs")
	// the mouse off (o): clicks do nothing; the setting is kept
	h.key("o", "down", "down", "space")
	if !h.m.set.NoMouse {
		t.Fatal("mouse setting")
	}
	if _, ok := h.m.mouseCmd()().(tea.MouseMsg); ok {
		t.Fatal("mouse command")
	}
	h.key("esc")
	h.click("1 Servers")
	if h.m.view != vActions {
		t.Fatal("a click with the mouse off")
	}
}

// TestMouseSetup: the setup by mouse: whose servers, fields, the check box, the picker, the button, the download,
// the access check's actions.
func TestMouseSetup(t *testing.T) {
	demoSSH(t)
	home := t.TempDir()
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(home, "no-feeds"))
	h := newHarnessAt(t, config.PathsAt(home), Options{}, true)
	h.size(120, 40)
	h.click("( ) Company")
	h.has("(•) Company", "Permission")
	h.click("Company  ACME")
	if f := h.m.setup.fields[h.m.setup.cur]; f.key != "name" {
		t.Fatal("focus", f.key)
	}
	h.click("( ) Personal")
	h.click("ctrl+o")
	h.click("[ ] nas")
	h.has("[x] nas")
	h.mouse(110, 30, tea.MouseButtonLeft) // outside: closed, nothing added
	if h.m.setup.pick != nil || len(h.m.setup.field("hosts").val) != 0 {
		t.Fatal("picker")
	}
	h.click("Servers   One per line")
	h.typeText("admin@192.0.2.10\nnas")
	h.click("1 admin@192.0.2.10")
	if f := h.m.setup.field("hosts"); f.pos != len("admin@192.0.2.10") {
		t.Fatal("cursor in the field", f.pos)
	}
	h.click("c change")
	h.click("(•) ssh-agent")
	h.has("User")
	h.click("[ ] I’m allowed")
	h.has("[x] I’m allowed")
	h.click("↓ d download")
	h.has("vulnerability list ")
	h.click("⏎ Check connection")
	h.has("Connecting")
	h.click("r Check again")
	h.has("Connecting")
	h.click("esc Back")
	if h.m.setup.step != 1 {
		t.Fatal("back")
	}
}
