package tui

import (
	"strings"
	"testing"
)

// TestJump: the palette (:) finds fixes, CVEs, hosts and views as one types, and goes there.
func TestJump(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key(":")
	h.has("Jump to", "> _", "ToDo", "view")
	h.key("3", ".", "2", ".", "7")
	h.has("rsync 3.2.3 → 3.2.7", "P2 fix")
	h.key("enter")
	if n := h.m.curNode(); n == nil || n.ID != "pkg:os:rsync:3.2.3" {
		t.Fatal("not on the fix", n)
	}
	// a CVE: grouped by CVE, the cursor on it (the filters cleared)
	h.m.flt["kev"] = true
	h.key(":", "C", "V", "E", "-", "2", "0", "2", "6", "-", "0", "0", "2", "1", "enter")
	if n := h.m.curNode(); n == nil || n.ID != "cve:CVE-2026-0021" || h.m.by[vActions] != "cve" || h.m.flt["kev"] {
		t.Fatal("not on the CVE", n, h.m.by)
	}
	h.key(":", "w", "e", "b", "-", "0", "1", "enter")
	h.has("Host(web-01)")
	h.key(":", "R", "u", "n", "s", "enter")
	h.has("Runs(acme/production)")
	// typing, then erasing, moving; nothing found; esc closes
	h.key(":", "z", "z", "backspace", "backspace", "down", "up", "pgdown", "pgup", "tab", "esc")
	if h.m.menu != nil {
		t.Fatal("esc closes")
	}
	h.key(":", "z", "z", "z", "z")
	h.has("nothing here")
	h.key("enter", "esc")
}

// TestOrgsEnvs: O and E list organizations and environments (narrowed by typing) and switch to them; a new
// organization from the list starts the setup.
func TestOrgsEnvs(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	solo(h, "solo")
	h.m.org, h.m.env = "acme", "production"
	h.key("O")
	h.has("Organizations", "acme", "2 environments", "solo", "+ New organization")
	h.key("s", "o", "l", "o")
	h.hasNot("2 environments")
	h.key("enter")
	if h.m.org != "solo" || h.m.env != "default" || !strings.Contains(h.m.toast, "solo: environment all (E: another)") {
		t.Fatal(h.m.org, h.m.env, h.m.toast)
	}
	h.key("O", "down", "down", "enter") // the setup
	h.has("~ kanareika setup")
	h.key("esc", "O", "up", "enter") // acme
	h.has(" acme  production ")
	h.key("E", "s", "t", "a", "enter")
	h.has(" acme  staging ", "No runs yet")
	h.key("E", "esc")
	h.has(" acme  staging ")
}

// TestDetails: the details pane next to the tree on a wide terminal, full screen on enter on a narrow one; it
// scrolls, chooses and copies commands.
func TestDetails(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(100, 30)
	h.hasNot("Details")
	h.key("enter")
	h.has("Details(openssl (CentOS Stream 9, X) 3.0.1 → 3.0.10)", "WHY P1", "APPLY", "↑↓ scroll")
	h.key("down", "j", "pgdown", "home", "up", "k", "pgup", "space")
	h.key("left")
	h.hasNot("WHY P1")
	h.key("enter", "]", "[", "c")
	if clipText(t, h) != "dnf update openssl" {
		t.Fatal("c in the details")
	}
	h.key("y")
	if !strings.HasPrefix(clipText(t, h), "TASK ") {
		t.Fatal("y in the details")
	}
	h.key("esc")
	h.size(160, 40)
	h.has("Details", "WHY P1")
	// a section has no details
	h.key("/", "a", "p", "i", "enter", "l", "down")
	h.has("COMPONENTS")
	h.key("enter")
	if h.m.full {
		t.Fatal("details of a section")
	}
	// hosts grouping: a group's details
	h.key("esc", "g", "g", "enter")
	h.has("Details(", "to fix", "scanned")
}
