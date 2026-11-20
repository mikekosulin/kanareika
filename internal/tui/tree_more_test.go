package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/mikekosulin/kanareika/internal/i18n"
)

// TestDueText: where a due date comes from, in words: how late or soon by the clock on screen, the clock's start
// and the SLA, CISA's own date; a reason without a start says only what it can.
func TestDueText(t *testing.T) {
	tt := &tr{lang: "en", ui: i18n.UI()}
	for _, c := range []struct {
		d    dueInfo
		want string
	}{
		{dueInfo{Date: "2026-11-05", Why: "first_seen", ClockStart: "2026-10-29", FirstSeen: "2026-10-29"},
			"due 2026-11-05 · overdue 2 d · first seen 2026-10-29, P1 = 7 days"},
		{dueInfo{Date: "2026-11-07", Why: "fix_available", ClockStart: "2026-10-31", FirstSeen: "2026-10-20"},
			"due 2026-11-07 · today · a fix since 2026-10-31, P1 = 7 days · first seen 2026-10-20"},
		{dueInfo{Date: "2026-11-21", Why: "kev", KEVDue: "2026-11-21"}, "due 2026-11-21 · in 14 d · CISA KEV due date 2026-11-21"},
		{dueInfo{Date: "2026-11-21", Why: "published"}, "due 2026-11-21 · in 14 d"}, // no clock start: no SLA to tell
		{dueInfo{Why: "no_fix"}, "no fix yet: the clock starts when there is one"},
		{dueInfo{Date: "2026-11-09", Why: "elsewhere"}, "due 2026-11-09 · in 2 d"},
	} {
		if got := ansi.Strip(dueText(tt, "P1", c.d, "2026-11-07")); got != c.want {
			t.Errorf("%+v:\n got %q\nwant %q", c.d, got, c.want)
		}
	}
}

// TestCells: the tree's small cells: EPSS (under 1 %, one decimal under 10 %), the due date (late, today, soon, far,
// or as written when it is not a date), a component's and a CVE's kind, a group's line.
func TestCells(t *testing.T) {
	for e, want := range map[float64]string{0: "", 0.004: "<1%", 0.042: "4.2%", 0.5: "50%"} {
		if got := epssText(e); got != want {
			t.Errorf("%v: %q", e, got)
		}
	}
	m := New(Options{Now: func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }})
	for due, want := range map[string]string{"soon": "soon", "2026-11-05": "2 d late", "2026-11-07": "today",
		"2026-11-10": "in 3 d", "2027-01-01": "2027-01-01"} {
		if got := ansi.Strip(m.dueCell(due)); got != want {
			t.Errorf("%s: %q", due, got)
		}
	}
	if days("x", "2026-11-07") != 0 {
		t.Error("an unreadable date: no days")
	}
	if ansi.Strip(kindOf(&tnode{Kind: "part", Path: "/app/lib.jar"})) != "lib" || kindOf(&tnode{Kind: "cve", Severity: "BOGUS"}) != "" {
		t.Error("kinds")
	}
	if got := m.nodeText(&tnode{Kind: "group", Label: "web", Hosts: 2, OS: "Debian 12"}, false, false); got != "web  2 hosts · Debian 12" {
		t.Error(got)
	}
	if got := m.nodeText(&tnode{Kind: "group", Hosts: 1}, false, false); got != "—  1 host" {
		t.Error(got)
	}
	if fit("abc", 0, false) != "" {
		t.Error("no room: nothing")
	}
}

// TestServerStates: the Servers tree marks each server's state (✓ clean, – not scanned, ✗ failed), says what a
// clean one has to fix (nothing), and its card says the state, what to fix, a pending reboot.
func TestServerStates(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(160, 40)
	h.key("1")
	h.m.tree = &treeResp{By: "host", Servers: map[string]int{"clean": 1, "partial": 1, "not_scanned": 1}, Nodes: []*tnode{
		{ID: "host:web-01", Kind: "host", Label: "web-01", State: "todo", Priority: "P1", Fixes: 2, Counts: map[string]int{"P1": 1, "P3": 1},
			States: map[string]int{"reboot": 1}, LastScan: "2026-11-07T10:00:00Z"},
		{ID: "host:web-02", Kind: "host", Label: "web-02", State: "clean", LastScan: "2026-11-07T11:00:00Z"},
		{ID: "host:web-03", Kind: "host", Label: "web-03", State: "not_scanned"},
		{ID: "host:web-04", Kind: "host", Label: "web-04", State: "partial", Fixes: 1, Counts: map[string]int{"P2": 1}},
	}}
	h.m.treeKey, h.m.curID = h.m.wantTree(), ""
	h.m.cur[vServers] = 0
	h.has("Servers(acme/production)[4]", "1 ✓", "1 !", "1 –", "✓  web-02      nothing to fix", "–  web-03  not scanned", "not checked",
		"to fix  P1 1 • P3 1", "reboot pending")
	h.key("down", "down")
	h.has("– not scanned")
	h.key("down")
	h.has("! partial", "to fix  P2 1")
}

// TestTreeDetailsMore: the details pane of a fix: its groups, binary packages, why nothing can be installed on some
// hosts, no reasons of its own, CVEs the server left out, a reboot after a command; a click picks a command, a
// second one copies it; a click elsewhere in the pane does nothing; loading until the node comes.
func TestTreeDetailsMore(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(180, 50)
	n := h.m.curNode()
	n.Groups = append(n.Groups[:0], struct {
		Name string `json:"name"`
		N    int    `json:"n"`
	}{"web", 1}, struct {
		Name string `json:"name"`
		N    int    `json:"n"`
	}{"db", 1})
	n.Pkgs = []string{"openssl-libs", "openssl"}
	n.NoFix = map[string]int{"pending": 1, "esm": 2}
	k := h.m.treeKey + "#" + n.ID
	h.m.nodes[k] = &nodeDetail{
		CVEs:  []cveInfo{{ID: "CVE-2026-0002", Severity: "HIGH"}},
		More:  3,
		Where: []whereInfo{{Group: "web", Hosts: []string{"web-01"}, OS: "Debian 12", States: map[string]int{"vendor": 1}}},
		Apply: []applyStep{{OS: "CentOS Stream 9", Hosts: []string{"web-01"}, Command: "dnf update openssl", Reboot: true},
			{OS: "Debian 12", Hosts: []string{"db-01"}, Command: "apt-get install openssl"}},
	}
	h.has("2 groups", "packages: openssl-libs, openssl", "no fix released yet · 1 host", "only with Ubuntu Pro (ESM) · 2 hosts",
		"the priority of its findings", "CVE (4)", "+3 more", "● no fix yet 1", "then reboot")
	x, y := h.where("WHY P1")
	h.mouse(x, y, tea.MouseButtonLeft) // the pane, not a command: nothing
	if h.m.cmdCur != 0 || h.m.full || h.clip.Len() != 0 {
		t.Fatal("a click on the pane did something")
	}
	h.click("Debian 12 · 1 host")
	if h.m.cmdCur != 1 || h.clip.Len() != 0 {
		t.Fatal("the click picks the command", h.m.cmdCur)
	}
	h.click("Debian 12 · 1 host")
	if clipText(t, h) != "apt-get install openssl" {
		t.Fatal("the second click copies it")
	}
	// a reason the TUI has no words for: its code
	h.m.nodes[k].Why = []reason{{Code: "custom-rule"}}
	h.has("● custom-rule")
	// a command with nothing to run: nothing copied
	h.m.nodes[k].Apply = []applyStep{{OS: "Alpine", Hosts: []string{"web-01"}}}
	h.key("c")
	h.has("No command to copy for this node")
	// the node not here yet
	delete(h.m.nodes, k)
	h.m.pending[k] = k
	h.has("loading")
	if h.m.fetchNode(n.ID, nil) != nil {
		t.Fatal("asked again while on its way")
	}
}

// TestTreeEdges: a section is not selected; a node deeper down opened fetches its kids, drawn under the lines of
// its parents; an empty tree takes h, Y and c without a node; the backport filter and the server list's own sort go
// to the server; answers for another tree are dropped.
func TestTreeEdges(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("/", "a", "p", "i", "enter", "l", "down") // the image's first section
	if n := h.m.curNode(); n == nil || n.Kind != "section" {
		t.Fatal(n)
	}
	h.key("space")
	if len(h.m.sel) != 0 {
		t.Fatal("a section selected", h.m.sel)
	}
	// by CVE: a CVE, its image, the image's parts (fetched when opened)
	h.key("g", "l", "down", "l")
	rows := h.m.treeRows()
	if len(rows) < 3 || rows[2].depth != 2 || !strings.HasPrefix(rows[2].prefix, "  ") {
		t.Fatalf("%+v", rows[:min(3, len(rows))])
	}
	img := rows[1].n
	tree := h.m.tree
	// answers for another tree, a node that is not there, one that has its kids already: dropped
	h.m.Update(kidsMsg{key: "elsewhere#kids#x", id: img.ID, d: &treeResp{}})
	h.m.Update(kidsMsg{key: h.m.treeKey + "#kids#nope", id: "nope", d: &treeResp{Nodes: []*tnode{{ID: "x"}}}})
	h.m.Update(kidsMsg{key: h.m.treeKey + "#kids#" + img.ID, id: img.ID, d: &treeResp{}})
	h.m.Update(treeMsg{key: "elsewhere", d: &treeResp{}})
	if h.m.tree != tree || len(img.Kids) == 0 {
		t.Fatal("a stale answer taken")
	}
	// nothing in the tree: h stays, Y and c have no node
	h.key("/", "z", "z", "z", "enter", "h", "Y", "c")
	if h.m.view != vActions || h.clip.Len() != 0 {
		t.Fatal("h, Y, c without a node", h.m.view)
	}
	h.has("No command to copy for this node")
	h.key("/", "backspace", "backspace", "backspace", "enter")
	// the backport filter goes as its own parameter
	h.key("f")
	for h.m.menuItems(h.m.menu)[h.m.menu.cur].id != "backported" {
		h.key("down")
	}
	h.key("space", "esc")
	if !strings.Contains(h.m.treeKey, "backported=1") {
		t.Fatal(h.m.treeKey)
	}
	// the server list sorts by its own columns
	h.key("1", "t")
	if h.m.sort[vServers] != "fixes" {
		t.Fatal(h.m.sort[vServers])
	}
	h.has("fixes ↓")
	// no tree yet: loading
	h.m.tree = nil
	h.m.pending["tree"] = h.m.wantTree()
	h.has("loading")
}
