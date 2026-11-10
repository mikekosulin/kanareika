package tui

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/server"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	must(t, filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	}))
}

// fixture: org acme (production with the report fixture's runs, staging empty) — fake addresses only.
func fixture(t *testing.T) config.Paths {
	t.Helper()
	home := t.TempDir()
	b, err := os.ReadFile("../server/testdata/parity/org.yml")
	must(t, err)
	must(t, os.MkdirAll(filepath.Join(home, "orgs"), 0o755))
	must(t, os.WriteFile(filepath.Join(home, "orgs", "acme.yml"), b, 0o644))
	copyTree(t, "../report/testdata/fixture/env/acme-production", filepath.Join(home, "reports", "acme", "production"))
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(home, "no-feeds"))
	return config.PathsAt(home)
}

// scanner: a fake scan that prints and waits for release or cancellation.
type scanner struct {
	mu      sync.Mutex
	reqs    []server.ScanRequest
	release chan struct{}
}

func (s *scanner) run(ctx context.Context, o *config.Org, req server.ScanRequest, out io.Writer) int {
	s.mu.Lock()
	s.reqs = append(s.reqs, req)
	s.mu.Unlock()
	_, _ = io.WriteString(out, "== "+o.ID+" / "+req.Env+"\nplan line\n")
	select {
	case <-ctx.Done():
		return 130
	case <-s.release:
		return 0
	}
}

// writeDBMeta: trivy's DBs as downloaded an hour before the harness's now, the next build far ahead.
func writeDBMeta(cache string) error {
	b := `{"UpdatedAt":"2026-11-07T11:00:00Z","NextUpdate":"2099-01-01T00:00:00Z"}`
	for _, n := range []string{"db", "java-db"} {
		if err := os.MkdirAll(filepath.Join(cache, n), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(cache, n, "metadata.json"), []byte(b), 0o644); err != nil {
			return err
		}
	}
	return nil
}

type harness struct {
	t    *testing.T
	m    *Model
	clip *bytes.Buffer
	scan *scanner
}

func newHarness(t *testing.T, o Options, scans bool) *harness {
	t.Helper()
	return newHarnessAt(t, fixture(t), o, scans)
}

// newHarnessAt: the harness over the working directory p.
func newHarnessAt(t *testing.T, p config.Paths, o Options, scans bool) *harness {
	t.Helper()
	cache := t.TempDir() // never the user's DBs: a current one here, or none for tests that want none
	t.Setenv("TRIVY_CACHE_DIR", cache)
	if os.Getenv("KN_TEST_NO_DB") == "" {
		must(t, writeDBMeta(cache))
	}
	sc := &scanner{release: make(chan struct{})}
	opts := server.Options{Paths: p, Log: log.New(io.Discard, "", 0),
		Prompt: func(_ *config.Org, env string, _ *report.View, ids []string, lang string) string {
			return "TASK " + env + " " + lang + " " + strings.Join(ids, ",")
		}}
	if scans {
		opts.Scan = sc.run
		opts.UpdateDB = func(_ context.Context, out io.Writer) error { // writes what trivy would, at once
			if err := writeDBMeta(os.Getenv("TRIVY_CACHE_DIR")); err != nil {
				return err
			}
			_, err := fmt.Fprintln(out, "trivy db: updated")
			return err
		}
	}
	s, err := server.New(opts)
	must(t, err)
	clip := &bytes.Buffer{}
	o.Client = Local(s.Handler())
	o.Tick = func(time.Duration) tea.Cmd { return nil }
	o.Clip = clip
	if o.Now == nil {
		o.Now = func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }
	}
	if o.Zone == nil {
		o.Zone = time.UTC
	}
	h := &harness{t: t, m: New(o), clip: clip, scan: sc}
	h.m.Update(tea.WindowSizeMsg{Width: 160, Height: 40})
	h.run(h.m.Init())
	if h.m.orgs.Orgs != nil && o.Org != "" {
		h.m.setView(vActions) // most tests are about ToDo; TestServers starts where the TUI does
		h.run(h.m.sync())
	}
	return h
}

// run executes a command and everything it leads to, synchronously (ticks are not followed).
func (h *harness) run(cmd tea.Cmd) {
	for depth := 0; cmd != nil && depth < 20; depth++ {
		msg := cmd()
		switch msg := msg.(type) {
		case tea.BatchMsg:
			for _, c := range msg {
				h.run(c)
			}
			return
		case tickMsg, nil, tea.QuitMsg:
			return
		}
		_, cmd = h.m.Update(msg)
	}
}

func (h *harness) key(keys ...string) {
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "space":
			msg = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")}
		case "down":
			msg = tea.KeyMsg{Type: tea.KeyDown}
		case "up":
			msg = tea.KeyMsg{Type: tea.KeyUp}
		case "tab":
			msg = tea.KeyMsg{Type: tea.KeyTab}
		case "shift+tab":
			msg = tea.KeyMsg{Type: tea.KeyShiftTab}
		case "home":
			msg = tea.KeyMsg{Type: tea.KeyHome}
		case "left":
			msg = tea.KeyMsg{Type: tea.KeyLeft}
		case "right":
			msg = tea.KeyMsg{Type: tea.KeyRight}
		case "ctrl+s":
			msg = tea.KeyMsg{Type: tea.KeyCtrlS}
		case "backspace":
			msg = tea.KeyMsg{Type: tea.KeyBackspace}
		case "pgdown":
			msg = tea.KeyMsg{Type: tea.KeyPgDown}
		case "ctrl+c":
			msg = tea.KeyMsg{Type: tea.KeyCtrlC}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		_, cmd := h.m.Update(msg)
		h.run(cmd)
	}
}

// screen: the frame without colors; every frame must be exactly the terminal's size.
func (h *harness) screen() string {
	h.t.Helper()
	v := h.m.View()
	lines := strings.Split(v, "\n")
	if len(lines) != h.m.h {
		h.t.Fatalf("frame has %d lines, terminal %d", len(lines), h.m.h)
	}
	for i, l := range lines {
		if w := ansi.StringWidth(l); w != h.m.w {
			h.t.Fatalf("line %d is %d cells wide, terminal %d: %q", i, w, h.m.w, ansi.Strip(l))
		}
	}
	return ansi.Strip(v)
}

func (h *harness) has(parts ...string) {
	h.t.Helper()
	s := h.screen()
	for _, p := range parts {
		if !strings.Contains(s, p) {
			h.t.Fatalf("%q not on screen:\n%s", p, s)
		}
	}
}

// eventually: refresh the jobs until the screen shows parts.
func (h *harness) eventually(parts ...string) {
	h.t.Helper()
	for i := 0; i < 200; i++ {
		h.run(h.m.fetchJobs())
		s := h.screen()
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(s, p)
		}
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.has(parts...)
}

func (h *harness) waitJob(state string) {
	h.t.Helper()
	for i := 0; i < 200; i++ {
		h.run(h.m.fetchJobs())
		for _, j := range h.m.jobs.Jobs {
			if j.State == state {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("no job %s: %+v", state, h.m.jobs)
}

func TestBrowse(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.has("ToDo(acme/production)[26] P1 6 • P2 10 • P3 10 • P4 4", "openssl (CentOS Stream 9, X) 3.0.1 → 3.0.10", "group by  server  fix  CVE  g",
		"space select", "? all keys", " acme  production ", "4 hosts", "DB ok", "12:00 UTC")
	h.hasNot("P4 os")
	h.key("p") // P4 too
	h.has("P4 os")
	h.key("p", "enter")
	h.has("Details(openssl (CentOS Stream 9, X) 3.0.1 → 3.0.10)", "WHY P1", "in CISA KEV: exploited in the wild", "due 2026-11-08 · in 1 d",
		"CVE-2026-0002    high   91% KEV openssl issue", "web    2 CentOS Stream 9  ● ready 2 internet-facing", "$ dnf update openssl",
		"node: pkg:os:openssl:3.0.1", "esc back")
	h.key("esc", "1")
	h.has("Servers(acme/production)", "web-01")
	h.show(vPackages)
	h.has("Packages(acme/production)", "nginx", "1.25.5")
	h.key("3")
	h.has("History(acme/production)[5]", "2026-11-02 11:00", "partial")
	// open an older run, then back to the current state
	h.key("G", "enter")
	h.has("ToDo(acme/production@2026-11-01 10:00)", "run 2026-11-01 10:00")
	h.key("3", "c")
	h.has("ToDo(acme/production)[")
	// the environments: another one, no runs yet, with the hints
	h.key("E")
	h.has("Environments", "production  4 hosts", "staging     1 host", "no runs")
	h.key("down", "enter")
	h.has(" acme  staging ", "kanareika scan acme --env staging", "or press <s>", "<enter> checks SSH access", "enter check access, first scan")
	h.key("tab", "tab", "tab", "tab", "tab", "tab", "tab", "tab", "tab", "tab", "tab") // around all views and one more
	h.has(" 1 Servers ", " acme  staging ")
	h.key("?")
	h.has("Hotkeys", "OSC 52", "list_fixes · get_fix")
	h.key("x")
	h.has("Servers(acme/staging)")
}

// TestTree: open and close, the cursor to the parent, grouping, a node's selection covering what is under it.
func TestTree(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("/", "a", "p", "i", "enter") // the api image
	h.has("</api>", "docker api:1.2@sha256:abcd  rebuild: lib1")
	h.key("l")
	h.has("▾ P2 docker", "├ COMPONENTS", "lib1", "RUNS ON")
	h.key("l") // open: l goes in
	if n := h.m.curNode(); n == nil || n.Kind != "section" {
		t.Fatal("l on an open node: its first kid", n)
	}
	h.key("down", "space") // a component, selected; its image is not wholly
	h.has("◐ ▾ P2 docker")
	h.key("h") // to the parent
	if n := h.m.curNode(); n == nil || n.Kind != "image" {
		t.Fatal("h: the parent", n)
	}
	img := h.m.curNode()
	h.key("space", "up") // the image and everything under it
	if !h.m.sel[img.Kids[1].ID] {
		t.Fatal("kids not selected")
	}
	h.has("● ▾ P2 docker", "1 selected")
	h.key("y")
	text := clipText(t, h)
	if !strings.HasPrefix(text, "TASK production en ") {
		t.Fatal(text)
	}
	h.key("h") // close
	h.has("● ▸ P2 docker")
	h.hasNot("COMPONENTS")
	h.key("space")
	if len(h.m.sel) != 0 {
		t.Fatal(h.m.sel)
	}
	// group by CVE, then host, then fix again
	h.key("esc", "g")
	h.has("ToDo(acme/production)[", "CVE-2026-0002", "group by  server  fix  CVE")
	if h.m.by[vActions] != "cve" || h.m.tree.By != "cve" {
		t.Fatal(h.m.by)
	}
	h.key("g")
	h.has("web-01", "CentOS Stream 9")
	if h.m.tree.By != "host" {
		t.Fatal(h.m.tree.By)
	}
	h.key("l", "down")
	h.key("g")
	if h.m.tree.By != "fix" {
		t.Fatal(h.m.tree.By)
	}
	// the cursor stays on its node when the tree is rebuilt
	h.key("down", "down")
	id := h.m.curNode().ID
	h.key("r")
	if h.m.curNode().ID != id {
		t.Fatal("cursor moved on refresh")
	}
}

// TestKidsOnOpen: the tree comes with its top rows only; a row's kids come when it is opened, selected if it is.
func TestKidsOnOpen(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("g") // by CVE
	if !strings.Contains(h.m.treeKey, "levels=0") {
		t.Fatal(h.m.treeKey)
	}
	n := h.m.curNode()
	if n == nil || n.Kind != "cve" || n.More == 0 || len(n.Kids) != 0 {
		t.Fatalf("a CVE row without its kids: %+v", n)
	}
	h.has("○ ▸ "+n.Priority, n.Label)
	h.key("space") // selects it
	if h.m.curNode() != n {
		h.key("up") // the cursor went on to the next row
	}
	h.key("l")
	if n.More != 0 || len(n.Kids) == 0 || !h.m.sel[n.Kids[0].ID] {
		t.Fatalf("opened: kids fetched and selected with it: %+v", n)
	}
	h.has("● ▾ "+n.Priority, n.Kids[0].Label)
	h.key("h")
	if slices.ContainsFunc(h.m.treeRows(), func(r trow) bool { return r.depth > 0 }) {
		t.Fatal("closed: its kids are not rows")
	}
}

// TestFilters: the filter menu (f) and the text filter (/) go to the server; the title says which are on.
func TestFilters(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("f")
	h.has("Filters", "[ ] in CISA KEV", "[ ] fixed by a backport too")
	h.key("space") // KEV
	h.has("[x] in CISA KEV")
	h.key("esc")
	h.has("ToDo(acme/production)[3]", " in CISA KEV ")
	if !strings.Contains(h.m.treeKey, "f=kev") {
		t.Fatal(h.m.treeKey)
	}
	h.key("f", "j", "j", "j", "j", "j", "j", "x", "f") // overdue too (what is overdue depends on the server's clock)
	h.has(" overdue ")
	if !strings.Contains(h.m.treeKey, "kev%2Coverdue") {
		t.Fatal(h.m.treeKey)
	}
	h.key("f", "k", "x", "j", "j", "j", "j", "j", "j", "x", "q")
	h.has("ToDo(acme/production)[26]")
	h.key("/", "k", "e", "r", "n", "e", "l")
	h.has("</kernel_>", "ToDo(acme/production)[2]")
	h.key("backspace", "enter")
	h.has("</kerne>")
	if h.m.typing {
		t.Fatal("still typing")
	}
	h.key("/", "z", "z", "z", "esc")
	if h.m.filter != "" {
		t.Fatal("esc while typing clears")
	}
	h.key("/", "z", "z", "z", "enter")
	h.has("nothing here")
}

func clipText(t *testing.T, h *harness) string {
	t.Helper()
	out := h.clip.String()
	if !strings.HasPrefix(out, "\x1b]52;c;") || !strings.HasSuffix(out, "\a") {
		t.Fatalf("no OSC 52: %q", out)
	}
	text, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(out, "\x1b]52;c;"), "\a"))
	must(t, err)
	h.clip.Reset()
	return string(text)
}

func TestFilterSelectCopy(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("space") // selects the first and moves on
	if len(h.m.picked()) != 1 {
		t.Fatal(h.m.sel)
	}
	h.key("y")
	if text := clipText(t, h); !strings.HasPrefix(text, "TASK production en ") {
		t.Fatal(text)
	}
	h.has("Task copied to the clipboard (1)")
	h.key("a") // all of the list
	if n := len(h.m.picked()); n != 26 {
		t.Fatal(n)
	}
	h.has("26 selected")
	h.key("a")
	if len(h.m.sel) != 0 {
		t.Fatal("a again clears")
	}
	h.key("y") // nothing selected: the node under the cursor
	if clipText(t, h) == "" {
		t.Fatal("cursor node not copied")
	}
	// the context of a node for an agent's chat
	h.key("home", "Y")
	ctx := clipText(t, h)
	for _, want := range []string{"kanareika finding: acme/production (run current)", "node: pkg:os:openssl:3.0.1",
		"what: openssl (CentOS Stream 9, X) 3.0.1 → 3.0.10", "facts: P1, 2 hosts, 2 CVEs, EPSS 91%, in CISA KEV, RCE without login",
		"why: in CISA KEV: exploited in the wild;", "due: due 2026-11-08 · in 1 d", "cve: CVE-2026-0002 HIGH EPSS 91% KEV RCE — openssl issue",
		"where: web (2 hosts, CentOS Stream 9): dead-01, web-01", "apply on CentOS Stream 9 (2 hosts): dnf update openssl", "action ids: ",
		`get_fix org=acme env=production by=fix id="pkg:os:openssl:3.0.1"`} {
		if !strings.Contains(ctx, want) {
			t.Fatalf("%q not in the context:\n%s", want, ctx)
		}
	}
	h.has("Context copied to the clipboard")
	// the command of the details
	h.key("c")
	if clipText(t, h) != "dnf update openssl" {
		t.Fatal("command")
	}
	h.has("Command copied to the clipboard")
	h.key("[", "]")
	h.key("/", "M", "i", "g", "r", "a", "t", "e", "enter", "c")
	h.has("No command to copy for this node")
	h.m.clip = nil
	h.key("y")
	h.has("This terminal session can't copy")
	h.key("Y")
	h.has("This terminal session can't copy")
}

func TestScanFromTUI(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("s")
	h.has("Scan(acme/production)", "Hosts (none selected: all)", "web-01", "os_packages", "dry run")
	h.key("space") // the first host
	for h.m.form.items[h.m.form.cur].value != "dry_run" {
		h.key("down")
	}
	h.key("space", "enter")
	h.eventually("Scans[1]", "acme/production", "running", "plan line")
	h.scan.mu.Lock()
	r := h.scan.reqs[0]
	h.scan.mu.Unlock()
	if r.Org != "acme" || r.Env != "production" || len(r.Hosts) != 1 || r.Hosts[0] != "web-01" || !r.DryRun {
		t.Fatalf("%+v", r)
	}
	h.key("x")
	h.waitJob("cancelled")
	h.has("cancelled")
	// the form: esc leaves it; Start as an item starts too
	h.key("s", "esc")
	if h.m.form != nil {
		t.Fatal("form open")
	}
	h.key("s")
	h.m.form.cur = len(h.m.form.items) - 1
	h.key("space")
	close(h.scan.release)
	h.waitJob("done")
	h.key("S")
	h.has("done")
}

func TestReadOnlyAndLanguages(t *testing.T) {
	h := newHarness(t, Options{Lang: "ru"}, false)
	h.key("O")
	h.has("Организации", "acme")
	h.key("esc")
	h.key("N") // no setup on a read-only dashboard
	if h.m.setup != nil {
		t.Fatal("setup on a read-only dashboard")
	}
	h.key("s")
	h.has("Отсюда сканы не запускаются")
	h.key("S")
	h.has("Отсюда сканы не запускаются")
	h.key("L") // the list of languages, each in its own name, the current one marked
	h.has("Язык", "English", "✓ Русский", "中文")
	h.key("down", "enter")
	h.has("扫描[0]", "此处无法启动扫描")
	// the menu lists every language, English first: from 中文, all the way up to it
	langs := i18n.Langs()
	steps := func(dir string, n int) []string { return slices.Repeat([]string{dir}, n) }
	h.key(append(append([]string{"L"}, steps("up", len(langs)-1)...), "space")...)
	h.has("Scans[0]")
	h.key("L", "j", "esc") // closed without a choice
	h.has("Scans[0]")
	h.key("L", "k", "L")
	h.has("Scans[0]")
	h.key(append(append([]string{"L"}, steps("down", slices.Index(langs, "ru"))...), "enter")...)
	h.has("Сканы[0]")
	if New(Options{Lang: "xx"}).t.lang != "en" {
		t.Fatal("unknown language")
	}
}

// TestSizes: the frame fits any terminal, small ones included.
func TestSizes(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	for _, sz := range [][2]int{{60, 15}, {90, 24}, {120, 30}, {200, 60}} {
		h.m.Update(tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		for v := range nViews {
			h.show(v)
			h.screen()
		}
		h.key("2", "pgdown", "G", "g")
		h.screen()
	}
	if New(Options{}).View() != "" {
		t.Fatal("no size yet: nothing to draw")
	}
}

func TestQuit(t *testing.T) {
	h := newHarness(t, Options{}, true)
	for _, k := range []tea.KeyMsg{{Type: tea.KeyRunes, Runes: []rune("q")}, {Type: tea.KeyCtrlC}} {
		_, cmd := h.m.Update(k)
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Fatal(k)
		}
	}
}

func TestErrorsShow(t *testing.T) {
	m := New(Options{Tick: func(time.Duration) tea.Cmd { return nil }, Client: Local(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = io.WriteString(w, `{"error": "internal error"}`)
	})), Org: "acme"})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 20})
	h := &harness{t: t, m: m}
	h.run(m.Init())
	h.has("internal error")
}

func TestRemoteClient(t *testing.T) {
	s, err := server.New(server.Options{Paths: fixture(t), Token: "tok", Log: log.New(io.Discard, "", 0),
		Scan: (&scanner{release: make(chan struct{})}).run})
	must(t, err)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	ctx := context.Background()
	var orgs orgsResp
	if err := Remote(ts.URL+"/", "wrong").Get(ctx, "/api/orgs", &orgs); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatal(err)
	}
	c := Remote(ts.URL, "tok")
	must(t, c.Get(ctx, "/api/orgs", &orgs))
	if len(orgs.Orgs) != 1 {
		t.Fatal(orgs)
	}
	var started map[string]any
	must(t, c.Post(ctx, "/api/scan", scanRequest{Org: "acme", Env: "staging"}, &started))
	// a stale CSRF token (the server restarted) is refreshed once
	c.(*client).csrf = "stale"
	err = c.Post(ctx, "/api/scan", scanRequest{Org: "acme", Env: "nope"}, nil)
	var ae *APIError
	if !asAPIError(err, &ae) || ae.Status != 400 || !strings.Contains(ae.Error(), "unknown env") {
		t.Fatal(err)
	}
	if (&APIError{Status: 502}).Error() != "HTTP 502" {
		t.Fatal()
	}
	if err := Remote("http://127.0.0.1:1", "").Get(ctx, "/api/orgs", nil); err == nil {
		t.Fatal("nothing listens there")
	}
}

func asAPIError(err error, out **APIError) bool { return errors.As(err, out) }

func TestTexts(t *testing.T) {
	tt := &tr{lang: "ru", ui: i18n.UI(), catalog: map[string]map[string]string{
		"act.x": {"en": "Update {n}", "ru": "Обновить {n} ({what})"},
		"w":     {"en": "pkgs", "ru": "пакеты"},
	}}
	a := action{Title: "Update 2", Msg: "act.x", Args: map[string]any{"n": 2, "what_key": "w"}}
	if got := tt.title(a); got != "Обновить 2 (пакеты)" {
		t.Fatal(got)
	}
	a.Args = map[string]any{"n": 2}
	if got := tt.title(a); got != "Обновить 2 ({what})" {
		t.Fatal(got)
	}
	if tt.title(action{Title: "plain"}) != "plain" || tt.detail(action{Detail: "d"}) != "d" {
		t.Fatal("fallback")
	}
	tt.lang = "en"
	if tt.title(a) != "Update 2" {
		t.Fatal("en uses the server's text")
	}
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{"2026-11-07T11:59:30Z": "just now", "2026-11-07T11:30:00Z": "30 min ago",
		"2026-11-07T09:00:00Z": "3 h ago", "2026-11-04T12:00:00.000000+00:00": "3 d ago", "2026-11-02_110000Z": "—", "": "—"} {
		if got := tt.ago(in, now); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
	if tt.runShort("2026-11-01_204722") != "2026-11-01 20:47" || tt.runShort("current") != "Current state" || tt.runShort("x") != "x" {
		t.Fatal("runShort")
	}
}

// TestLiveScan: a scan running in the env (started anywhere: CLI, web, TUI) shows in the header and in Scans.
func TestLiveScan(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.m.envd.Live = &liveInfo{State: "running", Hosts: map[string]liveHost{
		"web-01": {State: "ok"}, "db-01": {State: "running", Module: "os_packages", Last: "trivy sbom"},
		"app-01": {State: "failed"}, "x-01": {State: "warn"}, "y-01": {State: "pending"}}}
	if !h.m.busy() {
		t.Fatal("busy")
	}
	h.key("S")
	h.has("running 60% · 3/5", "Scan running", "os_packages", "trivy sbom", "3/5")
	h.m.envd.Live.State = "stale"
	h.has("scan not responding")
	h.m.envd.Live = nil
	h.m.jobs.Jobs = []jobInfo{{ID: "a", State: "running", Request: scanRequest{Org: "acme", Env: "production",
		Hosts: []string{"web-01"}, Modules: []string{"os_packages"}}, Output: []string{"x"}}}
	h.has("running: 1", "web-01 os_packages")
	h.m.jobs.Jobs[0].State = "failed"
	h.has("finished with errors")
	h.m.db.FeedsOutdated = false
	h.hasNot("KEV/EPSS old")
	h.m.db.FeedsOutdated = true
	h.has("KEV/EPSS old")
	h.m.orgs.Errors = []string{"bad"}
	h.m.err = ""
	h.has("Config errors: 1")
	// no organizations at all
	h.m.org, h.m.orgs.Orgs, h.m.rund = "", nil, nil
	h.key("2")
	h.has("no organizations", "kanareika org new <id>")
}

// TestFill: a sentence's {name}s filled in its own word order; a {name} without a value stays as written; with a
// style, only the sentence's own words take it.
func TestFill(t *testing.T) {
	if got := fill("hace {n} min", nil, []string{"n", "5"}); got != "hace 5 min" {
		t.Fatal(got)
	}
	if got := fill("{a} and {b}", nil, []string{"a", "x"}); got != "x and {b}" {
		t.Fatal(got)
	}
	upper := lipgloss.NewStyle().Transform(strings.ToUpper) // visible without colors
	if got := fill("press {key} now", &upper, []string{"key", "<s>"}); got != "PRESS <s> NOW" {
		t.Fatalf("%q", got)
	}
}

// TestScanLimitsFromTUI: the scan form shows how many hosts and trivy runs go at once; ←/→ change them, and
// starting the scan saves them for later scans (the form opened again shows the saved value).
func TestScanLimitsFromTUI(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("s")
	h.has("At once (←/→, kept for later scans)", "‹ 8 ›", "‹ 2 ›")
	for h.m.form.items[h.m.form.cur].value != "parallel" {
		h.key("down")
	}
	h.key("left", "left", "space") // space does nothing on a number
	h.has("‹ 6 ›")
	h.key("enter")
	h.eventually("Scans[1]", "acme/production")
	h.key("x")
	h.waitJob("cancelled")
	h.key("s")
	h.eventually("‹ 6 ›", "‹ 2 ›")
}
