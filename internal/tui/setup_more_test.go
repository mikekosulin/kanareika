package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// keyType: keys by their bubbletea type, for the ones key() has no name for (end, delete, ctrl+u).
func (h *harness) keyType(ts ...tea.KeyType) {
	for _, k := range ts {
		_, cmd := h.m.Update(tea.KeyMsg{Type: k})
		h.run(cmd)
	}
}

// scripted: the harness's client with some answers replaced (by path prefix) and every request counted.
type scripted struct {
	Client
	mu    sync.Mutex
	asked map[string]int    // "GET /api/db" -> how many times
	fail  map[string]error  // "GET /api/lens" -> the error it gets
	body  map[string]string // "GET /api/hostfile" -> the JSON it gets
	posts map[string][]any  // what was posted, by path
}

func script(c Client) *scripted {
	return &scripted{Client: c, asked: map[string]int{}, fail: map[string]error{}, body: map[string]string{}, posts: map[string][]any{}}
}

func (s *scripted) answer(method, path string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, _, _ := strings.Cut(path, "?")
	s.asked[method+" "+p]++
	return s.body[method+" "+p], s.fail[method+" "+p]
}

func (s *scripted) Get(ctx context.Context, path string, out any) error {
	body, err := s.answer("GET", path)
	switch {
	case err != nil:
		return err
	case body != "":
		return json.Unmarshal([]byte(body), out)
	}
	return s.Client.Get(ctx, path, out)
}

func (s *scripted) Post(ctx context.Context, path string, body, out any) error {
	s.mu.Lock()
	s.posts[path] = append(s.posts[path], body)
	s.mu.Unlock()
	if _, err := s.answer("POST", path); err != nil {
		return err
	}
	return s.Client.Post(ctx, path, body, out)
}

func (s *scripted) count(req string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked[req]
}

// TestSetupTextEditing: the paste area edits as a text box: the cursor by character, line, line start and end;
// backspace, delete, ctrl+u; enter adds a line there; up and down leave it at its first and last line. A one-line
// field takes a paste on one line and moves on with enter.
func TestSetupTextEditing(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	h.key("N")
	h.focus("hosts")
	h.has("admin@192.0.2.10", "ssh -p 2222 deploy@203.0.113.7") // empty: the examples, the cursor before them
	f := h.m.setup.field("hosts")
	h.typeText("web-1\nweb-22")
	pos := func(want int) {
		t.Helper()
		if f.pos != want {
			t.Fatalf("cursor at %d, want %d in %q", f.pos, want, string(f.val))
		}
	}
	h.click("2 web-22") // a click: the end of that line
	pos(12)
	h.key("up") // to the shorter line above: at its end
	pos(5)
	h.key("left") // on a character: drawn under the cursor
	pos(4)
	h.has("1 web-1", "2 web-22")
	h.key("home")
	pos(0)
	h.key("down", "up") // the same column on the next line and back
	pos(0)
	h.keyType(tea.KeyEnd)
	pos(5)
	h.key("down")
	pos(11)
	h.key("right", "right") // not past the end
	pos(12)
	h.key("down") // the last line: on to the next field
	if h.m.setup.fields[h.m.setup.cur].key != "login" {
		t.Fatal("down from the last line", h.m.setup.fields[h.m.setup.cur].key)
	}
	h.key("shift+tab")
	h.key("up", "home", "up") // the first line: on to the field before
	if h.m.setup.fields[h.m.setup.cur].key != "kind" {
		t.Fatal("up from the first line", h.m.setup.fields[h.m.setup.cur].key)
	}
	h.focus("hosts")
	f.pos = 3
	h.key("backspace")
	h.keyType(tea.KeyDelete)
	if string(f.val) != "we1\nweb-22" {
		t.Fatalf("%q", string(f.val))
	}
	h.key("enter") // a new line at the cursor
	if string(f.val) != "we\n1\nweb-22" {
		t.Fatalf("%q", string(f.val))
	}
	f.pos = len(f.val)
	h.keyType(tea.KeyDelete) // nothing after the cursor
	f.pos = 0
	h.key("backspace") // nothing before it
	if string(f.val) != "we\n1\nweb-22" {
		t.Fatalf("%q", string(f.val))
	}
	h.keyType(tea.KeyCtrlU) // all of it
	if len(f.val) != 0 || f.pos != 0 {
		t.Fatalf("%q", string(f.val))
	}
	h.has("admin@192.0.2.10")
	// a one-line field: a pasted newline is a space, enter goes on to the next field
	h.focus("kind")
	h.key("right") // a client: its name
	h.focus("name")
	h.typeText("Globex\nCorp")
	if v := h.m.setup.value("name"); v != "Globex Corp" {
		t.Fatalf("%q", v)
	}
	h.key("enter")
	if h.m.setup.fields[h.m.setup.cur].key != "consent" {
		t.Fatal("enter in a one-line field", h.m.setup.fields[h.m.setup.cur].key)
	}
}

// TestSetupLogin: what discover found decides the login line: the first key in ~/.ssh when the agent has none, the
// agent's keys when it has some; the key chosen under the login line wins; c closes the fields under it.
func TestSetupLogin(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	h.key("N")
	found := func(f foundResp) { h.run(func() tea.Msg { return foundMsg(f) }) }
	found(foundResp{User: "alice", Keys: []string{"~/.ssh/id_ed25519", "~/.ssh/id_rsa"}})
	h.has("Login  ~/.ssh/id_ed25519 · user alice", "ssh-agent none")
	h.focus("login")
	h.key("enter")
	h.focus("key")
	h.has("(•) ssh-agent  ( ) ~/.ssh/id_ed25519  ( ) ~/.ssh/id_rsa")
	h.key("right", "right")
	h.has("( ) ssh-agent  ( ) ~/.ssh/id_ed25519  (•) ~/.ssh/id_rsa", "Login  ~/.ssh/id_rsa · user alice")
	h.key("x") // not a key of a choice
	if h.m.setup.value("key") != "~/.ssh/id_rsa" {
		t.Fatal(h.m.setup.value("key"))
	}
	// the agent answers with keys: the choice says how many; the chosen key stays
	found(foundResp{User: "alice", Keys: []string{"~/.ssh/id_ed25519", "~/.ssh/id_rsa"}, AgentKeys: 2})
	h.has("( ) ssh-agent (2 keys)", "(•) ~/.ssh/id_rsa", "ssh-agent 2 keys")
	h.key("left", "left")
	h.has("(•) ssh-agent (2 keys)", "Login  ssh-agent · 2 keys · user alice")
	// c closes the login fields: the cursor goes to the login line, which stays
	h.key("c")
	if w := h.m.setup; w.loginOpen || w.fields[w.cur].key != "login" {
		t.Fatalf("open %v, on %s", w.loginOpen, w.fields[w.cur].key)
	}
	h.hasNot("(•) ssh-agent (2 keys)")
	// a wizard without a form (the access check of an env) has no values
	if w := h.m.checkWizard("acme", "staging"); w.value("hosts") != "" || w.field("hosts") != nil {
		t.Fatal("values without a form")
	}
}

// TestSetupPickerEdges: the ~/.ssh/config picker: esc closes it with nothing added; a filter nothing matches says so
// and enter adds nothing; enter with nothing ticked adds the host under the cursor.
func TestSetupPickerEdges(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	h.key("N")
	h.focus("hosts")
	h.key("ctrl+o")
	h.has("[ ] nas", "space toggle")
	h.key("esc")
	if h.m.setup.pick != nil {
		t.Fatal("esc: still open")
	}
	h.key("ctrl+o")
	h.typeText("zzz")
	h.has("~/.ssh/config", "nothing here")
	h.key("enter")
	if h.m.setup.pick != nil || len(h.m.setup.field("hosts").val) != 0 {
		t.Fatal("nothing matched: nothing added")
	}
	h.key("ctrl+o", "down", "enter")
	if v := h.m.setup.value("hosts"); v != "vps" {
		t.Fatalf("the host under the cursor: %q", v)
	}
	h.has("1 vps", "→ root@vps.example.com:2222 from ssh config")
}

// TestSetupSubmitProblems: what the form lacks, what the server refuses (its own words, each line), a server that
// can't be reached; one request at a time, the button busy meanwhile.
func TestSetupSubmitProblems(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	h.key("N", "left", "left") // a company
	h.focus("hosts")
	h.typeText("192.0.2.30")
	h.key("ctrl+s")
	h.has("✗ Name the company.")
	h.focus("kind")
	h.key("right") // Add to ACME: a host it has already
	h.has("(•) Add to ACME Corp")
	h.focus("hosts")
	h.keyType(tea.KeyCtrlU)
	h.typeText("web-01 192.0.2.31")
	h.focus("confirmed")
	h.key("space")
	h.focus("submit")
	h.has("⏎ Check connection")
	h.key("enter")
	h.has("✗ no new hosts to add", `✗ host "web-01" is in acme already, skipped`)
	if h.m.setup.step != 1 || h.m.setup.busy {
		t.Fatal("refused: the form stays")
	}
	// the request on its way: the button spins, a second one is not sent
	cmd := h.m.submit()
	if cmd == nil || h.m.submit() != nil {
		t.Fatal("a second request while the first is on its way")
	}
	h.has("⏎ Check connection  ⠋") // focused: a space more
	h.run(cmd)
	// the server can't be reached: said in the form
	sc := script(h.m.c)
	sc.fail["POST /api/setup/add"] = errors.New("connection refused")
	h.m.c = sc
	h.key("enter")
	h.has("✗ connection refused")
	if h.m.setup.busy {
		t.Fatal("still busy")
	}
}

// TestSetupNewOrgIDs: a client's org is named after the client, with a number when the name is taken and the kind
// when the name has no letters; a company's servers go to the environment and jump host typed under the login line.
func TestSetupNewOrgIDs(t *testing.T) {
	demoSSH(t)
	p := fixture(t)
	h := newHarnessAt(t, p, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	sc := script(h.m.c)
	h.m.c = sc
	sent := func() setupReq {
		t.Helper()
		l := sc.posts["/api/setup"]
		if len(l) == 0 {
			t.Fatal("nothing sent")
		}
		return l[len(l)-1].(setupReq)
	}
	for _, c := range []struct{ name, id string }{{"ACME", "acme-2"}, {"!!!", "client"}} {
		h.key("N", "right") // a client
		h.focus("hosts")
		h.typeText("192.0.2.30")
		h.focus("name")
		h.typeText(c.name)
		h.focus("consent")
		h.typeText("Contract 42")
		h.focus("confirmed")
		h.key("space", "ctrl+s")
		if r := sent(); r.ID != c.id || r.Name != c.name || r.Consent != "Contract 42" || r.Env != "production" {
			t.Fatalf("%s: %+v", c.name, r)
		}
		h.has("Connecting", c.name+" · production")
		h.key("esc", "esc")
	}
	for _, id := range []string{"acme-2", "client"} {
		if _, err := os.Stat(filepath.Join(p.Orgs, id+".yml")); err != nil {
			t.Fatal(err)
		}
	}
	h.key("N", "left", "left") // a company, its environment and jump host
	h.focus("hosts")
	h.typeText("192.0.2.40")
	h.focus("name")
	h.typeText("Initech")
	h.focus("consent")
	h.typeText("Ticket 7")
	h.focus("login")
	h.key("enter")
	h.focus("env")
	h.keyType(tea.KeyCtrlU)
	h.typeText("lab")
	h.focus("jump")
	h.typeText("jumper@203.0.113.10")
	h.focus("confirmed")
	h.key("space", "ctrl+s")
	if r := sent(); r.ID != "initech" || r.Env != "lab" || r.Jump != "jumper@203.0.113.10" {
		t.Fatalf("%+v", r)
	}
	h.has("Connecting", "Initech · lab")
}

// TestSetupAccessCheck: the access check's screen: before the hosts come, when they can't be read, the checks the
// API itself fails; long logins cut, causes grouped with each host's own error where they differ; the keys that
// scroll it; enter does nothing until a host answers.
func TestSetupAccessCheck(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(100, 40)
	m := h.m
	m.setup = m.checkWizard("gone", "production") // an org removed meanwhile
	h.has("Connecting", "loading")
	h.run(m.fetchHosts())
	h.has("✗ unknown org")
	// the checks: the API refuses them; a host the env no longer has gets no answer
	m.err = ""
	w := m.setup
	w.hosts = []hostRef{{name: "web-09", address: "192.0.2.9"}}
	h.run(m.checkAccess(false))
	if r := w.res["web-09"]; r == nil || r.OK || !strings.Contains(r.Error, "unknown org/env") {
		t.Fatalf("%+v", r)
	}
	m.setup = m.checkWizard("acme", "production")
	w = m.setup
	w.hosts = []hostRef{{name: "gone-01", address: "192.0.2.8"}}
	h.run(m.checkAccess(false))
	if r := w.res["gone-01"]; r == nil || r.Error != "no answer" {
		t.Fatalf("%+v", r)
	}
	// what the screen makes of the answers
	long := "a-very-long-host-name-that-goes-on-and-on.example.com"
	w.hosts = []hostRef{{name: "web-01", address: "192.0.2.1", user: "deploy"}, {name: "web-02", address: "192.0.2.2", user: "deploy"},
		{name: "db-01", address: long}, {name: "db-02", address: "192.0.2.4"}}
	w.res = map[string]*checkResult{
		"web-01": {Error: "web-01: ssh: unable to authenticate", Hint: "the server refused the login"},
		"web-02": {Error: "web-02: ssh: handshake failed: no common algorithm", Hint: "the server refused the login"},
		"db-01":  {Error: "timeout"},
		"db-02":  {Error: "timeout"},
	}
	h.has("✗ the server refused the login", "ssh: unable to authenticate", "ssh: handshake failed: no common",
		"fix: ssh-copy-id deploy@192.0.2.1", "✗ timeout", "…", "r Check again")
	h.hasNot(long)
	sc := script(h.m.c)
	h.m.c = sc
	h.key("enter") // nobody answered: nothing to scan
	if w.step != 2 || sc.count("POST /api/scan") != 0 {
		t.Fatal("a scan of no host")
	}
	h.key("down", "down", "j", "up")
	if w.off != 2 {
		t.Fatal("scrolled", w.off)
	}
	h.key("k", "k", "k")
	if w.off != 0 {
		t.Fatal("scrolled past the top", w.off)
	}
}

// TestSetupScanRefused: the first scan refused (one of the env is running already): the button is free again.
func TestSetupScanRefused(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("s", "enter") // a scan of the env, running
	h.eventually("Scans[1]", "running")
	m := h.m
	m.setup = m.checkWizard("acme", "production")
	w := m.setup
	w.hosts = []hostRef{{name: "web-01", address: "192.0.2.1"}}
	w.res = map[string]*checkResult{"web-01": {OK: true, System: "Linux 6.8.0"}}
	h.key("enter")
	if w.busy || w.step != 2 || !strings.Contains(m.err, "already running") {
		t.Fatalf("busy %v step %d err %q", w.busy, w.step, m.err)
	}
	close(h.scan.release)
}

// TestSetupFirstScanScreen: the first scan's output, its last lines only; enter waits for its end; a scan that
// failed says so and still leads to the results.
func TestSetupFirstScanScreen(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(100, 40)
	m := h.m
	m.setup = m.checkWizard("acme", "production")
	m.setup.step, m.setup.job = 3, "j1"
	h.has("First scan", "starting") // the job not listed yet
	var out []string
	for i := range 20 {
		out = append(out, fmt.Sprintf("web-01: line %02d", i))
	}
	m.jobs.Jobs = []jobInfo{{ID: "j1", State: "running", Output: out}}
	h.has("web-01: line 19", "web-01: line 04", "running")
	h.hasNot("web-01: line 03")
	h.key("enter", "x") // still running; not a key here
	if m.setup == nil {
		t.Fatal("left a running scan")
	}
	m.jobs.Jobs[0].State, m.jobs.Jobs[0].Code = "failed", 2
	h.has("⏎ See the results", "finished with errors")
	h.key("enter")
	if m.setup != nil || m.view != vServers {
		t.Fatal("enter: the results")
	}
}

// TestSetupDownloadLine: the vulnerability list's line: nothing before its size is known; asked again while it
// downloads, nothing more is sent; a failed download retried by a click.
func TestSetupDownloadLine(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	h.key("N")
	h.has("vulnerability list 68 MB  ↓ d download")
	h.m.dbSize = nil
	h.m.pending["dbsize"] = "dbsize" // its size on the way
	h.hasNot("vulnerability list")
	h.key("i") // nothing to break down yet
	h.hasNot("Linux packages")
	h.key("i")
	delete(h.m.pending, "dbsize")
	h.run(h.m.fetchDBSize())
	// downloading: d again sends nothing
	sc := script(h.m.c)
	h.m.c = sc
	h.m.db.Updating = true
	h.key("ctrl+d")
	if sc.count("POST /api/db/update") != 0 || !h.m.setup.dlAsked {
		t.Fatal("a second download")
	}
	// failed: d retry, by a click
	h.m.db.Updating, h.m.db.Error = false, "no repository worked"
	h.has("vulnerability list failed  d retry")
	h.click("d retry")
	if sc.count("POST /api/db/update") != 1 || !h.m.dlStart.Equal(h.m.now()) {
		t.Fatal("not retried")
	}
	h.hasNot("failed  d retry")
}

// TestSetupSpinner: while checks or the download run, one spinner frame is due at a time; each frame asks for the
// download's state at most once a second; the paste's preview waits for the typing to stop.
func TestSetupSpinner(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	var ticks []time.Duration
	h.m.every = func(d time.Duration) tea.Cmd { ticks = append(ticks, d); return func() tea.Msg { return nil } }
	h.key("N")
	h.focus("hosts")
	ticks = nil
	h.typeText("192.0.2.10")
	if len(ticks) != 1 || ticks[0] != 250*time.Millisecond || h.m.setup.parsed == nil {
		t.Fatal("the preview after a pause", ticks, h.m.setup.parsed)
	}
	if h.m.spin() != nil {
		t.Fatal("a spinner with nothing running")
	}
	sc := script(h.m.c)
	h.m.c = sc
	h.m.db.Updating = true
	frame := h.m.spin()
	if frame == nil || h.m.spin() != nil {
		t.Fatal("one frame due at a time")
	}
	msg := frame()
	if _, ok := msg.(spinMsg); !ok {
		t.Fatalf("%T", msg)
	}
	_, cmd := h.m.Update(msg)
	if h.m.dbPolled != h.m.now() || !h.m.spinning {
		t.Fatal("the next frame, the state asked", h.m.dbPolled)
	}
	var walk func(c tea.Cmd) // the frame's commands, the download still running
	walk = func(c tea.Cmd) {
		if c == nil {
			return
		}
		switch msg := c().(type) {
		case tea.BatchMsg:
			for _, x := range msg {
				walk(x)
			}
		case dbMsg:
			msg.Updating = true
			h.m.Update(msg)
		}
	}
	walk(cmd)
	if sc.count("GET /api/db") != 1 {
		t.Fatal("the download's state", sc.count("GET /api/db"))
	}
	h.m.Update(spinMsg{}) // the same second: not asked again
	if sc.count("GET /api/db") != 1 {
		t.Fatal("asked twice in a second")
	}
}

// TestSetupAddedElsewhere: servers added to the org on screen: the check is of the env on screen, only the hosts
// just added.
func TestSetupAddedElsewhere(t *testing.T) {
	demoSSH(t)
	p := fixture(t)
	h := newHarnessAt(t, p, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	h.key("N", "left")
	h.has("(•) Add to ACME Corp")
	h.focus("hosts")
	h.typeText("web-05 192.0.2.55")
	h.focus("confirmed")
	h.key("space", "ctrl+s")
	h.has("Connecting", "192.0.2.55")
	if w := h.m.setup; w.env != "production" || len(w.hosts) != 1 || w.hosts[0].name != "web-05" {
		t.Fatalf("%+v", w.hosts)
	}
	b, err := os.ReadFile(filepath.Join(p.Orgs, "acme.yml"))
	must(t, err)
	if !strings.Contains(string(b), "192.0.2.55") {
		t.Fatal("not added")
	}
}

// TestSetupPreview: the paste's preview before discover and the parse have answered (no results yet, the default
// user root), when the parse can't be asked (its error after the lines), and what a pasted ssh config says without a
// line of its own (after the lines too).
func TestSetupPreview(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	h.key("N")
	h.m.found = nil
	h.m.pending["found"] = "found" // discover still on its way
	h.focus("hosts")
	h.typeText("192.0.2.10")
	h.has("1 192.0.2.10", "→ root@192.0.2.10", "Login  no SSH key found · user root")
	h.m.setup.parsed = nil // the parse not answered yet
	h.has("1 192.0.2.10")
	h.hasNot("→ root@192.0.2.10")
	delete(h.m.pending, "found")
	h.run(h.m.fetchFound())
	// pasted ssh config: a host twice, said below the lines
	h.keyType(tea.KeyCtrlU)
	h.typeText("Host a1\n  HostName 192.0.2.1\nHost a1\n  HostName 192.0.2.2")
	h.has("1 Host a1", "→ demo@192.0.2.1", `→ Host "a1" twice, the second skipped · skipped`)
	// the parse can't be asked: why, in its place
	sc := script(h.m.c)
	sc.fail["POST /api/setup/parse"] = errors.New("connection refused")
	h.m.c = sc
	h.typeText("\n192.0.2.3")
	h.has("→ connection refused · skipped")
}
