package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// The less travelled paths: texts without a translation, client failures, odd data, small terminals.

func TestTextFallbacks(t *testing.T) {
	tt := &tr{lang: "ru", catalog: map[string]map[string]string{
		"act.only-en": {"en": "Update {n} {what}"},
		"w":           {"en": "packages"},
	}}
	if got := tt.msg("act.only-en", map[string]any{"n": 2, "what_key": "w"}, "fallback"); got != "Update 2 packages" {
		t.Fatal(got)
	}
	if tt.cat("w") != "packages" || tt.cat("nope") != "nope" {
		t.Fatal("cat fallbacks")
	}
	if str(true) != "yes" || str(false) != "no" {
		t.Fatal("bools")
	}
}

// failing: a handler that answers every request with status and body.
func failing(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func TestClientFailures(t *testing.T) {
	ctx := context.Background()
	ok := Local(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"csrf": "c"}`)
	}))
	if err := ok.Get(ctx, "/api/orgs", nil); err != nil {
		t.Fatal("no answer wanted:", err)
	}
	if err := ok.Get(ctx, "/%zz", nil); err == nil {
		t.Fatal("a bad path requested")
	}
	if err := ok.Post(ctx, "/api/scan", make(chan int), nil); err == nil {
		t.Fatal("a body that is not JSON posted")
	}
	down := Local(failing(500, `{"error": "session store down"}`))
	if err := down.Post(ctx, "/api/scan", nil, nil); err == nil || err.Error() != "session store down" {
		t.Fatal(err)
	}
	cut := &client{base: "http://localhost", do: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(iotest.ErrReader(errors.New("connection reset")))}, nil
	}}
	if err := cut.Get(ctx, "/api/orgs", nil); err == nil || err.Error() != "connection reset" {
		t.Fatal(err)
	}
}

func TestSettingsEdges(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", "")
	if p := DefaultSettingsPath(); p != "" {
		t.Fatal("no config dir, yet", p)
	}
	var s Settings
	s.toggle(vHosts, "OS")
	s.toggle(vHosts, "OS")
	if s.Hidden == nil || len(s.Hidden) != 0 {
		t.Fatalf("a column back on leaves no empty entry: %v", s.Hidden)
	}
}

func TestDefaultTick(t *testing.T) {
	m := New(Options{})
	if _, ok := m.every(time.Millisecond)().(tickMsg); !ok {
		t.Fatal("not a tick")
	}
	var got time.Duration
	m = New(Options{Tick: func(d time.Duration) tea.Cmd { got = d; return nil }})
	m.tick()
	if got != 15*time.Second {
		t.Fatal(got)
	}
	m.envd.Live = &liveInfo{State: "running"}
	m.tick()
	if got != 2*time.Second {
		t.Fatal("busy:", got)
	}
}

func TestMessages(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	// an answer for an env left meanwhile is dropped
	runs := len(h.m.envd.Runs)
	if _, cmd := h.m.Update(envMsg{org: "acme", env: "staging"}); cmd != nil || len(h.m.envd.Runs) != runs {
		t.Fatal("stale env answer used")
	}
	// a run that went away: back to the current state
	h.m.run = "2020-01-01_000000"
	h.run(func() tea.Msg { return envMsg{"acme", "production", h.m.envd} })
	if h.m.run != "current" {
		t.Fatal(h.m.run)
	}
	// the first job opens
	h.m.open = ""
	h.m.Update(jobsMsg{Enabled: true, Jobs: []jobInfo{{ID: "j1", State: "done"}}})
	if h.m.open != "j1" {
		t.Fatal(h.m.open)
	}
	// a tick refreshes
	h.m.orgs = orgsResp{}
	_, cmd := h.m.Update(tickMsg(time.Time{}))
	h.run(cmd)
	if len(h.m.orgs.Orgs) != 1 {
		t.Fatal("not refreshed on tick")
	}
	// a newer DB build: said once, on the first answer
	h.m.db = nil
	d := dbResp{Enabled: true}
	d.DBs = append(d.DBs, struct {
		Name     string `json:"name"`
		Updated  string `json:"updated"`
		Next     string `json:"next_update"`
		Outdated bool   `json:"outdated"`
	}{Name: "db", Updated: "2026-11-01T00:00:00Z", Outdated: true})
	h.m.Update(dbMsg(d))
	h.has("A newer vulnerability DB is out: press U to update")
	// a run's info that cannot be read
	if _, ok := h.m.openRunInfo("2020-01-01_000000")().(errMsg); !ok {
		t.Fatal("no error for a run that is not there")
	}
}

func TestKeysMore(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("h")
	if h.m.view != vOrgs {
		t.Fatal("h: the previous view", h.m.view)
	}
	h.key("enter") // the env already open: just its ToDo
	if h.m.view != vActions || h.m.rund == nil {
		t.Fatal("enter on the open env")
	}
	h.m.runKey = "stale"
	h.key("r")
	if h.m.runKey == "stale" {
		t.Fatal("r reloads the run")
	}
	h.key("G", "k")
	if h.m.cur[vActions] != 11 {
		t.Fatal(h.m.cur[vActions])
	}
	h.key("G", "up", "pgup")
	if h.m.cur[vActions] != 0 {
		t.Fatal(h.m.cur[vActions])
	}
	// select, then unselect the same action
	h.key("space", "up", "space")
	if len(h.m.sel) != 0 {
		t.Fatal(h.m.sel)
	}
	// nothing to copy: no action under the filter
	h.key("/", "z", "z", "z", "enter", "y")
	if h.clip.Len() != 0 {
		t.Fatal("copied nothing as a task")
	}
	h.key("esc")
	h.m.clip = nil
	h.key("y")
	h.has("This terminal session can't copy")
	// P4 from Packages
	h.key("4", "p")
	if !h.m.set.ShowP4 {
		t.Fatal("p in Packages")
	}
	// a host card from Health
	h.key("8", "enter")
	h.has("Host(")
	// the rows of every view a cursor moves in
	for _, v := range viewHotkeys {
		h.key(v, "G")
		if n := h.m.rows(); h.m.cur[h.m.view] != max(n-1, 0) {
			t.Fatalf("view %s: cursor %d of %d", v, h.m.cur[h.m.view], n)
		}
	}
	h.m.view = nViews
	if h.m.rows() != 0 {
		t.Fatal("no such view: no rows")
	}
}

func TestNoRunData(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.m.rund = nil
	for _, v := range []view{vPackages, vNetwork, vHealth} {
		h.m.view = v
		if h.m.rows() != 0 {
			t.Fatal(v)
		}
	}
	h.key("4")
	h.has("Packages(acme/production)[0]")
	h.m.org = ""
	h.key("0")
	h.has("no organizations")
}

func TestScansMore(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(90, 30)
	var out []string
	for i := range 40 {
		out = append(out, fmt.Sprintf("[12:00:01] web-01: line %02d", i))
	}
	h.m.jobs.Jobs = []jobInfo{{ID: "j1", State: "done", Request: scanRequest{Org: "acme", Env: "production"}, Output: []string{"first"}},
		{ID: "j2", State: "running", Request: scanRequest{Org: "acme", Env: "production"}, Output: out}}
	h.m.open = "j1"
	h.key("S", "down", "enter")
	if h.m.open != "j2" {
		t.Fatal(h.m.open)
	}
	s := h.screen()
	if strings.Contains(s, "[12:00:01]") || !strings.Contains(s, "web-01: line 39") || strings.Contains(s, "web-01: line 00") {
		t.Fatalf("the output's tail, without times on a narrow screen:\n%s", s)
	}
	h.key("x") // a job the server does not know
	if h.m.err == "" {
		t.Fatal("no error for a failed cancel")
	}
}

func TestFormMore(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(80, 14)
	h.key("s")
	h.key("space") // the first host
	h.has("[x] ")
	for h.m.form.items[h.m.form.cur].kind != itemModule {
		h.key("down")
	}
	h.key("space")
	for h.m.form.items[h.m.form.cur].value != "ignore_window" {
		h.key("down")
	}
	h.key("space", "down", "space", "down")
	h.has("Start")
	h.key("up")
	r := h.m.form.request()
	if len(r.Hosts) != 1 || len(r.Modules) != 1 || r.DryRun || !r.IgnoreWindow || !r.Offline {
		t.Fatalf("%+v", r)
	}
	h.key("esc")
	h.m.org = ""
	if h.m.openForm() != nil {
		t.Fatal("a form without an env")
	}
}

func TestPanelsScroll(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(80, 12)
	h.key("3", "o")
	for range 12 {
		h.key("down")
	}
	h.has("Panels(Hosts)", "chart")
	h.hasNot("Layout")
}

// solo: an org with one env for all its hosts ("default"), shown as "all".
func solo(h *harness, id string) {
	h.m.orgs.Orgs = append(h.m.orgs.Orgs, orgRow{ID: id, Name: "Example Ltd", Envs: []envRow{{Env: "default", Hosts: 2,
		Last:    &runInfo{RunID: "2026-11-06_100000", PlanCounts: map[string]int{"P1": 7, "P2": 1}},
		Running: &runInfo{RunID: "2026-11-07_110000"}}}})
	h.m.org, h.m.env, h.m.run, h.m.rund = id, "default", "", nil
	h.m.envd = envResp{}
}

func TestDefaultEnv(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 30)
	solo(h, "solo")
	h.key("1")
	h.has("solo", "all", "7", "running", "Example Ltd", "solo   all   organizations", "Env:      all")
	h.key("2")
	h.has("kanareika scan solo", "or press <s>")
	h.hasNot("--env")
	h.set(Settings{Header: headerCompact})
	h.has(" Kanareika │ solo/all")
}

func (h *harness) set(s Settings) { h.m.set = s }

func TestHeaders(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(70, 30)
	h.set(Settings{Header: headerFull})
	h.has("Org:", "P1")
	// compact, with the DB being updated
	h.set(Settings{Header: headerCompact})
	h.m.db.Updating = true
	h.has("DB updating…")
	h.m.db.Updating = false
	// compact, with nothing but where: the help key does not fit
	h.size(40, 20)
	solo(h, "an-organization-with-a-long-identifier")
	if first := strings.Split(h.screen(), "\n")[0]; !strings.Contains(first, "an-organization-with-a-long-identifier") || strings.Contains(first, "help") {
		t.Fatalf("%q", first)
	}
	// no DB answer yet
	h.size(120, 30)
	h.set(Settings{Header: headerFull})
	h.m.db = nil
	h.has("DB:       -")
	// the clock without a zone: UTC
	h.m.t.zone = nil
	h.has("12:00 UTC")
}

func TestNarrowCursor(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(40, 12)
	h.key("G")
	h.has("ToDo(acme/production)")
	if h.m.off[vActions] == 0 {
		t.Fatal("the cursor's row not scrolled into view")
	}
	h.key("/", "o", "p", "e", "n", "s", "s", "l")
	h.has("</openssl~")
	// columns that can't be dropped are all kept, however narrow
	keep, _ := h.m.layout(vActions, []col{{title: "a", width: 30}, {title: "b", width: 30}}, nil, 2)
	if len(keep) != 2 {
		t.Fatal(keep)
	}
	if (col{}).minW() != 12 {
		t.Fatal("default minimum width")
	}
}

func TestOddData(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(160, 50)
	if hostsCell([]string{"web-01", "web-02", "db-01"}) != "web-01, web-02 +1" || stack(map[string]int{}, 0, 10) != "" {
		t.Fatal("cells")
	}
	// hosts with the same counts: by name
	h.m.rund.Hosts = map[string]map[string]int{"web-02": {"P1": 1}, "web-01": {"P1": 1}}
	if l := h.m.hostList(); l[0].name != "web-01" || l[1].name != "web-02" {
		t.Fatal(l)
	}
	// a host card without facts
	if l := h.m.hostCard("web-02", 100); !strings.Contains(ansi.Strip(l[0]), "web-02  ?") {
		t.Fatal(l[0])
	}
	// the open run highlighted, a run still running
	h.m.envd.Runs = append(h.m.envd.Runs, runInfo{RunID: "2026-11-07_110000", State: "running"})
	h.m.run = "2026-11-07_110000"
	h.key("0")
	h.has("running", "2026-11-07 11:00")
	h.m.run = "current"
	// new changes with KEV and RCE; nothing resolved
	h.m.rund.New = &diffSet{Total: 3, Rows: []diffRow{{Host: "web-01", Pkg: "openssl", Priority: "P1", KEV: true, RCE: 1, Count: 3}}}
	h.m.rund.Resolved = nil
	h.key("5")
	h.has("Changes(acme/production)[1]", "+ P1 web-01", "KEV RCE openssl")
	// logins: none accepted; attackers sorted by attempts, users by tries then name
	h.m.rund.Access = map[string]map[string]any{"web-01": {"logins": map[string]any{"attackers": []any{
		map[string]any{"ip": "203.0.113.7", "n": 5.0, "users": []any{[]any{"root", 2.0}, []any{"admin", 2.0}}},
		map[string]any{"ip": "203.0.113.9", "n": 50.0, "users": []any{}}}}}}
	h.key("6")
	h.has("No login data", "admin,root")
	if s := h.screen(); strings.Index(s, "203.0.113.9") > strings.Index(s, "203.0.113.7") {
		t.Fatal("most attempts first")
	}
	h.m.rund.Access["web-01"] = map[string]any{"logins": map[string]any{}}
	h.has("No attempts")
	// a live scan: equal states by name
	h.m.envd.Live = &liveInfo{State: "running", Hosts: map[string]liveHost{"web-02": {State: "running"}, "web-01": {State: "running"}}}
	h.key("S")
	if s := h.screen(); strings.Index(s, "web-02") < strings.Index(s, "web-01") {
		t.Fatal("by name")
	}
	// a language with no name of its own
	h.m.t.ui = maps(h.m.t.ui, "xx")
	h.key("L")
	h.has("xx", "XX")
	h.key("esc")
}

// maps: ui with one more (empty) language.
func maps(ui map[string]map[string]string, lang string) map[string]map[string]string {
	out := map[string]map[string]string{lang: {}}
	for k, v := range ui {
		out[k] = v
	}
	return out
}

func TestRunInfoMore(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("0")
	h.m.runInfo = &runInfoView{id: "2026-11-02_110000"}
	h.has("loading")
	h.m.runInfo.meta = &runMeta{ModuleErrors: map[string][]string{"web-01": {"os_packages: trivy failed"}}}
	h.m.runInfo.log = []string{"== acme / production", "web-01: done"}
	h.has("! web-01", "module error: os_packages: trivy failed", "web-01: done")
	h.m.runInfo.meta = &runMeta{}
	h.has("No errors")
	if !slices.Contains(h.m.languages(), "en") {
		t.Fatal("languages")
	}
}
