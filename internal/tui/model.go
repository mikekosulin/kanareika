package tui

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mikekosulin/kanareika/internal/i18n"
)

type view int

const (
	vOrgs view = iota
	vActions
	vHosts
	vPackages
	vChanges
	vAccess
	vNetwork
	vHealth
	vExceptions
	vRuns
	vScans
	nViews
)

// viewNames: tab titles (English keys of the web page's translations where it has them).
var viewNames = [nViews]string{"Organizations", "ToDo", "Hosts", "Packages", "Changes", "Access", "Network", "Health",
	"Exceptions", "Runs", "Scans"}

// viewHotkeys: the key of each view: 1-9, 0, then S.
var viewHotkeys = [nViews]string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "S"}

// Options of a TUI session.
type Options struct {
	Client Client
	Lang   string    // "": English
	Org    string    // preselect
	Env    string    // preselect
	Clip   io.Writer // where the OSC 52 clipboard sequence goes (the terminal); nil: no copying
	Now    func() time.Time
	Tick   func(time.Duration) tea.Cmd // the refresh timer; nil: tea.Tick (tests stop it)
	// Settings: the file the panel layout is kept in (DefaultSettingsPath); "": not kept.
	Settings string
	Zone     *time.Location // the system's time zone; nil: time.Local (tests fix it)
}

// Model: the bubbletea model of the whole interface.
type Model struct {
	c     Client
	t     *tr
	now   func() time.Time
	every func(time.Duration) tea.Cmd
	clip  io.Writer

	w, h int
	view view

	orgs   orgsResp
	org    string
	env    string
	run    string // "current", a run id, or "" (no runs)
	envd   envResp
	rund   *runResp
	runKey string // org/env/run/last-run the run data is for
	jobs   jobsResp
	scanOK bool
	db     *dbResp // nil until the first answer
	loaded bool

	cur     [nViews]int
	off     [nViews]int
	filter  string
	typing  bool // the filter line has the keyboard
	set     Settings
	setPath string
	sysZone *time.Location
	sel     map[string]bool // selected action ids
	onlySel bool            // ToDo lists only the selected actions (v)
	detail  bool
	help    bool
	helpOff int
	host    string // the host whose card the Hosts view shows ("" = the list)
	hostOff int
	// outsideOnly: the Network view lists only ports open to the outside
	outsideOnly bool
	runInfo     *runInfoView // errors and log of one run (i in Runs)
	panels      *panelsDlg
	langs       *panelsDlg // the language list (L)
	form        *scanForm
	open        string // job whose output the Scans view shows

	toast   string
	toastAt time.Time
	err     string
}

// New builds the model.
func New(o Options) *Model {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Tick == nil {
		o.Tick = func(d time.Duration) tea.Cmd { return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) }) }
	}
	if o.Zone == nil {
		o.Zone = time.Local
	}
	m := &Model{c: o.Client, now: o.Now, every: o.Tick, clip: o.Clip, org: o.Org, env: o.Env, view: vActions, sel: map[string]bool{},
		t: &tr{lang: "en", ui: i18n.UI()}, set: loadSettings(o.Settings), setPath: o.Settings, sysZone: o.Zone}
	m.applyZone()
	if o.Lang != "" && (o.Lang == "en" || m.t.ui[o.Lang] != nil) {
		m.t.lang = o.Lang
	}
	if o.Org == "" {
		m.view = vOrgs
	}
	return m
}

// --- messages -----------------------------------------------------------------------------------------------------

type (
	orgsMsg orgsResp
	envMsg  struct {
		org, env string
		d        envResp
	}
	runMsg struct {
		key string
		d   *runResp
	}
	jobsMsg    jobsResp
	dbMsg      dbResp
	i18nMsg    i18nResp
	errMsg     struct{ err error }
	tickMsg    time.Time
	toastMsg   string
	optsMsg    scanOptions
	startedMsg struct{ id string }
)

const timeout = 60 * time.Second

func (m *Model) get(path string, wrap func(any) tea.Msg, out any) tea.Cmd {
	c := m.c
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := c.Get(ctx, path, out); err != nil {
			return errMsg{err}
		}
		return wrap(out)
	}
}

func (m *Model) fetchOrgs() tea.Cmd {
	return m.get("/api/orgs", func(v any) tea.Msg { return orgsMsg(*v.(*orgsResp)) }, &orgsResp{})
}

func (m *Model) fetchEnv() tea.Cmd {
	if m.org == "" || m.env == "" {
		return nil
	}
	org, env := m.org, m.env
	return m.get("/api/env?org="+url.QueryEscape(org)+"&env="+url.QueryEscape(env),
		func(v any) tea.Msg { return envMsg{org, env, *v.(*envResp)} }, &envResp{})
}

func (m *Model) fetchRun(key string) tea.Cmd {
	q := "/api/run?org=" + url.QueryEscape(m.org) + "&env=" + url.QueryEscape(m.env) + "&run=" + url.QueryEscape(m.run)
	return m.get(q, func(v any) tea.Msg { return runMsg{key, v.(*runResp)} }, &runResp{})
}

func (m *Model) fetchJobs() tea.Cmd {
	return m.get("/api/jobs", func(v any) tea.Msg { return jobsMsg(*v.(*jobsResp)) }, &jobsResp{})
}

func (m *Model) fetchI18n() tea.Cmd {
	return m.get("/api/i18n", func(v any) tea.Msg { return i18nMsg(*v.(*i18nResp)) }, &i18nResp{})
}

func (m *Model) fetchDB() tea.Cmd {
	return m.get("/api/db", func(v any) tea.Msg { return dbMsg(*v.(*dbResp)) }, &dbResp{})
}

func (m *Model) refresh() tea.Cmd {
	return tea.Batch(m.fetchOrgs(), m.fetchEnv(), m.fetchJobs(), m.fetchDB())
}

// dbAttention: the DBs need an update (one is missing, or a newer build is out); "" when they don't.
func (m *Model) dbAttention() string {
	if m.db == nil {
		return ""
	}
	for _, d := range m.db.DBs {
		if d.Updated == "" && d.Name == "db" {
			return "missing"
		}
	}
	for _, d := range m.db.DBs {
		if d.Outdated {
			return "outdated"
		}
	}
	return ""
}

func (m *Model) onDB(d dbResp) tea.Cmd {
	was, first := m.db != nil && m.db.Updating, m.db == nil
	m.db = &d
	switch {
	case was && !d.Updating && d.Error != "":
		m.err = m.t.T("DB update failed") + ": " + d.Error
	case was && !d.Updating:
		m.say(m.t.T("Vulnerability DBs updated"))
		m.runKey = "" // the current state is rebuilt with them on the next look
		return m.refresh()
	case first && d.Enabled && m.dbAttention() == "missing":
		m.say(m.t.T("No vulnerability DB yet: press U to download it"))
	case first && d.Enabled && m.dbAttention() == "outdated":
		m.say(m.t.T("A newer vulnerability DB is out: press U to update"))
	}
	return nil
}

// updateDB: U — check for newer DBs and download them (what kanareika db update does).
func (m *Model) updateDB() tea.Cmd {
	if m.db != nil && !m.db.Enabled {
		m.say(m.t.T("DB updates are off here (read-only)"))
		return nil
	}
	if m.db != nil && m.db.Updating {
		return nil
	}
	fetch := m.fetchDB()
	return m.post("/api/db/update", nil, func(any) tea.Msg {
		return tea.BatchMsg{fetch, func() tea.Msg { return toastMsg(m.t.T("Updating vulnerability DBs…")) }}
	})
}

// busy: a scan is running here or in the selected env (refresh more often).
func (m *Model) busy() bool {
	if m.envd.Live != nil && m.envd.Live.State == "running" || m.db != nil && m.db.Updating {
		return true
	}
	return slices.ContainsFunc(m.jobs.Jobs, func(j jobInfo) bool { return j.State == "running" })
}

func (m *Model) tick() tea.Cmd {
	d := 15 * time.Second
	if m.busy() {
		d = 2 * time.Second
	}
	return m.every(d)
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.fetchI18n(), m.refresh(), m.tick())
}

func (m *Model) say(s string) { m.toast, m.toastAt = s, m.now() }

// --- update -------------------------------------------------------------------------------------------------------

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case i18nMsg:
		m.t.catalog = msg.Messages
	case orgsMsg:
		return m, m.onOrgs(orgsResp(msg))
	case envMsg:
		if msg.org != m.org || msg.env != m.env {
			return m, nil // an answer for a selection left meanwhile
		}
		return m, m.onEnv(msg.d)
	case runMsg:
		if msg.key == m.wantKey() {
			m.rund, m.runKey, m.err = msg.d, msg.key, ""
		}
	case dbMsg:
		return m, m.onDB(dbResp(msg))
	case jobsMsg:
		was := m.busy()
		m.jobs, m.scanOK = jobsResp(msg), msg.Enabled
		if m.open == "" && len(m.jobs.Jobs) > 0 {
			m.open = m.jobs.Jobs[0].ID
		}
		if was && !m.busy() {
			return m, m.refresh() // a scan just ended: its results
		}
	case tickMsg:
		return m, tea.Batch(m.refresh(), m.tick())
	case errMsg:
		m.err = msg.err.Error()
	case toastMsg:
		m.say(string(msg))
	case optsMsg:
		m.form = newForm(m.org, m.env, scanOptions(msg))
	case runInfoMsg:
		if m.runInfo != nil && m.runInfo.id == msg.id {
			m.runInfo.meta, m.runInfo.log = msg.meta, msg.log
		}
	case startedMsg:
		m.form, m.open, m.view = nil, msg.id, vScans
		m.say(m.t.T("Scan started"))
		return m, m.fetchJobs()
	case tea.KeyMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m *Model) onOrgs(o orgsResp) tea.Cmd {
	m.orgs, m.loaded = o, true
	if i := slices.IndexFunc(m.orgs.Orgs, func(x orgRow) bool { return x.ID == m.org }); i < 0 {
		m.org, m.env = "", ""
		if len(m.orgs.Orgs) > 0 {
			m.org = m.orgs.Orgs[0].ID
		}
	}
	if o := m.orgRow(); o != nil && !slices.ContainsFunc(o.Envs, func(e envRow) bool { return e.Env == m.env }) {
		m.env = ""
		if len(o.Envs) > 0 {
			m.env = o.Envs[0].Env
		}
	}
	if m.envd.Runs == nil {
		return m.fetchEnv()
	}
	return nil
}

func (m *Model) orgRow() *orgRow {
	for i := range m.orgs.Orgs {
		if m.orgs.Orgs[i].ID == m.org {
			return &m.orgs.Orgs[i]
		}
	}
	return nil
}

// lastDone: the newest finished run of the env ("" for none).
func (m *Model) lastDone() string {
	for i := len(m.envd.Runs) - 1; i >= 0; i-- {
		if m.envd.Runs[i].State == "done" {
			return m.envd.Runs[i].RunID
		}
	}
	return ""
}

// wantKey: what the run data on screen should be for (a new run changes "current").
func (m *Model) wantKey() string { return m.org + "/" + m.env + "/" + m.run + "/" + m.lastDone() }

func (m *Model) onEnv(d envResp) tea.Cmd {
	m.envd = d
	last := m.lastDone()
	switch {
	case last == "":
		m.run = ""
	case m.run == "" || m.run != "current" && !slices.ContainsFunc(d.Runs, func(r runInfo) bool { return r.RunID == m.run }):
		m.run = "current"
	}
	if m.run == "" {
		m.rund, m.runKey = nil, ""
		return nil
	}
	if key := m.wantKey(); key != m.runKey {
		return m.fetchRun(key)
	}
	return nil
}

// selectEnv switches org/env and shows its current state.
func (m *Model) selectEnv(org, env string) tea.Cmd {
	if org == m.org && env == m.env {
		return nil
	}
	m.org, m.env, m.run = org, env, ""
	m.envd, m.rund, m.runKey = envResp{}, nil, ""
	m.sel = map[string]bool{}
	m.cur, m.off = [nViews]int{}, [nViews]int{}
	return m.fetchEnv()
}

// latin: keys typed with another keyboard layout, as the same keys on a QWERTY one (й -> q, о -> j): the
// hotkeys work whatever layout is on. Text (the filter) is never mapped.
var latin = func() map[rune]rune {
	m := map[rune]rune{}
	for _, p := range [][2]string{
		{"йцукенгшщзхъфывапролджэячсмитьбю.ё", "qwertyuiop[]asdfghjkl;'zxcvbnm,./`"},
		{"ЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮ,Ё", "QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?~"},
	} {
		from, to := []rune(p[0]), []rune(p[1])
		for i := range from {
			m[from[i]] = to[i]
		}
	}
	return m
}()

func (m *Model) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if !m.typing && k.Type == tea.KeyRunes && len(k.Runes) == 1 {
		if r, ok := latin[k.Runes[0]]; ok {
			k.Runes = []rune{r}
		}
	}
	s := k.String()
	if s == "ctrl+c" {
		return m, tea.Quit
	}
	if m.form != nil {
		return m, m.formKey(s)
	}
	if m.panels != nil {
		m.panelsKey(s)
		return m, nil
	}
	if m.langs != nil {
		m.langKey(s)
		return m, nil
	}
	if m.runInfo != nil && m.view == vRuns && !m.typing && !m.help {
		m.runInfoKey(s)
		return m, nil
	}
	if m.typing {
		switch s {
		case "enter":
			m.typing = false
		case "esc":
			m.typing, m.filter = false, ""
		case "backspace":
			if r := []rune(m.filter); len(r) > 0 {
				m.filter = string(r[:len(r)-1])
			}
		default:
			if len(k.Runes) > 0 {
				m.filter += string(k.Runes)
			}
		}
		m.cur[m.view], m.off[m.view] = 0, 0
		return m, nil
	}
	if m.host != "" && m.view == vHosts && !m.typing && m.form == nil && m.panels == nil && !m.help {
		switch s {
		case "up", "k":
			m.hostOff = max(m.hostOff-1, 0)
			return m, nil
		case "down", "j":
			m.hostOff++
			return m, nil
		case "pgup", "ctrl+b":
			m.hostOff = max(m.hostOff-m.page(), 0)
			return m, nil
		case "pgdown", "ctrl+f", "space", " ":
			m.hostOff += m.page()
			return m, nil
		case "home", "g":
			m.hostOff = 0
			return m, nil
		case "end", "G":
			m.hostOff = 1 << 30
			return m, nil
		case "esc", "enter", "backspace":
			m.host, m.hostOff = "", 0
			return m, nil
		}
	}
	if m.help {
		switch s {
		case "up", "k":
			m.helpOff = max(m.helpOff-1, 0)
		case "down", "j":
			m.helpOff++
		default:
			m.help, m.helpOff = false, 0
		}
		return m, nil
	}
	switch s {
	case "q":
		return m, tea.Quit
	case "?":
		m.help = true
	case "tab", "right", "l":
		m.setView((m.view + 1) % nViews)
	case "shift+tab", "left", "h":
		m.setView((m.view + nViews - 1) % nViews)
	case "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "S":
		m.setView(view(slices.Index(viewHotkeys[:], s)))
	case "r", "ctrl+r":
		m.runKey = "" // reload the run too
		return m, m.refresh()
	case "L":
		m.langs = &panelsDlg{cur: max(slices.Index(m.languages(), m.t.lang), 0)}
	case "o":
		m.panels = &panelsDlg{cur: 1}
	case "z":
		m.toggleZone()
	case "U":
		return m, m.updateDB()
	case "/":
		m.typing = true
	case "esc":
		m.filter, m.detail = "", false
	case "s":
		return m, m.openForm()
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup", "ctrl+b":
		m.move(-m.page())
	case "pgdown", "ctrl+f":
		m.move(m.page())
	case "home", "g":
		m.move(-1 << 30)
	case "end", "G":
		m.move(1 << 30)
	default:
		return m, m.viewKey(s)
	}
	return m, nil
}

func (m *Model) setView(v view) {
	m.view, m.filter, m.detail = v, "", false
	m.host, m.hostOff, m.runInfo = "", 0, nil
}

// languages: English first, then the others by code.
func (m *Model) languages() []string {
	langs := []string{"en"}
	for l := range m.t.ui {
		if l != "en" {
			langs = append(langs, l)
		}
	}
	sort.Strings(langs[1:])
	return langs
}

func (m *Model) langKey(s string) {
	langs := m.languages()
	switch s {
	case "up", "k":
		m.langs.cur = max(m.langs.cur-1, 0)
	case "down", "j":
		m.langs.cur = min(m.langs.cur+1, len(langs)-1)
	case "enter", " ", "space":
		m.t.lang = langs[m.langs.cur]
		m.langs = nil
	case "esc", "q", "L":
		m.langs = nil
	}
}

func (m *Model) move(d int) {
	n := m.rows()
	c := min(max(m.cur[m.view]+d, 0), max(n-1, 0))
	m.cur[m.view] = c
}

func (m *Model) page() int { return max(m.bodyHeight()-2, 1) }

// rows: how many rows the current view lists.
func (m *Model) rows() int {
	switch m.view {
	case vOrgs:
		return len(m.envList())
	case vActions:
		return len(m.actions())
	case vHosts:
		return len(m.hostList())
	case vPackages:
		return len(m.packages())
	case vChanges:
		return len(m.changes())
	case vAccess:
		return len(m.sectionHosts(m.rundAccess()))
	case vNetwork:
		return len(m.sectionHosts(m.rundExposure()))
	case vHealth:
		return len(m.sectionHosts(m.rundHealth()))
	case vExceptions:
		return len(m.exceptions())
	case vRuns:
		return len(m.runList())
	case vScans:
		return len(m.jobs.Jobs)
	}
	return 0
}

func (m *Model) viewKey(s string) tea.Cmd {
	switch m.view {
	case vOrgs:
		if s == "enter" {
			if l := m.envList(); m.cur[vOrgs] < len(l) {
				e := l[m.cur[vOrgs]]
				cmd := m.selectEnv(e.org, e.env)
				m.view = vActions
				return cmd
			}
		}
	case vActions:
		list := m.actions()
		switch s {
		case " ", "space":
			if c := m.cur[vActions]; c < len(list) {
				id := list[c].ID
				m.sel[id] = !m.sel[id]
				if !m.sel[id] {
					delete(m.sel, id)
				}
				m.move(1)
			}
		case "a":
			all := len(list) > 0 && !slices.ContainsFunc(list, func(a action) bool { return !m.sel[a.ID] })
			for _, a := range list {
				if all {
					delete(m.sel, a.ID)
				} else {
					m.sel[a.ID] = true
				}
			}
		case "p":
			m.toggleP4()
		case "v":
			m.onlySel = !m.onlySel
			m.cur[vActions], m.off[vActions] = 0, 0
			if m.onlySel && len(m.sel) == 0 {
				m.say(m.t.T("Nothing selected yet: space selects an action"))
			}
		case "enter":
			m.detail = !m.detail
		case "y":
			return m.copyPrompt(list)
		}
	case vAccess, vNetwork, vHealth:
		var hosts []string
		switch m.view {
		case vAccess:
			hosts = m.sectionHosts(m.rundAccess())
		case vNetwork:
			hosts = m.sectionHosts(m.rundExposure())
		default:
			hosts = m.sectionHosts(m.rundHealth())
		}
		switch s {
		case "enter": // the host's card
			if c := m.cur[m.view]; c < len(hosts) {
				m.view, m.host, m.hostOff, m.filter = vHosts, hosts[c], 0, ""
			}
		case "f":
			if m.view == vNetwork {
				m.outsideOnly = !m.outsideOnly
			}
		}
	case vHosts:
		switch s {
		case "p":
			m.toggleP4()
		case "enter":
			if l := m.hostList(); m.cur[vHosts] < len(l) {
				m.host, m.hostOff = l[m.cur[vHosts]].name, 0
			}
		}
	case vPackages:
		if s == "p" {
			m.toggleP4()
		}
	case vRuns:
		switch s {
		case "i":
			if l := m.runList(); m.cur[vRuns] < len(l) {
				return m.openRunInfo(l[m.cur[vRuns]].RunID)
			}
		case "enter":
			if l := m.runList(); m.cur[vRuns] < len(l) {
				m.run, m.rund = l[m.cur[vRuns]].RunID, nil
				m.view = vActions
				return m.fetchRun(m.wantKey())
			}
		case "c":
			if m.lastDone() != "" {
				m.run, m.rund = "current", nil
				m.view = vActions
				return m.fetchRun(m.wantKey())
			}
		}
	case vScans:
		if c := m.cur[vScans]; c < len(m.jobs.Jobs) {
			j := m.jobs.Jobs[c]
			switch s {
			case "enter":
				m.open = j.ID
			case "x":
				if j.State == "running" {
					return m.post("/api/jobs/"+url.PathEscape(j.ID)+"/cancel", nil, func(any) tea.Msg {
						return toastMsg(m.t.T("Stopping the scan…"))
					})
				}
			}
		}
	}
	return nil
}

func (m *Model) post(path string, body any, ok func(any) tea.Msg) tea.Cmd {
	c := m.c
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var out map[string]any
		if err := c.Post(ctx, path, body, &out); err != nil {
			return errMsg{err}
		}
		return ok(out)
	}
}

// copyPrompt: the agent task for the selected actions (or the one under the cursor) to the terminal clipboard.
func (m *Model) copyPrompt(list []action) tea.Cmd {
	ids := make([]string, 0, len(m.sel))
	for id := range m.sel {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 && m.cur[vActions] < len(list) {
		ids = []string{list[m.cur[vActions]].ID}
	}
	if len(ids) == 0 || m.run == "" {
		return nil
	}
	if m.clip == nil {
		m.say(m.t.T("This terminal session can't copy"))
		return nil
	}
	q := fmt.Sprintf("/api/prompt?org=%s&env=%s&run=%s&lang=%s&ids=%s", url.QueryEscape(m.org), url.QueryEscape(m.env),
		url.QueryEscape(m.run), url.QueryEscape(m.t.lang), url.QueryEscape(strings.Join(ids, ",")))
	clip, n, done := m.clip, len(ids), m.t.T("Task copied to the clipboard")
	var out struct {
		Text string `json:"text"`
	}
	return m.get(q, func(any) tea.Msg {
		// OSC 52: the terminal puts it on the clipboard (also over SSH)
		_, _ = fmt.Fprintf(clip, "\x1b]52;c;%s\a", base64.StdEncoding.EncodeToString([]byte(out.Text)))
		return toastMsg(fmt.Sprintf("%s (%d)", done, n))
	}, &out)
}

func (m *Model) openForm() tea.Cmd {
	if !m.scanOK {
		m.say(m.t.T("Scans can't be started here (read-only)"))
		return nil
	}
	if m.org == "" || m.env == "" {
		return nil
	}
	q := "/api/scan-options?org=" + url.QueryEscape(m.org) + "&env=" + url.QueryEscape(m.env)
	return m.get(q, func(v any) tea.Msg { return optsMsg(*v.(*scanOptions)) }, &scanOptions{})
}

func (m *Model) formKey(s string) tea.Cmd {
	f := m.form
	switch s {
	case "esc", "q":
		m.form = nil
	case "up", "k", "shift+tab":
		f.cur = max(f.cur-1, 0)
	case "down", "j", "tab":
		f.cur = min(f.cur+1, len(f.items)-1)
	case " ", "space", "x":
		if it := &f.items[f.cur]; it.kind != itemHead && it.kind != itemStart {
			it.on = !it.on
		} else if it.kind == itemStart {
			return m.startScan()
		}
	case "enter":
		return m.startScan()
	}
	return nil
}

func (m *Model) startScan() tea.Cmd {
	req := m.form.request()
	return m.post("/api/scan", req, func(v any) tea.Msg {
		id, _ := v.(map[string]any)["id"].(string)
		return startedMsg{id}
	})
}

// --- panel settings -----------------------------------------------------------------------------------------------

type panelsDlg struct{ cur int }

func (m *Model) toggleP4() {
	m.set.ShowP4 = !m.set.ShowP4
	m.move(0)
	m.saveSettings()
}

// applyZone: times in UTC or in the system's zone, as set.
func (m *Model) applyZone() {
	m.t.zone = m.sysZone
	if m.set.UTC {
		m.t.zone = time.UTC
	}
}

func (m *Model) toggleZone() {
	m.set.UTC = !m.set.UTC
	m.applyZone()
	m.say(m.t.F("times in {zone}", "zone", m.t.zoneName(m.now())))
	m.saveSettings()
}

func (m *Model) saveSettings() {
	if err := saveSettings(m.setPath, m.set); err != nil {
		m.err = err.Error()
	}
}

// zoneNames: the time zone setting as the panel settings show it.
var zoneNames = map[bool]string{false: "system", true: "UTC"}

var headerNames = map[string]string{headerAuto: "auto", headerFull: "six lines", headerCompact: "one line", headerOff: "hidden"}

// panelItems: the settings dialog's lines (value of a column item: its title, the setting key).
func (m *Model) panelItems() []formItem {
	zone := zoneNames[m.set.UTC]
	items := []formItem{{kind: itemHead, label: "Layout"},
		{kind: itemChoice, label: "header", value: headerNames[m.set.Header]},
		{kind: itemFlag, label: "view tabs", value: "tabs", on: !m.set.NoTabs},
		{kind: itemFlag, label: "show P4 too", value: "p4", on: m.set.ShowP4},
		{kind: itemChoice, label: "time zone", value: zone},
		{kind: itemHead, label: "Columns"}}
	for _, c := range viewCols[m.view] {
		if c.drop > 0 {
			items = append(items, formItem{kind: itemColumn, label: c.title, on: !m.set.hidden(m.view, c.key())})
		}
	}
	return items
}

func (m *Model) panelsKey(s string) {
	items := m.panelItems()
	d := m.panels
	step := func(dir int) {
		for i := d.cur + dir; i >= 0 && i < len(items); i += dir {
			if items[i].kind != itemHead {
				d.cur = i
				return
			}
		}
	}
	switch s {
	case "esc", "q", "o":
		m.panels = nil
	case "up", "k", "shift+tab":
		step(-1)
	case "down", "j", "tab":
		step(1)
	case " ", "space", "enter", "x", "right", "l", "left", "h":
		it := items[d.cur]
		switch it.kind {
		case itemChoice:
			if it.label == "time zone" {
				m.toggleZone()
				return
			}
			dir := 1
			if s == "left" || s == "h" {
				dir = len(headerModes) - 1
			}
			m.set.Header = headerModes[(slices.Index(headerModes, m.set.Header)+dir)%len(headerModes)]
		case itemFlag:
			if it.value == "tabs" {
				m.set.NoTabs = !m.set.NoTabs
			} else {
				m.set.ShowP4 = !m.set.ShowP4
				m.move(0)
			}
		case itemColumn:
			m.set.toggle(m.view, it.label)
		}
		m.saveSettings()
	}
}

// --- scan form ----------------------------------------------------------------------------------------------------

type itemKind int

const (
	itemHead itemKind = iota
	itemHost
	itemModule
	itemFlag
	itemStart
	itemChoice // panel settings: one of several values
	itemColumn // panel settings: a column on or off
)

type formItem struct {
	kind  itemKind
	label string // text (flags: the English key)
	value string // host, module or flag name
	on    bool
}

type scanForm struct {
	org, env string
	items    []formItem
	cur      int
}

func newForm(org, env string, o scanOptions) *scanForm {
	f := &scanForm{org: org, env: env}
	f.items = append(f.items, formItem{kind: itemHead, label: "Hosts (none selected: all)"})
	for _, h := range o.Hosts {
		f.items = append(f.items, formItem{kind: itemHost, label: h, value: h})
	}
	f.items = append(f.items, formItem{kind: itemHead, label: "Modules (none selected: all enabled)"})
	for _, mo := range o.Modules {
		f.items = append(f.items, formItem{kind: itemModule, label: mo, value: mo})
	}
	f.items = append(f.items, formItem{kind: itemHead, label: "Options"},
		formItem{kind: itemFlag, label: "dry run: show the plan, connect nowhere", value: "dry_run"},
		formItem{kind: itemFlag, label: "ignore the consent time window", value: "ignore_window"},
		formItem{kind: itemFlag, label: "offline: don't download vulnerability DBs", value: "offline"},
		formItem{kind: itemStart, label: "Start"})
	f.cur = 1
	return f
}

func (f *scanForm) request() scanRequest {
	r := scanRequest{Org: f.org, Env: f.env}
	for _, it := range f.items {
		if !it.on {
			continue
		}
		switch it.kind {
		case itemHost:
			r.Hosts = append(r.Hosts, it.value)
		case itemModule:
			r.Modules = append(r.Modules, it.value)
		case itemFlag:
			switch it.value {
			case "dry_run":
				r.DryRun = true
			case "ignore_window":
				r.IgnoreWindow = true
			case "offline":
				r.Offline = true
			}
		}
	}
	return r
}

// --- lists of the views ---------------------------------------------------------------------------------------------

type envItem struct {
	org, name, env string
	e              envRow
}

func (m *Model) envList() []envItem {
	var out []envItem
	for _, o := range m.orgs.Orgs {
		for _, e := range o.Envs {
			it := envItem{o.ID, o.Name, e.Env, e}
			if m.match(o.ID, o.Name, e.Env) {
				out = append(out, it)
			}
		}
	}
	return out
}

func (m *Model) match(fields ...string) bool {
	if m.filter == "" {
		return true
	}
	f := strings.ToLower(m.filter)
	for _, s := range fields {
		if strings.Contains(strings.ToLower(s), f) {
			return true
		}
	}
	return false
}

func (m *Model) actions() []action {
	if m.rund == nil {
		return nil
	}
	var out []action
	for _, a := range m.rund.Actions {
		if m.onlySel && !m.sel[a.ID] {
			continue
		}
		if !m.set.ShowP4 && !m.onlySel && (a.Priority == "P4" || a.Priority == "") {
			continue
		}
		if m.match(append([]string{m.t.title(a), a.Detail, a.Cat, a.Priority}, a.Hosts...)...) {
			out = append(out, a)
		}
	}
	return out
}

type hostItem struct {
	name   string
	os     string
	counts map[string]int
}

func (m *Model) hostList() []hostItem {
	if m.rund == nil {
		return nil
	}
	var out []hostItem
	for name, c := range m.rund.Hosts {
		os := m.rund.Facts[name].OS
		if m.match(name, os) {
			out = append(out, hostItem{name, os, c})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].counts, out[j].counts
		for _, p := range []string{"P1", "P2", "P3", "P4"} {
			if a[p] != b[p] {
				return a[p] > b[p]
			}
		}
		return out[i].name < out[j].name
	})
	return out
}

func (m *Model) packages() []planRow {
	if m.rund == nil {
		return nil
	}
	var out []planRow
	for _, p := range m.rund.Plan {
		if !m.set.ShowP4 && (p.Priority == "P4" || p.Priority == "") {
			continue
		}
		if m.match(p.Host, p.Pkg, p.Target, p.Priority) {
			out = append(out, p)
		}
	}
	return out
}

func (m *Model) runList() []runInfo {
	var out []runInfo
	for i := len(m.envd.Runs) - 1; i >= 0; i-- {
		r := m.envd.Runs[i]
		if m.match(r.RunID, r.State) {
			out = append(out, r)
		}
	}
	return out
}
