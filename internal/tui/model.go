package tui

import (
	"cmp"
	"context"
	"encoding/base64"
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
	vActions view = iota
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

// viewNames: tab titles (English keys of the web page's translations where it has them). Organizations and
// environments are chosen with O and E.
var viewNames = [nViews]string{"ToDo", "Hosts", "Packages", "Changes", "Access", "Network", "Health",
	"Exceptions", "Runs", "Scans"}

// viewHotkeys: the key of each view: 1-9, 0 (S opens Scans too).
var viewHotkeys = [nViews]string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"}

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

	// ToDo: the tree
	by      string                 // grouping: fix, cve, host (g)
	flt     map[string]bool        // filters on (f)
	tree    *treeResp              // nil until it comes
	treeKey string                 // what the tree on screen is for (wantTree)
	nodes   map[string]*nodeDetail // details by treeKey#node id
	pending map[string]string      // requests on the way: "tree" -> its key, a node's key -> itself
	opened  map[string]bool        // expanded nodes
	sel     map[string]bool        // selected nodes (a node selects everything under it)
	onlySel bool                   // only the selected (v)
	curID   string                 // the node under the cursor, kept when the tree is rebuilt
	jumpTo  string                 // the node to put the cursor on when the next tree comes (:)
	full    bool                   // the details full screen (enter)
	detOff  int
	cmdCur  int // the command of the details c copies ([ ])

	menu      *menuDlg // filters (f), organizations (O), environments (E), jump (:)
	setup     *wizard  // first-run setup (no organization yet, N) and the first scan of an env
	setupSeen bool     // the setup opened on its own once
	firstScan string   // the job of a first scan: ToDo when it ends

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
		t: &tr{lang: "en", ui: i18n.UI()}, set: loadSettings(o.Settings), setPath: o.Settings, sysZone: o.Zone,
		by: "fix", flt: map[string]bool{}, nodes: map[string]*nodeDetail{}, pending: map[string]string{}, opened: map[string]bool{}}
	m.applyZone()
	if o.Lang != "" && (o.Lang == "en" || m.t.ui[o.Lang] != nil) {
		m.t.lang = o.Lang
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

// Update: the message, then whatever the screen now needs fetched.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	_, cmd := m.update(msg)
	if c := m.sync(); c != nil {
		cmd = tea.Batch(cmd, c)
	}
	return m, cmd
}

func (m *Model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		m.autoSetup()
		if i := slices.IndexFunc(m.jobs.Jobs, func(j jobInfo) bool { return j.ID == m.firstScan }); i >= 0 && m.jobs.Jobs[i].State != "running" {
			m.firstScan = "" // the first scan of an env ended: what to do
			m.setView(vActions)
		}
		if was && !m.busy() {
			return m, m.refresh() // a scan just ended: its results
		}
	case treeMsg:
		m.onTree(msg)
	case nodeMsg:
		delete(m.pending, msg.key)
		if strings.HasPrefix(msg.key, m.treeKey+"#") {
			m.nodes[msg.key] = msg.d
		}
	case jumpTreeMsg:
		if m.menu != nil && m.menu.kind == "jump" {
			m.menu.trees[msg.by] = msg.d
		}
	case setupMsg:
		return m, m.onSetup(msg)
	case tickMsg:
		return m, tea.Batch(m.refresh(), m.tick())
	case errMsg:
		m.err = msg.err.Error()
		if m.setup != nil {
			m.setup.busy = false
		}
	case toastMsg:
		m.say(string(msg))
	case optsMsg:
		m.form = newForm(m.org, m.env, scanOptions(msg))
	case runInfoMsg:
		if m.runInfo != nil && m.runInfo.id == msg.id {
			m.runInfo.meta, m.runInfo.log = msg.meta, msg.log
		}
	case startedMsg:
		if m.setup != nil {
			m.setup, m.firstScan = nil, msg.id
		}
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
	m.autoSetup()
	if m.envd.Runs == nil {
		return m.fetchEnv()
	}
	return nil
}

// autoSetup: no organization yet, and one can be set up here: the setup, once (esc leaves it, N brings it back).
func (m *Model) autoSetup() {
	if m.loaded && len(m.orgs.Orgs) == 0 && m.scanOK && m.setup == nil && !m.setupSeen {
		m.setupSeen = true
		m.setup = newWizard()
	}
}

// newOrg: the setup of a new organization (where it writes org files: as scans, not on a read-only dashboard).
func (m *Model) newOrg() {
	if !m.scanOK {
		m.say(m.t.T("Scans can't be started here (read-only)"))
		return
	}
	m.setup = newWizard()
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
	m.tree, m.treeKey, m.nodes, m.pending = nil, "", map[string]*nodeDetail{}, map[string]string{}
	m.sel, m.opened, m.curID, m.full = map[string]bool{}, map[string]bool{}, "", false
	m.cur, m.off = [nViews]int{}, [nViews]int{}
	return m.fetchEnv()
}

// latin: keys typed with another keyboard layout, as the same keys on a QWERTY one (й -> q, ㅂ -> q, é -> 2):
// the hotkeys work whatever layout is on. Russian ЙЦУКЕН, Korean 2-set (shifted letters give the same jamo as
// unshifted ones but the five doubled consonants and two vowels), and the French AZERTY digit row, which types
// & é " ' ( - è _ ç à without Shift. Text (the filter) is never mapped.
var latin = func() map[rune]rune {
	m := map[rune]rune{}
	for _, p := range [][2]string{
		{"йцукенгшщзхъфывапролджэячсмитьбю.ё", "qwertyuiop[]asdfghjkl;'zxcvbnm,./`"},
		{"ЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮ,Ё", "QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?~"},
		{"ㅂㅈㄷㄱㅅㅛㅕㅑㅐㅔㅁㄴㅇㄹㅎㅗㅓㅏㅣㅋㅌㅊㅍㅠㅜㅡ", "qwertyuiopasdfghjklzxcvbnm"},
		{"ㅃㅉㄸㄲㅆㅒㅖ", "QWERTOP"},
		{"&é\"'(-è_çà", "1234567890"},
	} {
		from, to := []rune(p[0]), []rune(p[1])
		for i := range from {
			m[from[i]] = to[i]
		}
	}
	return m
}()

func (m *Model) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	texting := m.typing || m.setup != nil && m.setup.texting() || m.menu != nil && m.menu.kind != "filters"
	if !texting && k.Type == tea.KeyRunes && len(k.Runes) == 1 {
		if r, ok := latin[k.Runes[0]]; ok {
			k.Runes = []rune{r}
		}
	}
	s := k.String()
	if s == "ctrl+c" {
		return m, tea.Quit
	}
	if m.setup != nil {
		return m, m.setupKey(k)
	}
	if m.form != nil {
		return m, m.formKey(s)
	}
	if m.menu != nil {
		return m, m.menuKey(k)
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
	if m.host != "" && m.view == vHosts && !m.help {
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
	if m.view == vActions {
		if cmd, ok := m.todoKey(s); ok {
			return m, cmd
		}
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
	case "1", "2", "3", "4", "5", "6", "7", "8", "9", "0":
		m.setView(view(slices.Index(viewHotkeys[:], s)))
	case "S":
		m.setView(vScans)
	case "r", "ctrl+r":
		m.runKey, m.treeKey = "", "" // reload the run and the tree too
		m.nodes, m.pending = map[string]*nodeDetail{}, map[string]string{}
		return m, m.refresh()
	case "L":
		m.langs = &panelsDlg{cur: max(slices.Index(m.languages(), m.t.lang), 0)}
	case "o":
		m.panels = &panelsDlg{cur: 1}
	case "O":
		m.menu = m.newMenu("orgs")
	case "E":
		m.menu = m.newMenu("envs")
	case ":", "ctrl+k":
		m.menu = m.newMenu("jump")
		return m, m.fetchJumpTrees()
	case "N":
		m.newOrg()
	case "z":
		m.toggleZone()
	case "U":
		return m, m.updateDB()
	case "/":
		m.typing = true
	case "esc":
		m.filter = ""
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
	m.view, m.filter, m.full = v, "", false
	m.host, m.hostOff, m.runInfo = "", 0, nil
}

// languages: English first, then the others by code.
func (m *Model) languages() []string {
	// in the order of i18n.Langs (English, then by their own names); any this build has no file for, last
	langs, order := []string{"en"}, i18n.Langs()
	for l := range m.t.ui {
		if l != "en" {
			langs = append(langs, l)
		}
	}
	rank := func(l string) int {
		if i := slices.Index(order, l); i >= 0 {
			return i
		}
		return len(order)
	}
	slices.SortFunc(langs[1:], func(a, b string) int { return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(a, b)) })
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
	if m.view == vActions {
		if rows := m.treeRows(); c < len(rows) {
			m.curID = rows[c].n.ID
		}
		m.cmdCur = 0
	}
}

func (m *Model) page() int { return max(m.bodyHeight()-2, 1) }

// rows: how many rows the current view lists.
func (m *Model) rows() int {
	switch m.view {
	case vActions:
		return len(m.treeRows())
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
	case vActions:
		if s == "enter" && m.run == "" && m.org != "" { // no runs yet: check the access, then the first scan
			m.setup = checkWizard(m.org, m.env)
			return m.setup.check(m)
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

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

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

// panelItems: the settings dialog's lines (value of a column item: its title, the setting key).
func (m *Model) panelItems() []formItem {
	zone := zoneNames[m.set.UTC]
	items := []formItem{{kind: itemHead, label: "Layout"},
		{kind: itemFlag, label: "view tabs", value: "tabs", on: !m.set.NoTabs},
		{kind: itemFlag, label: "show P4 too", value: "p4", on: m.set.ShowP4},
		{kind: itemChoice, label: "time zone", value: zone},
		{kind: itemHead, label: "Columns"}}
	cols := viewCols[m.view]
	if m.view == vActions {
		cols = m.treeCols()
	}
	for _, c := range cols {
		if c.drop > 0 && c.title != "" {
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
		case itemChoice: // the time zone
			m.toggleZone()
			return
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
