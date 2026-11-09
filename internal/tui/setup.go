package tui

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/mikekosulin/kanareika/internal/dbsize"
)

// The setup, one screen as the web page's window, on the same API. Servers: whose they are (personal, a client's,
// a company's, or more for the org on screen), what to connect to — pasted in any form, each line beside what the
// server understood of it (POST /api/setup/parse), aliases picked from ~/.ssh/config (GET /api/setup/discover) —
// and how to log in; saved by POST /api/setup or /api/setup/add. Access: a login to each host, eight at a time
// (POST /api/setup/check), grouped by outcome. First scan: POST /api/scan, its output. The vulnerability list is one
// line on every step, downloaded only when asked (POST /api/db/update), with its size (GET /api/db/size).

type fieldKind int

const (
	fText fieldKind = iota
	fArea
	fChoice
	fCheck
	fButton
	fLogin // the login line: what will be used; c opens the fields under it
)

type field struct {
	key         string
	label       string
	placeholder string
	kind        fieldKind
	val         []rune
	pos         int      // the cursor in val
	opts        []string // a choice's values
	shown       []string // what a choice shows of them
	opt         int
	on          bool   // a check box
	login       bool   // under the login line
	only        string // shown for this kind of org only ("org": client and company, "company")
}

type checkResult struct {
	Host    string `json:"host"`
	Address string `json:"address"`
	OK      bool   `json:"ok"`
	System  string `json:"system"`
	Error   string `json:"error"`
	Hint    string `json:"hint"`
}

type sshHost struct {
	Alias    string `json:"alias"`
	HostName string `json:"hostname"`
	User     string `json:"user"`
	Port     int    `json:"port"`
	Jump     string `json:"jump"`
}

// foundResp: GET /api/setup/discover.
type foundResp struct {
	User      string    `json:"user"`
	Keys      []string  `json:"keys"`
	AgentKeys int       `json:"agent_keys"`
	Hosts     []sshHost `json:"hosts"`
}

type parsedHost struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	User    string `json:"user"`
	Jump    string `json:"jump"`
	Line    int    `json:"line"`
	From    string `json:"from"`
}

// parseResp: POST /api/setup/parse.
type parseResp struct {
	Hosts  []parsedHost `json:"hosts"`
	Errors []string     `json:"errors"`
}

// dbSizeResp: GET /api/db/size.
type dbSizeResp struct {
	Sizes map[string]int64 `json:"sizes"`
	Need  []string         `json:"need"`
	Total int64            `json:"total"`
}

type hostRef struct {
	name, address, user, jump string
	port                      int
}

// login: user@address, as the check shows a host.
func (h hostRef) login() string {
	a := orStr(h.address, h.name)
	if h.port != 0 && h.port != 22 {
		a += ":" + strconv.Itoa(h.port)
	}
	if h.user != "" {
		return h.user + "@" + a
	}
	return a
}

// sshPick: the ~/.ssh/config hosts to choose from (ctrl+o).
type sshPick struct {
	q   string
	cur int
	on  map[int]bool
}

type wizard struct {
	step      int    // 1: servers, 2: access, 3: the first scan
	kind      string // add, personal, client, company
	fields    []field
	cur       int
	loginOpen bool
	errs      []string // what is wrong with the form (the server's words, or what is missing)
	busy      bool

	parsed   *parseResp
	parseGen int // the paste area's edits: an answer for an older text is dropped
	pick     *sshPick

	org, env, file string
	only           []string // the hosts just added (nil: all of the env)
	skipped        []string // lines the server left out when saving
	hosts          []hostRef
	res            map[string]*checkResult
	queue          []string // hosts still to check
	inflight       int
	started        time.Time
	job            string
	off            int
	dlAsked        bool // the download was asked for here: its error shows
	dlParts        bool // what the vulnerability list is made of (i)
}

// The messages of the setup.
type (
	setupMsg struct {
		kind     string // invalid, created
		org, env string
		path     string
		errs     []string
		skipped  []string
		only     []string
	}
	foundMsg  foundResp
	parsedMsg struct {
		gen int
		d   parseResp
	}
	parseDueMsg struct{ gen int }
	hostsMsg    []hostRef
	checkedMsg  struct {
		host string
		r    checkResult
	}
	dbSizeMsg    dbSizeResp
	spinMsg      struct{}
	dlStartedMsg struct{}
)

const checkers = 8 // access checks at a time

var spinner = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

func (m *Model) spinChar() string {
	return string(spinner[int(m.now().UnixMilli()/100)%len(spinner)])
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (m *Model) orgByID(id string) *orgRow {
	for i := range m.orgs.Orgs {
		if m.orgs.Orgs[i].ID == id {
			return &m.orgs.Orgs[i]
		}
	}
	return nil
}

// kinds: whose servers; "add" only with an organization on screen that is not Personal.
func (m *Model) kinds() []string {
	var out []string
	if m.org != "" && m.org != "servers" && m.orgRow() != nil {
		out = append(out, "add")
	}
	return append(out, "personal", "client", "company")
}

func (m *Model) kindName(k string) string {
	switch k {
	case "add":
		o := m.orgRow()
		return m.t.F("Add to {org}", "org", orStr(o.Name, o.ID))
	case "personal":
		return m.t.T("Personal")
	case "client":
		return m.t.T("Client")
	}
	return m.t.T("Company")
}

func (m *Model) newWizard() *wizard {
	w := &wizard{step: 1, kind: "personal"}
	w.fields = m.setupFields()
	return w
}

// checkWizard: the access check of an env that has no runs yet, then its first scan.
func checkWizard(org, env string) *wizard { return &wizard{step: 2, org: org, env: env} }

// setupFields: the form; which of them show depends on the kind and on the login line being open.
func (m *Model) setupFields() []field {
	f := m.found
	if f == nil {
		f = &foundResp{}
	}
	agent := m.t.T("ssh-agent")
	if f.AgentKeys > 0 {
		agent = m.t.F("ssh-agent ({n} keys)", "n", strconv.Itoa(f.AgentKeys))
	}
	return []field{
		{key: "kind", label: "Whose servers?", kind: fChoice},
		{key: "name", label: "Client", placeholder: "ACME", only: "org"},
		{key: "consent", label: "Permission", only: "org"},
		{key: "hosts", label: "Servers", kind: fArea, placeholder: "admin@192.0.2.10"},
		{key: "login", label: "Login", kind: fLogin},
		{key: "user", label: "User", placeholder: orStr(f.User, "root"), login: true},
		{key: "key", label: "Key", kind: fChoice, opts: append([]string{""}, f.Keys...), shown: append([]string{agent}, f.Keys...), login: true},
		{key: "env", label: "Environment", val: []rune("production"), pos: 10, login: true, only: "company"},
		{key: "jump", label: "Jump host", placeholder: "bastion", login: true, only: "company"},
		{key: "sudo", label: "passwordless sudo: also check passwords, keys and the firewall", kind: fCheck, login: true},
		{key: "confirmed", label: "I’m allowed to audit these servers", kind: fCheck},
		{key: "submit", label: "Check connection", kind: fButton},
	}
}

func (w *wizard) visible(i int) bool {
	f := w.fields[i]
	switch {
	case f.login && !w.loginOpen:
		return false
	case f.only == "org":
		return w.kind == "client" || w.kind == "company"
	case f.only == "company":
		return w.kind == "company"
	}
	return true
}

// texting: a text field has the keyboard (keys are text, not hotkeys).
func (w *wizard) texting() bool {
	if w.pick != nil {
		return true
	}
	return w.step == 1 && w.cur < len(w.fields) && (w.fields[w.cur].kind == fText || w.fields[w.cur].kind == fArea)
}

func (w *wizard) field(key string) *field {
	for i := range w.fields {
		if w.fields[i].key == key {
			return &w.fields[i]
		}
	}
	return nil
}

func (w *wizard) value(key string) string {
	f := w.field(key)
	switch {
	case f == nil:
		return ""
	case f.kind == fChoice:
		if f.opt < len(f.opts) {
			return f.opts[f.opt]
		}
		return ""
	case f.kind == fCheck:
		return strconv.FormatBool(f.on)
	}
	return strings.TrimSpace(string(f.val))
}

// --- background: spinner frames, delayed messages --------------------------------------------------------------------

// spin: the next frame of a spinner (checks and downloads under way); nil when none is needed or one is due.
func (m *Model) spin() tea.Cmd {
	if m.spinning || !m.spinNeeded() {
		return nil
	}
	c := m.every(250 * time.Millisecond)
	if c == nil {
		return nil
	}
	m.spinning = true
	return func() tea.Msg { c(); return spinMsg{} }
}

func (m *Model) spinNeeded() bool {
	w := m.setup
	return w != nil && (w.inflight > 0 || m.db != nil && m.db.Updating)
}

// after: msg after d (at once where time does not pass: tests).
func (m *Model) after(d time.Duration, msg tea.Msg) tea.Cmd {
	c := m.every(d)
	return func() tea.Msg {
		if c != nil {
			c()
		}
		return msg
	}
}

// setupUpdate: the setup's messages.
func (m *Model) setupUpdate(msg tea.Msg) tea.Cmd {
	w := m.setup
	switch msg := msg.(type) {
	case foundMsg:
		f := foundResp(msg)
		m.found = &f
		if w != nil && w.fields != nil {
			m.refreshForm()
		}
		return nil
	case dlStartedMsg: // what is still needed: asked again (also once the download ends)
		m.dbSize = nil
		return m.spin()
	case dbSizeMsg:
		d := dbSizeResp(msg)
		m.dbSize = &d
		delete(m.pending, "dbsize")
		return nil
	case spinMsg:
		m.spinning = false
		var cmds []tea.Cmd
		if m.db != nil && m.db.Updating && m.now().Sub(m.dbPolled) >= time.Second {
			m.dbPolled = m.now()
			cmds = append(cmds, m.fetchDB())
		}
		return tea.Batch(append(cmds, m.spin())...)
	}
	if w == nil {
		return nil
	}
	switch msg := msg.(type) {
	case parseDueMsg:
		if msg.gen == w.parseGen {
			return m.parse()
		}
	case parsedMsg:
		if msg.gen == w.parseGen {
			d := msg.d
			w.parsed = &d
		}
	case setupMsg:
		w.busy = false
		switch msg.kind {
		case "invalid":
			w.errs = msg.errs
		case "created":
			w.step, w.org, w.env, w.file, w.skipped, w.only = 2, msg.org, msg.env, msg.path, msg.skipped, msg.only
			w.res, w.hosts, w.errs = map[string]*checkResult{}, nil, nil
			return tea.Batch(m.fetchOrgs(), m.selectEnv(msg.org, msg.env), m.fetchHosts())
		}
	case hostsMsg:
		w.hosts = nil
		for _, h := range msg {
			if w.only == nil || slices.Contains(w.only, h.name) {
				w.hosts = append(w.hosts, h)
			}
		}
		return m.checkAccess(false)
	case checkedMsg:
		r := msg.r
		w.res[msg.host] = &r
		w.inflight--
		return m.nextCheck()
	}
	return nil
}

// refreshForm: the fields again with what discover found (the key choice, the user), what was typed kept.
func (m *Model) refreshForm() {
	w := m.setup
	old := w.fields
	w.fields = m.setupFields()
	for i := range w.fields {
		for _, o := range old {
			if o.key == w.fields[i].key {
				w.fields[i].val, w.fields[i].pos, w.fields[i].on = o.val, o.pos, o.on
				w.fields[i].opt = min(o.opt, max(len(w.fields[i].opts)-1, 0))
			}
		}
	}
}

func (m *Model) fetchFound() tea.Cmd {
	if m.found != nil || m.pending["found"] != "" || !m.scanOK {
		return nil
	}
	m.pending["found"] = "found"
	c := m.c
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var f foundResp
		_ = c.Get(ctx, "/api/setup/discover", &f) // nothing found is no error: the fields stay empty
		return foundMsg(f)
	}
}

// fetchDBSize: what the download would cost (none on a read-only dashboard: nothing to ask).
func (m *Model) fetchDBSize() tea.Cmd {
	if m.dbSize != nil || m.pending["dbsize"] != "" || !m.scanOK {
		return nil
	}
	m.pending["dbsize"] = "dbsize"
	c := m.c
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var d dbSizeResp
		_ = c.Get(ctx, "/api/db/size", &d)
		return dbSizeMsg(d)
	}
}

func (m *Model) parse() tea.Cmd {
	w := m.setup
	text, gen, c := string(w.field("hosts").val), w.parseGen, m.c
	if strings.TrimSpace(text) == "" {
		w.parsed = nil
		return nil
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var d parseResp
		if err := c.Post(ctx, "/api/setup/parse", map[string]string{"text": text}, &d); err != nil {
			d.Errors = []string{err.Error()}
		}
		return parsedMsg{gen, d}
	}
}

func (m *Model) fetchHosts() tea.Cmd {
	w := m.setup
	c, org, env := m.c, w.org, w.env
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var e struct {
			Hosts []struct {
				Name    string  `json:"name"`
				Address string  `json:"address"`
				User    string  `json:"user"`
				Port    int     `json:"port"`
				Jump    *string `json:"jump"`
			} `json:"hosts"`
		}
		if err := c.Get(ctx, "/api/env?org="+url.QueryEscape(org)+"&env="+url.QueryEscape(env), &e); err != nil {
			return errMsg{err}
		}
		out := hostsMsg{}
		for _, h := range e.Hosts {
			r := hostRef{name: h.Name, address: h.Address, user: h.User, port: h.Port}
			if h.Jump != nil {
				r.jump = *h.Jump
			}
			out = append(out, r)
		}
		return out
	}
}

// checkAccess: every host (or the failed ones) again, eight at a time.
func (m *Model) checkAccess(onlyFailed bool) tea.Cmd {
	w := m.setup
	if w.res == nil {
		w.res = map[string]*checkResult{}
	}
	w.queue = nil
	for _, h := range w.hosts {
		if r := w.res[h.name]; !onlyFailed || r != nil && !r.OK {
			delete(w.res, h.name)
			w.queue = append(w.queue, h.name)
		}
	}
	w.started, m.err = m.now(), ""
	return m.nextCheck()
}

func (m *Model) nextCheck() tea.Cmd {
	w := m.setup
	var cmds []tea.Cmd
	for w.inflight < checkers && len(w.queue) > 0 {
		host := w.queue[0]
		w.queue = w.queue[1:]
		w.inflight++
		c, org, env := m.c, w.org, w.env
		cmds = append(cmds, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 3*timeout)
			defer cancel()
			var out struct {
				Results []checkResult `json:"results"`
			}
			err := c.Post(ctx, "/api/setup/check", map[string]any{"org": org, "env": env, "hosts": []string{host}}, &out)
			switch {
			case err != nil:
				return checkedMsg{host, checkResult{Host: host, Error: err.Error()}}
			case len(out.Results) == 0:
				return checkedMsg{host, checkResult{Host: host, Error: "no answer"}}
			}
			return checkedMsg{host, out.Results[0]}
		})
	}
	return tea.Batch(append(cmds, m.spin())...)
}

// loginKey: the key the login line shows and the org file gets: the agent's (empty) when it has keys, else the first
// key in ~/.ssh.
func (m *Model) loginKey() string {
	w, f := m.setup, m.found
	if k := w.value("key"); k != "" || f == nil || f.AgentKeys > 0 || len(f.Keys) == 0 {
		return k
	}
	return f.Keys[0]
}

// submit: the form to the server, as the web page sends it.
func (m *Model) submit() tea.Cmd {
	w := m.setup
	if w.busy {
		return nil
	}
	f := m.found
	if f == nil {
		f = &foundResp{}
	}
	named := w.kind == "client" || w.kind == "company"
	switch {
	case strings.TrimSpace(w.value("hosts")) == "":
		w.errs = []string{m.t.T("Paste at least one server.")}
	case named && w.value("name") == "" && w.kind == "client":
		w.errs = []string{m.t.T("Name the client.")}
	case named && w.value("name") == "":
		w.errs = []string{m.t.T("Name the company.")}
	case named && w.value("consent") == "":
		w.errs = []string{m.t.T("Say where the permission is documented.")}
	case w.value("confirmed") != "true":
		w.errs = []string{m.t.T("Confirm that you are allowed to audit these servers.")}
	default:
		w.errs = nil
	}
	if w.errs != nil {
		return nil
	}
	w.busy = true
	sudo := map[bool]string{true: "sudo", false: "none"}[w.value("sudo") == "true"]
	base := setupReq{User: orStr(w.value("user"), orStr(f.User, "root")), Privilege: sudo, Key: m.loginKey(), Hosts: w.value("hosts"),
		Env: "production", Confirmed: true}
	var body any
	path, org, env := "/api/setup", "", "production"
	target := m.orgByID("servers")
	switch w.kind {
	case "add":
		target = m.orgRow()
	case "personal":
	default:
		target = nil
	}
	switch {
	case target != nil:
		path, org, env = "/api/setup/add", target.ID, target.Envs[0].Env
		if w.kind == "add" && slices.ContainsFunc(target.Envs, func(e envRow) bool { return e.Env == m.env }) {
			env = m.env
		}
		body = map[string]any{"org": org, "hosts": w.value("hosts"), "user": w.value("user")}
	case w.kind == "personal":
		org = "servers"
		base.ID, base.Name, base.Consent = org, m.t.T("Personal"), m.t.F("Confirmed in the setup on {d}", "d", m.now().Format(time.DateOnly))
		body = base
	default:
		org = m.freeID(strings.Trim(slugRE.ReplaceAllString(strings.ToLower(w.value("name")), "-"), "-"), w.kind)
		base.ID, base.Name, base.Consent = org, w.value("name"), w.value("consent")
		if w.kind == "company" {
			base.Env, base.Jump = orStr(w.value("env"), "production"), w.value("jump")
			env = base.Env
		}
		body = base
	}
	c := m.c
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var out struct {
			Org     string   `json:"org"`
			Path    string   `json:"path"`
			Added   []string `json:"added"`
			Skipped []string `json:"skipped"`
		}
		err := c.Post(ctx, path, body, &out)
		var ae *APIError
		switch {
		case errors.As(err, &ae) && len(ae.Errors) > 0:
			return setupMsg{kind: "invalid", errs: ae.Errors}
		case err != nil:
			return setupMsg{kind: "invalid", errs: []string{err.Error()}}
		}
		msg := setupMsg{kind: "created", org: orStr(out.Org, org), env: env, path: out.Path, skipped: out.Skipped}
		if path == "/api/setup/add" {
			msg.only = out.Added
			if msg.only == nil {
				msg.only = []string{}
			}
		}
		return msg
	}
}

var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

// freeID: an org id not taken yet (acme, acme-2, ...); base, or fallback when it is empty.
func (m *Model) freeID(base, fallback string) string {
	if base == "" {
		base = fallback
	}
	id := base
	for i := 2; m.orgByID(id) != nil; i++ {
		id = base + "-" + strconv.Itoa(i)
	}
	return id
}

// setupReq: POST /api/setup.
type setupReq struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	User      string   `json:"user"`
	Privilege string   `json:"privilege"`
	Key       string   `json:"key"`
	Hosts     string   `json:"hosts"`
	Env       string   `json:"env"`
	Internet  bool     `json:"internet"`
	Front     []string `json:"front,omitempty"`
	Jump      string   `json:"jump,omitempty"`
	Consent   string   `json:"consent"`
	Confirmed bool     `json:"confirmed"`
}

// download: the vulnerability list now, asked for.
func (m *Model) download() tea.Cmd {
	if w := m.setup; w != nil {
		w.dlAsked = true
	}
	if m.db != nil && m.db.Updating {
		return nil
	}
	m.dlStart = m.now()
	fetch := m.fetchDB()
	return m.post("/api/db/update", nil, func(any) tea.Msg {
		return tea.BatchMsg{fetch, func() tea.Msg { return dlStartedMsg{} }}
	})
}

func (m *Model) dlNeeded() bool { return m.dbSize != nil && len(m.dbSize.Need) > 0 }

// --- keys ------------------------------------------------------------------------------------------------------------

func (m *Model) setupKey(k tea.KeyMsg) tea.Cmd {
	w := m.setup
	s := k.String()
	if w.pick != nil {
		return m.pickKey(k)
	}
	if s == "ctrl+d" || s == "d" && !w.texting() { // the vulnerability list, downloaded when asked
		return m.download()
	}
	if s == "i" && !w.texting() { // what it is made of
		w.dlParts = !w.dlParts
		return nil
	}
	switch w.step {
	case 2:
		return m.checkKey(s)
	case 3:
		if j := m.jobOf(w.job); s == "esc" || s == "q" || s == "enter" && j != nil && j.State != "running" {
			m.setup = nil
			m.setView(vServers)
			return m.refresh()
		}
		return nil
	}
	return m.serversKey(k)
}

func (m *Model) jobOf(id string) *jobInfo {
	for i := range m.jobs.Jobs {
		if m.jobs.Jobs[i].ID == id {
			return &m.jobs.Jobs[i]
		}
	}
	return nil
}

func (m *Model) checkKey(s string) tea.Cmd {
	w := m.setup
	ok, bad := w.counts()
	waiting := len(w.hosts) - ok - bad
	switch s {
	case "esc":
		if waiting == 0 && ok == 0 && w.fields != nil { // nothing answered: back to the servers
			w.step = 1
			return nil
		}
		m.setup = nil
		m.setView(vServers)
	case "r":
		if waiting == 0 {
			return m.checkAccess(bad > 0 && ok > 0)
		}
	case "enter", "s":
		if ok == 0 || waiting > 0 || w.busy {
			return nil
		}
		req := scanRequest{Org: w.org, Env: w.env}
		if ok < len(w.hosts) || w.only != nil {
			for _, h := range w.hosts {
				if r := w.res[h.name]; r != nil && r.OK {
					req.Hosts = append(req.Hosts, h.name)
				}
			}
		}
		w.busy = true
		return m.post("/api/scan", req, func(v any) tea.Msg {
			id, _ := v.(map[string]any)["id"].(string)
			return startedMsg{id}
		})
	case "up", "k":
		w.off = max(w.off-1, 0)
	case "down", "j":
		w.off++
	}
	return nil
}

func (w *wizard) counts() (ok, bad int) {
	for _, h := range w.hosts {
		if r := w.res[h.name]; r != nil {
			if r.OK {
				ok++
			} else {
				bad++
			}
		}
	}
	return ok, bad
}

// serversKey: the keys of the servers form.
func (m *Model) serversKey(k tea.KeyMsg) tea.Cmd {
	w := m.setup
	s := k.String()
	f := &w.fields[w.cur]
	next := func(d int) {
		for i := w.cur + d; i >= 0 && i < len(w.fields); i += d {
			if w.visible(i) {
				w.cur = i
				return
			}
		}
	}
	switch s {
	case "esc":
		if len(m.orgs.Orgs) > 0 {
			m.setup = nil
		}
		return nil
	case "ctrl+s":
		return m.submit()
	case "ctrl+o":
		if m.found != nil && len(m.found.Hosts) > 0 {
			w.pick = &sshPick{on: map[int]bool{}}
		}
		return nil
	case "tab":
		next(1)
		return nil
	case "shift+tab":
		next(-1)
		return nil
	case "up", "down":
		if f.kind == fArea {
			if f.line(map[string]int{"up": -1, "down": 1}[s]) {
				return nil
			}
		}
		next(map[string]int{"up": -1, "down": 1}[s])
		return nil
	case "c":
		if !w.texting() {
			w.loginOpen = !w.loginOpen
			if !w.visible(w.cur) {
				w.cur = slices.IndexFunc(w.fields, func(x field) bool { return x.key == "login" })
			}
			return nil
		}
	}
	before := string(f.val)
	switch f.kind {
	case fButton:
		if s == "enter" || s == " " || s == "space" {
			return m.submit()
		}
	case fLogin:
		if s == "enter" || s == " " || s == "space" || s == "right" {
			w.loginOpen = !w.loginOpen
		}
	case fCheck:
		switch s {
		case "enter", " ", "space", "x":
			f.on = !f.on
		}
	case fChoice:
		dir := map[string]int{"enter": 1, " ": 1, "space": 1, "right": 1, "l": 1, "left": -1, "h": -1}[s]
		if dir == 0 {
			break
		}
		if f.key == "kind" {
			ks := m.kinds()
			i := slices.Index(ks, w.kind)
			w.kind = ks[(i+dir+len(ks))%len(ks)]
			w.errs = nil
			return m.parseSoon() // the default user may change the preview
		}
		f.opt = (f.opt + dir + len(f.opts)) % len(f.opts)
	case fText, fArea:
		switch s {
		case "enter":
			if f.kind == fArea {
				f.insert([]rune("\n"))
			} else {
				next(1)
			}
		case "left":
			f.pos = max(f.pos-1, 0)
		case "right":
			f.pos = min(f.pos+1, len(f.val))
		case "home", "ctrl+a":
			for f.pos > 0 && f.val[f.pos-1] != '\n' {
				f.pos--
			}
		case "end", "ctrl+e":
			for f.pos < len(f.val) && f.val[f.pos] != '\n' {
				f.pos++
			}
		case "backspace":
			if f.pos > 0 {
				f.val = append(f.val[:f.pos-1], f.val[f.pos:]...)
				f.pos--
			}
		case "delete":
			if f.pos < len(f.val) {
				f.val = append(f.val[:f.pos], f.val[f.pos+1:]...)
			}
		case "ctrl+u":
			f.val, f.pos = nil, 0
		default:
			if k.Type == tea.KeyRunes || k.Type == tea.KeySpace {
				r := strings.ReplaceAll(string(k.Runes), "\r", "")
				if f.kind == fText {
					r = strings.ReplaceAll(r, "\n", " ")
				}
				f.insert([]rune(r))
			}
		}
	}
	if string(f.val) != before {
		w.errs = nil // what was wrong may be fixed now
	}
	if (f.key == "hosts" || f.key == "user") && string(f.val) != before {
		return m.parseSoon()
	}
	return nil
}

// parseSoon: what the paste area says, a moment after the typing stops.
func (m *Model) parseSoon() tea.Cmd {
	w := m.setup
	w.parseGen++
	return m.after(250*time.Millisecond, parseDueMsg{w.parseGen})
}

// pickKey: the ~/.ssh/config picker: type to narrow, space to choose, enter adds their aliases (the server resolves
// them).
func (m *Model) pickKey(k tea.KeyMsg) tea.Cmd {
	w := m.setup
	p := w.pick
	s := k.String()
	list := m.pickList()
	switch s {
	case "esc":
		w.pick = nil
	case "up", "ctrl+p":
		p.cur = max(p.cur-1, 0)
	case "down", "ctrl+n", "tab":
		p.cur = min(p.cur+1, max(len(list)-1, 0))
	case " ", "space":
		if p.cur < len(list) {
			p.on[list[p.cur]] = !p.on[list[p.cur]]
		}
	case "backspace":
		if r := []rune(p.q); len(r) > 0 {
			p.q, p.cur = string(r[:len(r)-1]), 0
		}
	case "enter":
		var chosen []int
		for i := range m.found.Hosts {
			if p.on[i] {
				chosen = append(chosen, i)
			}
		}
		if len(chosen) == 0 && p.cur < len(list) {
			chosen = []int{list[p.cur]}
		}
		w.pick = nil
		if len(chosen) == 0 {
			return nil
		}
		f := w.field("hosts")
		text := strings.TrimSpace(string(f.val))
		for _, i := range chosen {
			if text != "" {
				text += "\n"
			}
			text += m.found.Hosts[i].Alias
		}
		f.val = []rune(text)
		f.pos = len(f.val)
		return m.parseSoon()
	default:
		if k.Type == tea.KeyRunes {
			p.q += string(k.Runes)
			p.cur = 0
		}
	}
	return nil
}

// pickList: the indexes of the ~/.ssh/config hosts the typed filter keeps.
func (m *Model) pickList() []int {
	var out []int
	q := strings.ToLower(m.setup.pick.q)
	for i, h := range m.found.Hosts {
		if strings.Contains(strings.ToLower(h.Alias+" "+h.User+"@"+h.HostName), q) {
			out = append(out, i)
		}
	}
	return out
}

func (f *field) insert(r []rune) {
	v := append([]rune{}, f.val[:f.pos]...)
	v = append(v, r...)
	f.val = append(v, f.val[f.pos:]...)
	f.pos += len(r)
}

// line: the cursor a line up or down in a text area; false at its first or last line.
func (f *field) line(d int) bool {
	start := f.pos
	for start > 0 && f.val[start-1] != '\n' {
		start--
	}
	col := f.pos - start
	if d < 0 {
		if start == 0 {
			return false
		}
		prev := start - 1
		for prev > 0 && f.val[prev-1] != '\n' {
			prev--
		}
		f.pos = min(prev+col, start-1)
		return true
	}
	end := f.pos
	for end < len(f.val) && f.val[end] != '\n' {
		end++
	}
	if end >= len(f.val) {
		return false
	}
	nextEnd := end + 1
	for nextEnd < len(f.val) && f.val[nextEnd] != '\n' {
		nextEnd++
	}
	f.pos = min(end+1+col, nextEnd)
	return true
}

// --- drawing ---------------------------------------------------------------------------------------------------------

func (m *Model) setupTitle() string { return sTitle.Render("~ kanareika setup") }

// steps: the setup's steps, as tabs.
var steps = []string{"Servers", "Connect", "First scan"}

// stepTabs: Servers › Access › First scan; the current one a tab, the done ones ✓ green, the rest dim.
func (m *Model) stepTabs() string {
	var parts []string
	for i, st := range steps {
		n := i + 1
		switch {
		case n < m.setup.step:
			parts = append(parts, sOK.Render("✓ "+m.t.T(st)))
		case n == m.setup.step:
			parts = append(parts, sCrumb.Render(m.t.T(st)))
		default:
			parts = append(parts, sDim.Render(m.t.T(st)))
		}
	}
	return " " + strings.Join(parts, sDim.Render(" › "))
}

func (m *Model) setupView(w, h int) []string {
	wz := m.setup
	tabs, dl := m.stepTabs(), m.dlLine(w)
	if room := w - ansi.StringWidth(tabs) - ansi.StringWidth(dl) - 1; dl != "" && room > 0 {
		tabs += strings.Repeat(" ", room) + dl
	}
	out := []string{tabs, ""}
	if wz.dlParts {
		out = append(out, m.dlBreakdown()...)
	}
	switch wz.step {
	case 1:
		body := m.serversView(w)
		if wz.pick != nil {
			body = append(m.pickView(w), body...)
		}
		out = append(out, body...)
	case 2:
		out = append(out, m.checkView(w)...)
	default:
		out = append(out, m.scanView(w)...)
	}
	off := min(wz.off, max(len(out)-h, 0))
	if wz.step == 1 {
		off = max(m.setupCurLine-h+4, 0)
	}
	return out[min(off, len(out)):]
}

// textBox: a field's text, the cursor shown where it is when it has the keyboard; one string per line.
func textBox(f *field, focus bool) []string {
	if len(f.val) == 0 && !focus {
		return []string{sDim.Render(f.placeholder)}
	}
	cur := lipgloss.NewStyle().Reverse(true)
	var lines []string
	var b strings.Builder
	for i := 0; i <= len(f.val); i++ {
		if focus && i == f.pos {
			ch := " "
			if i < len(f.val) && f.val[i] != '\n' {
				ch = string(f.val[i])
			}
			b.WriteString(cur.Render(ch))
			if i < len(f.val) && f.val[i] != '\n' {
				continue
			}
		}
		if i == len(f.val) {
			break
		}
		if f.val[i] == '\n' {
			lines = append(lines, b.String())
			b.Reset()
			continue
		}
		b.WriteString(sText.Render(string(f.val[i])))
	}
	return append(lines, b.String())
}

// heading: a question or a label, highlighted when its field has the keyboard.
func heading(s string, focus bool) string {
	if focus {
		return sKey.Render("▶ " + s)
	}
	return "  " + sBold.Render(s)
}

func (m *Model) serversView(w int) []string {
	wz := m.setup
	focus := func(key string) bool { return wz.fields[wz.cur].key == key }
	var out []string
	mark := func() { m.setupCurLine = len(out) + 2 } // the steps, a blank line
	// whose servers
	if focus("kind") {
		mark()
	}
	var opts []string
	for _, k := range m.kinds() {
		if k == wz.kind {
			opts = append(opts, m.zone("kind:"+k, sBrand.Render("(•) "+m.kindName(k)), m.clickKind(k)))
		} else {
			opts = append(opts, m.zone("kind:"+k, sMuted.Render("( ) "+m.kindName(k)), m.clickKind(k)))
		}
	}
	out = append(out, " "+heading(m.t.T("Whose servers?"), focus("kind"))+"   "+strings.Join(opts, "  "))
	if wz.kind == "client" || wz.kind == "company" {
		name, consent := wz.field("name"), wz.field("consent")
		name.label, consent.label, consent.placeholder = "Client", "Their permission", m.t.T("contract, ticket, e-mail")
		if wz.kind == "company" {
			name.label, consent.label, consent.placeholder = "Company", "Permission", m.t.T("ticket, policy")
		}
		if focus("name") || focus("consent") {
			mark()
		}
		out = append(out, "   "+m.zone("field:name", heading(m.t.T(name.label), focus("name"))+"  "+fit(textBox(name, focus("name"))[0], 24, false), m.clickField("name"))+"   "+
			m.zone("field:consent", heading(m.t.T(consent.label), focus("consent"))+"  "+textBox(consent, focus("consent"))[0], m.clickField("consent")))
	}
	out = append(out, "")
	// the servers: what was written, and beside each line what it becomes
	if focus("hosts") {
		mark()
	}
	out = append(out, " "+m.zone("field:hosts", heading(m.t.T("Servers"), focus("hosts")), m.clickField("hosts"))+"   "+sMuted.Render(m.t.T("One per line: user@host, an ssh command, ssh config, CSV")))
	out = append(out, m.editor(w)...)
	if m.found != nil && len(m.found.Hosts) > 0 {
		out = append(out, "    "+m.zoneKey("ctrl+o", sKey.Render("ctrl+o")+" "+sMuted.Render("+ ~/.ssh/config ("+strconv.Itoa(len(m.found.Hosts))+")")))
	}
	out = append(out, "")
	// login
	if focus("login") {
		mark()
	}
	out = append(out, " "+m.zone("field:login", heading(m.t.T("Login"), focus("login"))+"  "+m.loginSummary(), m.clickField("login"))+"   "+
		m.zone("login:open", sKey.Render("c")+" "+sMuted.Render(m.t.T("change")), func(int) tea.Cmd { m.setup.loginOpen = !m.setup.loginOpen; return nil }))
	if wz.loginOpen {
		for i := range wz.fields {
			f := &wz.fields[i]
			if !f.login || !wz.visible(i) {
				continue
			}
			if focus(f.key) {
				mark()
			}
			switch f.kind {
			case fCheck:
				out = append(out, "     "+m.zone("check:"+f.key, checkBox(f, m.t.T(f.label), focus(f.key)), m.clickCheck(f.key)))
			case fChoice:
				var o []string
				for j := range f.opts {
					opt := sMuted.Render("( ) " + f.shown[j])
					if j == f.opt {
						opt = sBrand.Render("(•) " + f.shown[j])
					}
					o = append(o, m.zone(fmt.Sprintf("opt:%s:%d", f.key, j), opt, m.clickOpt(f.key, j)))
				}
				out = append(out, "   "+heading(fit(m.t.T(f.label), 12, false), focus(f.key))+strings.Join(o, "  "))
			default:
				out = append(out, "   "+m.zone("field:"+f.key, heading(fit(m.t.T(f.label), 12, false), focus(f.key))+textBox(f, focus(f.key))[0], m.clickField(f.key)))
			}
		}
	}
	out = append(out, "")
	if focus("confirmed") {
		mark()
	}
	out = append(out, " "+m.zone("check:confirmed", checkBox(wz.field("confirmed"), m.t.T("I’m allowed to audit these servers"), focus("confirmed")), m.clickCheck("confirmed")))
	for _, e := range wz.errs {
		out = append(out, " "+sErr.Render("✗ "+e))
	}
	if focus("submit") {
		mark()
	}
	b := sCrumb.Render("⏎ " + m.t.T("Check connection"))
	if focus("submit") {
		b = sSel.Render(" ⏎ " + m.t.T("Check connection") + " ")
	}
	if wz.busy {
		b += " " + sRun.Render(m.spinChar())
	}
	return append(out, "", " "+m.zone("btn:submit", b, func(int) tea.Cmd { return m.submit() }))
}

// The setup's clicks: a choice, a field (the keyboard to it), a check box, a choice's option.
func (m *Model) clickKind(k string) func(int) tea.Cmd {
	return func(int) tea.Cmd {
		w := m.setup
		w.kind, w.errs = k, nil
		w.cur = slices.IndexFunc(w.fields, func(f field) bool { return f.key == "kind" })
		return m.parseSoon()
	}
}

func (m *Model) clickField(key string) func(int) tea.Cmd {
	return func(int) tea.Cmd {
		w := m.setup
		if i := slices.IndexFunc(w.fields, func(f field) bool { return f.key == key }); i >= 0 {
			w.cur = i
		}
		return nil
	}
}

func (m *Model) clickCheck(key string) func(int) tea.Cmd {
	return func(int) tea.Cmd {
		m.clickField(key)(0)
		f := m.setup.field(key)
		f.on = !f.on
		m.setup.errs = nil
		return nil
	}
}

func (m *Model) clickOpt(key string, j int) func(int) tea.Cmd {
	return func(int) tea.Cmd {
		m.clickField(key)(0)
		m.setup.field(key).opt = j
		return nil
	}
}

func checkBox(f *field, label string, focus bool) string {
	box := sDim.Render("[ ]")
	if f.on {
		box = sBrand.Render("[x]")
	}
	if focus {
		return sKey.Render("▶ ") + box + " " + sKey.Render(label)
	}
	return "  " + box + " " + sText.Render(label)
}

// loginSummary: what the login will be: the agent's keys or the key file, and the user.
func (m *Model) loginSummary() string {
	wz, f := m.setup, m.found
	if f == nil {
		f = &foundResp{}
	}
	key := ""
	switch k := m.loginKey(); {
	case k != "":
		key = sBold.Render(k)
	case f.AgentKeys > 0:
		key = sText.Render("ssh-agent · ") + sBold.Render(m.t.F("{n} keys", "n", strconv.Itoa(f.AgentKeys)))
	default:
		key = sErr.Render(m.t.T("no SSH key found"))
	}
	return key + sMuted.Render(" · "+m.t.T("user")+" ") + sBold.Render(orStr(wz.value("user"), orStr(f.User, "root")))
}

// editor: the paste area. Empty: one plain field with greyed examples. With text: line numbers, what was written,
// and on each line's row what the server made of it.
func (m *Model) editor(w int) []string {
	wz := m.setup
	f := wz.field("hosts")
	focus := wz.fields[wz.cur].key == "hosts"
	if len(f.val) == 0 {
		cur := " "
		if focus {
			cur = lipgloss.NewStyle().Reverse(true).Render(" ")
		}
		return []string{"    " + cur + sDim.Render("admin@192.0.2.10"), "     " + sDim.Render("ssh -p 2222 deploy@203.0.113.7"), "     " + sDim.Render("nas")}
	}
	box := textBox(f, focus)
	n := max(3, len(box))
	right := m.lineResults(n)
	leftW := max(min((w-8)/2, 44), 20)
	var out []string
	for i := 0; i < max(n, len(right)); i++ {
		num := ""
		if i < n {
			num = strconv.Itoa(i + 1)
		}
		line := i
		out = append(out, m.zone(fmt.Sprintf("edit:%d", i), "   "+sDim.Render(fit(num, 2, true))+" "+fit(get(box, i), leftW, false), func(int) tea.Cmd {
			m.clickField("hosts")(0) // the keyboard to the field, the cursor at the end of the clicked line
			f.pos = 0
			for l := 0; l < line && f.pos < len(f.val); f.pos++ {
				if f.val[f.pos] == '\n' {
					l++
				}
			}
			for f.pos < len(f.val) && f.val[f.pos] != '\n' {
				f.pos++
			}
			return nil
		})+"  "+get(right, i))
	}
	return out
}

func get(l []string, i int) string {
	if i < len(l) {
		return l[i]
	}
	return ""
}

var lineErr = regexp.MustCompile(`^line (\d+): (?:"[^"]*"(?::\s*|\s+))?(.*)$`)

// lineResults: for each of n pasted lines, what it becomes (✓ user@address via … from ssh config), or why it is
// skipped; errors without a line at the end.
func (m *Model) lineResults(n int) []string {
	wz := m.setup
	if wz.parsed == nil {
		return nil
	}
	f := m.found
	if f == nil {
		f = &foundResp{}
	}
	defUser := orStr(wz.value("user"), orStr(f.User, "root"))
	rows := make([]string, n)
	for _, h := range wz.parsed.Hosts {
		if h.Line < 1 || h.Line > n {
			continue
		}
		l := sMuted.Render("→ ") + sText.Render(orStr(h.User, defUser)+"@"+h.Address)
		if h.Jump != "" {
			l += sMuted.Render(" via " + h.Jump)
		}
		if h.From != "" {
			l += sMuted.Render(" " + m.t.T("from ssh config"))
		}
		rows[h.Line-1] = l
	}
	for _, e := range wz.parsed.Errors {
		msg := e
		line := 0
		if sm := lineErr.FindStringSubmatch(e); sm != nil {
			line, _ = strconv.Atoi(sm[1])
			msg = sm[2]
		}
		l := sMuted.Render("→ ") + lipgloss.NewStyle().Foreground(cP["P3"]).Render(msg) + sMuted.Render(" · "+m.t.T("skipped"))
		if line >= 1 && line <= n && rows[line-1] == "" {
			rows[line-1] = l
		} else {
			rows = append(rows, l)
		}
	}
	return rows
}

// pickView: the ~/.ssh/config hosts to choose from.
func (m *Model) pickView(w int) []string {
	p := m.setup.pick
	list := m.pickList()
	lines := []string{" " + sKey.Render("> ") + sText.Render(p.q) + sBrand.Render("_"), ""}
	aw := 0
	for _, h := range m.found.Hosts {
		aw = max(aw, ansi.StringWidth(h.Alias))
	}
	for j, i := range list {
		h := m.found.Hosts[i]
		box := sDim.Render("[ ]")
		if p.on[i] {
			box = sBrand.Render("[x]")
		}
		where := orStr(h.HostName, h.Alias)
		if h.User != "" {
			where = h.User + "@" + where
		}
		if h.Port != 0 {
			where += ":" + strconv.Itoa(h.Port)
		}
		l := " " + box + " " + sBold.Render(fit(h.Alias, aw, false)) + "  " + sMuted.Render(where)
		if h.Jump != "" {
			l += sMuted.Render(" via " + h.Jump)
		}
		if j == p.cur {
			l = sSel.Render(fit(ansi.Strip(l), min(w-4, 70), false))
		}
		l = m.zone(fmt.Sprintf("pick:%d", j), l, func(int) tea.Cmd { p.cur = j; p.on[i] = !p.on[i]; return nil })
		lines = append(lines, l)
	}
	if len(list) == 0 {
		lines = append(lines, " "+sMuted.Render(m.t.T("nothing here")))
	}
	lines = append(lines, "", " "+sKey.Render("space")+" "+sMuted.Render(m.t.T("toggle"))+"  "+sKey.Render("⏎")+" "+
		sMuted.Render(m.t.T("Add"))+"  "+sKey.Render("esc")+" "+sMuted.Render(m.t.T("Cancel")))
	return append(panel(sTitle.Render("~/.ssh/config"), lines, min(w, 74), len(lines)+2), "")
}

var authFail = regexp.MustCompile(`(?i)authenticat|permission denied|publickey|refused the login`)

// checkView: the hosts as their checks answer, grouped: connecting, each cause of failure once (its hint, its hosts,
// how to fix a refused login), the ones that answered, the lines skipped when saving.
func (m *Model) checkView(w int) []string {
	wz := m.setup
	out := []string{" " + sBold.Render(m.t.T("Connecting")) + "   " + sMuted.Render(m.t.T("One login per server, uname -sr, log out. Nothing is changed.")), ""}
	if m.err != "" && wz.hosts == nil {
		return append(out, " "+sErr.Render("✗ "+m.err))
	}
	if wz.hosts == nil {
		return append(out, " "+sRun.Render(m.spinChar())+" "+sMuted.Render(m.t.T("loading")))
	}
	lw := 0
	for _, h := range wz.hosts {
		lw = max(lw, ansi.StringWidth(h.login()))
	}
	lw = min(lw, max(w/2, 24))
	row := func(mark string, h hostRef, note string) string {
		l := h.login()
		if ansi.StringWidth(l) > lw { // never wrapped: cut at its end
			l = ansi.Truncate(l, lw, "…")
		}
		return "   " + mark + " " + lipgloss.NewStyle().Foreground(cCyan).Render(fit(l, lw, false)) + "  " + sMuted.Render(ansi.Truncate(note, max(w-lw-8, 10), "…"))
	}
	var ok, bad, waiting []hostRef
	for _, h := range wz.hosts {
		switch r := wz.res[h.name]; {
		case r == nil:
			waiting = append(waiting, h)
		case r.OK:
			ok = append(ok, h)
		default:
			bad = append(bad, h)
		}
	}
	if len(waiting) > 0 {
		secs := strconv.Itoa(int(m.now().Sub(wz.started).Seconds()))
		out = append(out, " "+sRun.Render(m.spinChar()+" ")+sBold.Render(m.t.F("{n} connecting", "n", strconv.Itoa(len(waiting))))+sMuted.Render(" · "+secs+" s"))
		for _, h := range waiting {
			note := ""
			if h.jump != "" {
				note = "via " + h.jump
			}
			out = append(out, row(sRun.Render(m.spinChar()), h, note))
		}
		out = append(out, "")
	}
	type cause struct {
		r     *checkResult
		hosts []hostRef
	}
	var causes []*cause
	for _, h := range bad {
		r := wz.res[h.name]
		k := orStr(r.Hint, r.Error)
		i := slices.IndexFunc(causes, func(c *cause) bool { return orStr(c.r.Hint, c.r.Error) == k })
		if i < 0 {
			causes = append(causes, &cause{r: r})
			i = len(causes) - 1
		}
		causes[i].hosts = append(causes[i].hosts, h)
	}
	bare := func(e string) string { // the error without the host name it starts with
		if _, rest, ok := strings.Cut(e, ": "); ok {
			return rest
		}
		return e
	}
	for _, c := range causes {
		for i, l := range strings.Split(ansi.Wordwrap(orStr(c.r.Hint, c.r.Error), max(w-5, 20), ""), "\n") {
			p := "   "
			if i == 0 {
				p = " " + sErr.Render("✗ ")
			}
			out = append(out, p+sBold.Render(l))
		}
		same := !slices.ContainsFunc(c.hosts, func(h hostRef) bool { return bare(wz.res[h.name].Error) != bare(c.r.Error) })
		for _, h := range c.hosts {
			note := ""
			if c.r.Hint != "" && !same {
				note = bare(wz.res[h.name].Error)
			}
			out = append(out, row(sErr.Render("✗"), h, note))
		}
		if authFail.MatchString(c.r.Error + " " + c.r.Hint) {
			for _, h := range c.hosts[:min(3, len(c.hosts))] {
				host, port := h.address, ""
				if h.port != 0 && h.port != 22 {
					port = " -p " + strconv.Itoa(h.port)
				}
				if h.user != "" {
					host = h.user + "@" + host
				}
				out = append(out, "   "+sMuted.Render(m.t.T("fix")+": ")+sText.Render("ssh-copy-id"+port+" "+host))
			}
		}
		out = append(out, "")
	}
	if len(ok) > 0 {
		out = append(out, " "+sOK.Render("✓ ")+sBold.Render(m.t.F("{n} answered", "n", strconv.Itoa(len(ok)))))
		for _, h := range ok {
			out = append(out, row(sOK.Render("✓"), h, wz.res[h.name].System))
		}
		out = append(out, "")
	}
	if len(wz.skipped) > 0 {
		out = append(out, " "+lipgloss.NewStyle().Foreground(cP["P3"]).Render("! ")+sBold.Render(m.t.F("{n} skipped", "n", strconv.Itoa(len(wz.skipped)))))
		for _, s := range wz.skipped {
			out = append(out, "   "+sMuted.Render(s))
		}
		out = append(out, "")
	}
	if wz.file != "" {
		out = append(out, " "+sMuted.Render(m.t.F("Saved in {file}", "file", wz.file[strings.LastIndex(wz.file, "/")+1:])), "")
	}
	var keys []string
	switch {
	case len(waiting) > 0:
	case len(ok) > 0:
		scan := m.t.T("Start the first scan")
		if len(bad) > 0 {
			scan = m.t.F("Scan the {n} that answered", "n", strconv.Itoa(len(ok)))
		}
		if m.dlNeeded() && (m.db == nil || !m.db.Updating) {
			scan += " · " + m.t.F("downloads the vuln list first ({size})", "size", dbsize.Bytes(m.dbSize.Total))
		}
		keys = append(keys, m.zoneKey("enter", sCrumb.Render("⏎ "+scan)))
		if len(bad) > 0 {
			keys = append(keys, m.zoneKey("r", sKey.Render("r")+" "+sText.Render(m.t.T("Check again"))))
		}
	default:
		keys = append(keys, m.zoneKey("r", sCrumb.Render("r "+m.t.T("Check again"))))
		if wz.fields != nil {
			keys = append(keys, m.zoneKey("esc", sKey.Render("esc")+" "+sText.Render(m.t.T("Back"))))
		}
	}
	if len(keys) > 0 {
		out = append(out, " "+strings.Join(keys, "   "))
	}
	return out
}

// scanView: the first scan's own output, as a terminal shows it; then the results.
func (m *Model) scanView(w int) []string {
	wz := m.setup
	out := []string{" " + sBold.Render(m.t.T("First scan")) + "   " + sMuted.Render(m.t.T("A few minutes. The scan goes on if you leave this screen.")), ""}
	j := m.jobOf(wz.job)
	var lines []string
	if j != nil {
		lines = j.Output
		if len(lines) > 16 {
			lines = lines[len(lines)-16:]
		}
	}
	var term []string
	for _, l := range lines {
		term = append(term, " "+sText.Render(l))
	}
	if len(term) == 0 {
		term = []string{" " + sRun.Render(m.spinChar())}
	}
	out = append(out, panel(sMuted.Render("scan"), term, w, len(term)+2)...)
	switch {
	case j == nil || j.State == "running":
		state := "starting"
		if j != nil {
			state = j.State
		}
		return append(out, "", " "+sRun.Render(m.spinChar())+" "+sMuted.Render(m.t.T(state)))
	case j.Code != 0:
		return append(out, "", " "+m.zoneKey("enter", sCrumb.Render("⏎ "+m.t.T("See the results")))+"   "+sErr.Render(m.t.T("finished with errors")))
	}
	return append(out, "", " "+m.zoneKey("enter", sCrumb.Render("⏎ "+m.t.T("See the results"))))
}

// dlLine: the vulnerability list a scan needs, at the right of the steps: its size and d to download it;
// downloading; ready; failed. "" where it can't be downloaded (read-only) or before its size is known.
func (m *Model) dlLine(w int) string {
	z, db, wz := m.dbSize, m.db, m.setup
	if !m.scanOK || z == nil {
		return ""
	}
	label := sMuted.Render(m.t.T("vulnerability list")) + " "
	switch {
	case db != nil && db.Updating:
		secs := 0
		if !m.dlStart.IsZero() {
			secs = int(m.now().Sub(m.dlStart).Seconds())
		}
		bar := []string{"▬  ", "▬▬ ", "▬▬▬", " ▬▬", "  ▬"}[int(m.now().UnixMilli()/250)%5]
		return label + sRun.Render(bar) + " " + sMuted.Render(strconv.Itoa(secs)+" s") + " "
	case db != nil && db.Error != "" && wz != nil && wz.dlAsked:
		return label + sErr.Render(m.t.T("failed")) + "  " + m.zone("dl", sKey.Render("d")+" "+sText.Render(m.t.T("retry")), func(int) tea.Cmd { return m.download() }) + " "
	case len(z.Need) == 0:
		return label + sOK.Render("✓ "+m.t.T("ready")) + " "
	}
	_ = w
	return label + sText.Render(dbsize.Bytes(z.Total)) + "  " + m.zone("dl", sKey.Render("↓ d")+" "+sText.Render(m.t.T("download")), func(int) tea.Cmd { return m.download() }) + " "
}

// dlBreakdown: what the vulnerability list is made of (i), on demand only.
func (m *Model) dlBreakdown() []string {
	z := m.dbSize
	if z == nil {
		return nil
	}
	size := func(keys ...string) string {
		var n int64
		for _, k := range keys {
			n += z.Sizes[k]
		}
		return dbsize.Bytes(n)
	}
	row := func(label, size, note string) string {
		return "   " + sText.Render(fit(m.t.T(label), 18, false)) + sBold.Render(fit(size, 8, true)) + "  " + sMuted.Render(note)
	}
	out := []string{row("Linux packages", size("db"), ""), row("IP locations", size("dbip-city", "dbip-asn"), ""),
		row("Exploit data", size("kev", "epss"), "CISA KEV, EPSS")}
	if j := z.Sizes["java-db"]; j > 0 {
		out = append(out, row("Java libraries", "~"+dbsize.Bytes(j), m.t.T("only if a scan finds .jar files")))
	}
	if db := m.db; db != nil && db.Error != "" && m.setup.dlAsked {
		out = append(out, "   "+sErr.Render(ansi.Truncate(db.Error, 100, "…")))
	}
	return append(out, "")
}

// setupStatus: the setup's status bar: the org and env, the vulnerability list, the ssh-agent.
func (m *Model) setupStatus() string {
	wz := m.setup
	name := m.t.T("setup")
	if o := m.orgByID(wz.org); o != nil {
		name = orStr(o.Name, o.ID)
	}
	if wz.env != "" {
		name += " · " + wz.env
	}
	parts := []string{sBold.Render(name)}
	if f := m.found; f != nil {
		agent := m.t.T("none")
		if f.AgentKeys > 0 {
			agent = m.t.F("{n} keys", "n", strconv.Itoa(f.AgentKeys))
		}
		parts = append(parts, sMuted.Render("ssh-agent ")+sText.Render(agent))
	}
	l := " " + strings.Join(parts, sDim.Render(" │ "))
	if m.err != "" && wz.step != 2 {
		l += "  " + sErr.Render(m.err)
	}
	return l
}

// setupHints: the keys of the setup's step.
func (m *Model) setupHints() string {
	wz := m.setup
	type k struct{ key, what string }
	var l []k
	switch {
	case wz.pick != nil:
		l = []k{{"space", "toggle"}, {"⏎", "Add"}, {"esc", "Cancel"}}
	case wz.step == 1:
		l = []k{{"tab", "next"}, {"ctrl+s", "Check connection"}, {"ctrl+o", "~/.ssh/config"}, {"ctrl+d", "download"}}
		if len(m.orgs.Orgs) > 0 {
			l = append(l, k{"esc", "close"})
		}
	case wz.step == 2:
		l = []k{{"d", "download"}, {"i", "what is downloaded"}, {"esc", "close"}}
	default:
		l = []k{{"esc", "close"}}
	}
	parts := make([]string, 0, len(l))
	for _, x := range l {
		parts = append(parts, sKey.Render(x.key)+" "+sMuted.Render(m.t.T(x.what)))
	}
	return " " + strings.Join(parts, sDim.Render("  ·  "))
}
