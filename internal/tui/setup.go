package tui

import (
	"context"
	"errors"
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

// The setup, as the web page has it, on the same API: choose a path (add to the org on screen, my servers, a
// client's servers, a fleet), paste the servers (POST /api/setup/parse shows what was understood as one types;
// ~/.ssh/config hosts from GET /api/setup/discover can be picked), save (POST /api/setup or /api/setup/add), check
// SSH access to each host, eight at a time (POST /api/setup/check), then the first scan (POST /api/scan). The
// vulnerability list scans need is one line all along: downloaded only when asked (POST /api/db/update), with its
// size (GET /api/db/size).

type fieldKind int

const (
	fText fieldKind = iota
	fArea
	fChoice
	fCheck
	fButton
	fFold // "Login details": shows the fields folded under it
)

type field struct {
	key         string
	label       string
	hint        string
	placeholder string
	kind        fieldKind
	val         []rune
	pos         int      // the cursor in val
	opts        []string // a choice's values
	shown       []string // what a choice shows of them ("": the value)
	opt         int
	on          bool // a check box
	fold        bool // under "Login details"
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
	Group   string `json:"group"`
	Env     string `json:"env"`
	User    string `json:"user"`
	Jump    string `json:"jump"`
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

type hostRef struct{ name, address string }

// sshPick: the ~/.ssh/config hosts to choose from (ctrl+o).
type sshPick struct {
	q   string
	cur int
	on  map[int]bool
}

type wizard struct {
	step    int    // 0: the path, 1: the servers, 2: the access check, 3: the first scan
	path    string // add, few, client, fleet
	pathCur int
	fields  []field
	cur     int
	login   bool     // the login details unfolded
	errs    []string // the server's problems with the form
	busy    bool

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

	dlAsked bool // the download was asked for here: its error shows
	raw     bool // the raw errors of the failed checks unfolded (e)
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

// setupPaths: the ways in; "add" only with an organization on screen (not My servers: that is "few").
func (m *Model) setupPaths() []string {
	var out []string
	if m.org != "" && m.org != "servers" && m.orgRow() != nil {
		out = append(out, "add")
	}
	return append(out, "few", "client", "fleet")
}

func (m *Model) orgByID(id string) *orgRow {
	for i := range m.orgs.Orgs {
		if m.orgs.Orgs[i].ID == id {
			return &m.orgs.Orgs[i]
		}
	}
	return nil
}

func (m *Model) newWizard() *wizard { return &wizard{} }

// checkWizard: the access check of an env that has no runs yet, then its first scan.
func checkWizard(org, env string) *wizard { return &wizard{step: 2, org: org, env: env} }

// formFor: the fields of a path's form (the web page's fewForm, clientForm, fleetForm).
func (m *Model) formFor(path string) []field {
	f := m.found
	if f == nil {
		f = &foundResp{}
	}
	user := orStr(f.User, "root")
	hosts := field{key: "hosts", label: "Servers", hint: "an IP, user@host or an ssh command, one per line", kind: fArea, placeholder: "admin@192.0.2.10"}
	sudo := field{key: "sudo", label: "The user can sudo without a password: also check passwords, keys, the login log and the firewall", kind: fCheck}
	agent := m.t.T("the ssh-agent")
	if f.AgentKeys > 0 {
		agent = m.t.F("the ssh-agent ({n} keys)", "n", strconv.Itoa(f.AgentKeys))
	}
	keyChoice := field{key: "key", label: "Key", hint: "not needed with an ssh-agent", kind: fChoice, opts: append([]string{""}, f.Keys...),
		shown: append([]string{agent}, f.Keys...), fold: true}
	keyText := field{key: "key", label: "Key", hint: "not needed with an ssh-agent", placeholder: agent, fold: true}
	userF := field{key: "user", label: "SSH user", hint: "unless a line says otherwise", placeholder: user, fold: true}
	fold := field{key: "login", label: "Login details", kind: fFold}
	switch path {
	case "client":
		sudo.fold = true
		return []field{{key: "name", label: "Client", placeholder: m.t.T("ACME Corp")}, hosts, fold, userF, keyText, sudo,
			{key: "consent", label: "The client's permission", hint: "where it is documented: a contract, a ticket, an e-mail", placeholder: m.t.T("Contract 42, appendix 3")},
			{key: "confirmed", label: "The client allowed me to audit these servers.", kind: fCheck},
			{key: "submit", label: "Save and check access", kind: fButton}}
	case "fleet":
		userF.fold, keyText.fold = false, false
		userF.placeholder = orStr(f.User, "audit")
		return []field{{key: "name", label: "Organization", placeholder: m.t.T("ACME Corp")},
			{key: "id", label: "Short id", hint: "for files and commands", placeholder: "acme"}, hosts, userF, keyText,
			{key: "env", label: "Environment", hint: "unless a line says otherwise", val: []rune("production"), pos: 10},
			{key: "jump", label: "Jump host for all", hint: "[user@]host[:port], empty: direct or per line", placeholder: "bastion.example.com"},
			{key: "front", label: "Groups facing the internet", hint: "comma-separated; their findings get higher priority", placeholder: "web, edge"},
			sudo,
			{key: "consent", label: "Permission to audit", hint: "where it is documented: a contract, a ticket, an e-mail", placeholder: m.t.T("Ticket OPS-123")},
			{key: "confirmed", label: "I am allowed to audit these servers.", kind: fCheck},
			{key: "submit", label: "Save and check access", kind: fButton}}
	}
	sudo.fold = true
	return []field{hosts, fold, userF, keyChoice, sudo,
		{key: "confirmed", label: "These are my servers, or I am allowed to audit them.", kind: fCheck},
		{key: "submit", label: "Check access", kind: fButton}}
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (w *wizard) visible(i int) bool { return !w.fields[i].fold || w.login }

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
		return f.opts[f.opt]
	case f.kind == fCheck:
		return strconv.FormatBool(f.on)
	}
	return strings.TrimSpace(string(f.val))
}

// --- keys ------------------------------------------------------------------------------------------------------------

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
		if w != nil && w.step == 1 {
			m.refreshForm()
		}
	case dlStartedMsg: // what is still needed: asked again (also once the download ends)
		m.dbSize = nil
		return m.spin()
	case dbSizeMsg:
		d := dbSizeResp(msg)
		m.dbSize = &d
		delete(m.pending, "dbsize")
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
			w.res, w.hosts = map[string]*checkResult{}, nil
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

func (m *Model) refreshForm() {
	w := m.setup
	old := w.fields
	w.fields = m.formFor(w.path)
	for i := range w.fields { // what was typed stays
		for _, o := range old {
			if o.key == w.fields[i].key && o.kind == w.fields[i].kind {
				w.fields[i].val, w.fields[i].pos, w.fields[i].on = o.val, o.pos, o.on
				w.fields[i].opt = min(o.opt, max(len(w.fields[i].opts)-1, 0))
			}
		}
	}
}

func (m *Model) fetchFound() tea.Cmd {
	if m.found != nil || m.pending["found"] != "" {
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

// fetchDBSize: what a download would cost (none on a read-only dashboard: nothing to ask).
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
				Name    string `json:"name"`
				Address string `json:"address"`
			} `json:"hosts"`
		}
		if err := c.Get(ctx, "/api/env?org="+url.QueryEscape(org)+"&env="+url.QueryEscape(env), &e); err != nil {
			return errMsg{err}
		}
		out := hostsMsg{}
		for _, h := range e.Hosts {
			out = append(out, hostRef{h.Name, h.Address})
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
	w.busy, w.errs = true, nil
	sudo := map[bool]string{true: "sudo", false: "none"}[w.value("sudo") == "true"]
	confirmed := w.value("confirmed") == "true"
	today := m.now().Format(time.DateOnly)
	var body any
	path, org, env := "/api/setup", "", "production"
	switch w.path {
	case "add", "few":
		target := m.orgByID("servers")
		if w.path == "add" {
			target = m.orgRow()
		}
		if target != nil {
			path, org = "/api/setup/add", target.ID
			env = target.Envs[0].Env
			if w.path == "add" && slices.ContainsFunc(target.Envs, func(e envRow) bool { return e.Env == m.env }) {
				env = m.env
			}
			body = map[string]any{"org": org, "hosts": w.value("hosts"), "user": w.value("user")}
			break
		}
		org = "servers"
		body = setupReq{ID: org, Name: m.t.T("My servers"), User: orStr(w.value("user"), orStr(f.User, "root")), Privilege: sudo,
			Key: w.value("key"), Hosts: w.value("hosts"), Env: env, Consent: m.t.F("Confirmed in the setup on {d}", "d", today), Confirmed: confirmed}
	case "client":
		org = m.freeID(slugRE.ReplaceAllString(strings.ToLower(w.value("name")), "-"))
		body = setupReq{ID: org, Name: w.value("name"), User: orStr(w.value("user"), orStr(f.User, "root")), Privilege: sudo, Key: w.value("key"),
			Hosts: w.value("hosts"), Env: env, Consent: w.value("consent"), Confirmed: confirmed}
	default:
		org, env = w.value("id"), orStr(w.value("env"), "production")
		var front []string
		for _, g := range strings.FieldsFunc(w.value("front"), func(r rune) bool { return r == ',' || r == ' ' }) {
			front = append(front, strings.ToLower(g))
		}
		body = setupReq{ID: org, Name: w.value("name"), User: orStr(w.value("user"), orStr(f.User, "audit")), Privilege: sudo, Key: w.value("key"),
			Hosts: w.value("hosts"), Env: env, Jump: w.value("jump"), Front: front, Consent: w.value("consent"), Confirmed: confirmed}
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

// freeID: an org id from a name, not taken yet (acme, acme-2, ...).
func (m *Model) freeID(base string) string {
	base = strings.Trim(base, "-")
	if base == "" {
		base = "client"
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

// download: the DBs now, asked for (the card's "Download now").
func (m *Model) download() tea.Cmd {
	w := m.setup
	if w != nil {
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

func (m *Model) setupKey(k tea.KeyMsg) tea.Cmd {
	w := m.setup
	s := k.String()
	if w.pick != nil {
		return m.pickKey(k)
	}
	if s == "ctrl+d" || s == "d" && !w.texting() { // the vulnerability list, downloaded when asked
		return m.download()
	}
	switch w.step {
	case 0:
		paths := m.setupPaths()
		switch s {
		case "esc", "q":
			if len(m.orgs.Orgs) > 0 {
				m.setup = nil
			}
		case "up", "k", "shift+tab":
			w.pathCur = max(w.pathCur-1, 0)
		case "down", "j", "tab":
			w.pathCur = min(w.pathCur+1, len(paths)-1)
		case "enter", " ", "space":
			w.path, w.step, w.cur, w.errs, w.parsed = paths[min(w.pathCur, len(paths)-1)], 1, 0, nil, nil
			w.fields = m.formFor(w.path)
			return m.fetchFound()
		}
		return nil
	case 2:
		return m.checkKey(s)
	case 3:
		switch s {
		case "enter", "esc", "q":
			if j := m.jobOf(w.job); s != "enter" || j == nil || j.State != "running" {
				m.setup = nil
				m.setView(vActions)
				return m.refresh()
			}
		}
		return nil
	}
	return m.formKey1(k)
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
	case "esc", "q":
		m.setup = nil
		m.setView(vActions)
	case "r":
		if waiting == 0 {
			return m.checkAccess(bad > 0 && ok > 0)
		}
	case "e":
		w.raw = !w.raw
	case "enter", "s":
		if ok == 0 || w.busy {
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

// formKey1: the keys of the servers form.
func (m *Model) formKey1(k tea.KeyMsg) tea.Cmd {
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
		w.step, w.errs = 0, nil // back to the paths
		return nil
	case "ctrl+s":
		return m.submit()
	case "ctrl+o":
		if m.found != nil && len(m.found.Hosts) > 0 && w.field("hosts") != nil {
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
			if moved := f.line(map[string]int{"up": -1, "down": 1}[s]); moved {
				return nil
			}
		}
		next(map[string]int{"up": -1, "down": 1}[s])
		return nil
	}
	before := string(f.val)
	switch f.kind {
	case fButton:
		if s == "enter" || s == " " || s == "space" {
			return m.submit()
		}
	case fFold:
		if s == "enter" || s == " " || s == "space" || s == "right" || s == "left" {
			w.login = !w.login
		}
	case fCheck:
		switch s {
		case "enter", " ", "space", "x":
			f.on = !f.on
		}
	case fChoice:
		switch s {
		case "enter", " ", "space", "right", "l":
			f.opt = (f.opt + 1) % len(f.opts)
		case "left", "h":
			f.opt = (f.opt + len(f.opts) - 1) % len(f.opts)
		}
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
				r := k.Runes
				if f.kind == fText {
					r = []rune(strings.ReplaceAll(strings.ReplaceAll(string(r), "\r", ""), "\n", " "))
				} else {
					r = []rune(strings.ReplaceAll(string(r), "\r", ""))
				}
				f.insert(r)
			}
		}
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

// pickKey: the ~/.ssh/config picker: type to narrow, space to choose, enter adds them to the paste area.
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
			text += sshLine(m.found.Hosts[i], m.found.Hosts)
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

// sshLine: a ~/.ssh/config host as the ssh command the paste area understands (its jump host spelled out).
func sshLine(h sshHost, all []sshHost) string {
	s := "ssh"
	if h.Port != 0 && h.Port != 22 {
		s += " -p " + strconv.Itoa(h.Port)
	}
	if h.Jump != "" {
		j := h.Jump
		if i := slices.IndexFunc(all, func(x sshHost) bool { return x.Alias == h.Jump }); i >= 0 {
			x := all[i]
			j = orStr(x.HostName, x.Alias)
			if x.User != "" {
				j = x.User + "@" + j
			}
			if x.Port != 0 {
				j += ":" + strconv.Itoa(x.Port)
			}
		}
		s += " -J " + j
	}
	s += " "
	if h.User != "" {
		s += h.User + "@"
	}
	return s + orStr(h.HostName, h.Alias)
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

func (m *Model) setupTitle() string {
	w := m.setup
	switch {
	case w.step == 0 && len(m.orgs.Orgs) > 0:
		return sTitle.Render(m.t.T("Add servers"))
	case w.step == 0:
		return sTitle.Render(m.t.T("Welcome to Kanareika"))
	case w.step == 2:
		return sTitle.Render(m.t.T("Access check")) + sText.Render("("+w.org+"/"+w.env+")")
	case w.step == 3:
		return sTitle.Render(m.t.T("First scan")) + sText.Render("("+w.org+"/"+w.env+")")
	}
	return sTitle.Render(m.t.T(pathTitles[w.path]))
}

// steps: the stepper's steps.
var steps = []string{"Servers", "Access", "First scan"}

// stepper: 1 Servers ── 2 Access ── 3 First scan; done ✓ green, the current one canary, the rest dim.
func (m *Model) stepper() string {
	cur := max(1, m.setup.step)
	var b strings.Builder
	b.WriteString(" ")
	for i, st := range steps {
		n := i + 1
		label := m.t.T(st)
		switch {
		case n < cur:
			b.WriteString(sOK.Render("✓ " + label))
		case n == cur:
			b.WriteString(sBrand.Render(strconv.Itoa(n) + " " + label))
		default:
			b.WriteString(sDim.Render(strconv.Itoa(n) + " " + label))
		}
		if n < len(steps) {
			line := sDim
			if n < cur {
				line = sOK
			}
			b.WriteString(line.Render(" ──── "))
		}
	}
	return b.String()
}

var pathTitles = map[string]string{"add": "Add servers", "few": "Which servers?", "client": "A client's servers", "fleet": "Your fleet"}

// pathTexts: the paths, as the web page's cards say them.
var pathTexts = map[string]string{
	"add":    "More servers for this organization: paste them, they are checked and scanned on their own.",
	"few":    "A homelab, a VPS, a NAS. Paste an address or user@host; logins come from your SSH setup.",
	"client": "For freelancers: one organization per client, with where their permission is documented.",
	"fleet":  "Tens or hundreds of servers: a list, CSV, an Ansible inventory or ssh config; groups, environments, jump hosts.",
}

func (m *Model) pathName(p string) string {
	switch p {
	case "add":
		o := m.orgRow()
		return m.t.F("Add to {org}", "org", orStr(o.Name, o.ID))
	case "few":
		if m.orgByID("servers") != nil {
			return m.t.T("Add to My servers")
		}
		return m.t.T("My servers")
	case "client":
		return m.t.T("A client's servers")
	}
	return m.t.T("A fleet")
}

func (m *Model) setupView(w, h int) []string {
	wz := m.setup
	out := []string{m.stepper(), ""}
	switch wz.step {
	case 0:
		out = append(out, m.pathsView(w)...)
	case 1:
		out = append(out, m.formView1(w, h-4)...)
	case 2:
		out = append(out, m.checkView(w)...)
	default:
		out = append(out, m.firstScanView(w)...)
	}
	if l := m.dlLine(w); l != "" {
		out = append(out, "", l)
	}
	off := min(wz.off, max(len(out)-h, 0))
	if wz.step == 1 {
		off = 0
	}
	return out[off:]
}

func (m *Model) pathsView(w int) []string {
	wz := m.setup
	out := wrapText(m.t.T("A read-only security audit over SSH: what to patch first, who can get in, what is exposed. Nothing is installed or changed on the servers."), sText, w)
	out = append(out, "")
	icons := map[string]string{"add": "+", "few": "⌂", "client": "⚿", "fleet": "☰"}
	for i, p := range m.setupPaths() {
		name := m.pathName(p)
		text := m.t.T(pathTexts[p])
		if i == wz.pathCur {
			out = append(out, " "+sKey.Render("▶ "+icons[p]+" ")+sBold.Render(name))
			for _, l := range strings.Split(ansi.Wordwrap(text, max(w-8, 20), ""), "\n") {
				out = append(out, "      "+sText.Render(l))
			}
		} else {
			out = append(out, "   "+sMuted.Render(icons[p]+" ")+sText.Render(name))
			for _, l := range strings.Split(ansi.Wordwrap(text, max(w-8, 20), ""), "\n") {
				out = append(out, "      "+sDim.Render(l))
			}
		}
		out = append(out, "")
	}
	keys := sKey.Render("<↑↓>") + " " + sMuted.Render(m.t.T("choose")) + "  " + sKey.Render("<enter>") + " " + sMuted.Render(m.t.T("next"))
	if len(m.orgs.Orgs) > 0 {
		keys += "  " + sKey.Render("<esc>") + " " + sMuted.Render(m.t.T("Cancel"))
	}
	return append(out, " "+keys)
}

// wrapText: text in style, wrapped to w cells, each line indented by one.
func wrapText(s string, style lipgloss.Style, w int) []string {
	var out []string
	for _, l := range strings.Split(ansi.Wordwrap(s, max(w-2, 20), ""), "\n") {
		out = append(out, " "+style.Render(l))
	}
	return out
}

// textBox: a field's text, the cursor shown where it is when it has the keyboard; one string per line.
func textBox(f *field, focus bool, placeholder string) []string {
	if len(f.val) == 0 && !focus {
		return []string{sDim.Render(placeholder)}
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

func (m *Model) formView1(w, h int) []string {
	wz := m.setup
	labelW := 0
	for i, f := range wz.fields {
		if wz.visible(i) && (f.kind == fText || f.kind == fArea || f.kind == fChoice) {
			labelW = max(labelW, ansi.StringWidth(m.t.T(f.label))+map[bool]int{true: 2}[f.fold])
		}
	}
	labelW = min(labelW+2, 26)
	valueW := max(w-labelW-5, 16)
	ind := strings.Repeat(" ", labelW+3)
	var out []string
	curLine := 0
	for i := range wz.fields {
		if !wz.visible(i) {
			continue
		}
		f := &wz.fields[i]
		focus := i == wz.cur
		if focus {
			curLine = len(out)
		}
		mark := "  "
		label := sLabel.Render(fit(m.t.T(f.label), labelW, false))
		if focus {
			mark = sKey.Render("▶ ")
			label = sKey.Render(fit(m.t.T(f.label), labelW, false))
		}
		hint := ""
		if f.hint != "" {
			hint = sMuted.Render(m.t.T(f.hint))
		}
		if f.fold {
			mark = "  " + mark
			label = fit(label, labelW-2, false)
		}
		switch f.kind {
		case fText:
			box := textBox(f, focus, f.placeholder)
			out = append(out, " "+mark+label+" "+box[0]+"  "+hint)
		case fArea:
			box := textBox(f, focus, "")
			l := " " + mark + label + " " + hint
			if m.found != nil && len(m.found.Hosts) > 0 {
				l += "  " + sKey.Render("ctrl+o") + " " + sMuted.Render(m.t.F("choose from ~/.ssh/config ({n})", "n", strconv.Itoa(len(m.found.Hosts))))
			}
			out = append(out, l)
			if len(f.val) == 0 && !focus {
				box = []string{sDim.Render(f.placeholder)}
			}
			rows := 3
			if wz.path == "fleet" {
				rows = 6
			}
			for len(box) < rows {
				box = append(box, "")
			}
			for _, l := range box {
				out = append(out, ind+sDim.Render("│ ")+l)
			}
			out = append(out, m.previewLines(ind, valueW)...)
		case fChoice:
			var o []string
			for j, v := range f.opts {
				name := v
				if j < len(f.shown) && f.shown[j] != "" {
					name = f.shown[j]
				}
				if j == f.opt {
					o = append(o, sBrand.Render("(•) "+name))
				} else {
					o = append(o, sMuted.Render("( ) "+name))
				}
			}
			out = append(out, " "+mark+label+" "+strings.Join(o, "  ")+"   "+hint)
		case fFold:
			arrow := "▸"
			if wz.login {
				arrow = "▾"
			}
			l := sMuted.Render(arrow+" ") + sText.Render(m.t.T(f.label))
			if focus {
				l = sKey.Render(ansi.Strip(l))
			}
			if !wz.login {
				l += sDim.Render("  " + m.t.T("optional: the user and key from your SSH setup"))
			}
			out = append(out, " "+mark+l)
		case fCheck:
			box := sDim.Render("[ ]")
			if f.on {
				box = sBrand.Render("[x]")
			}
			l := box + " " + sText.Render(m.t.T(f.label))
			if focus {
				l = sKey.Render(ansi.Strip(l))
			}
			out = append(out, " "+mark+l)
		case fButton:
			b := sCrumb.Render(m.t.T(f.label))
			if wz.busy {
				b += " " + sRun.Render(m.spinChar()) + " " + sMuted.Render(m.t.T("saving…"))
			}
			out = append(out, "", " "+mark+b)
		}
	}
	if len(wz.errs) > 0 {
		out = append(out, "")
		for _, e := range wz.errs {
			for j, l := range strings.Split(ansi.Wordwrap(e, max(w-6, 20), ""), "\n") {
				p := "   "
				if j == 0 {
					p = " " + sErr.Render("✗ ")
				}
				out = append(out, p+sErr.Render(l))
			}
		}
	}
	out = append(out, "", " "+sKey.Render("<tab>")+" "+sMuted.Render(m.t.T("next field"))+"  "+sKey.Render("<ctrl+s>")+" "+
		sMuted.Render(m.t.T("save"))+"  "+sKey.Render("<ctrl+d>")+" "+sMuted.Render(m.t.T("download now"))+"  "+sKey.Render("<esc>")+" "+sMuted.Render(m.t.T("Back")))
	if off := curLine - (h - 8); off > 0 {
		out = out[min(off, len(out)):]
	}
	if wz.pick != nil {
		out = append(m.pickView(w), out...)
	}
	return out
}

// previewLines: what the server understood of the paste area: ✓ user@address (via a jump host); a table for a
// fleet; the lines it skipped and why.
func (m *Model) previewLines(ind string, w int) []string {
	wz := m.setup
	if wz.parsed == nil || strings.TrimSpace(string(wz.field("hosts").val)) == "" {
		return nil
	}
	defUser := wz.value("user")
	if defUser == "" && wz.field("user") != nil {
		defUser = wz.field("user").placeholder
	}
	var out []string
	hs := wz.parsed.Hosts
	if wz.path == "fleet" && len(hs) > 3 {
		cols := []col{{title: "Name", width: 20}, {title: "User", width: 12}, {title: "Address", width: 24}, {title: "Via", width: 20},
			{title: "Group", min: 8}}
		var rows [][]string
		for _, h := range hs {
			g := strings.Trim(h.Group+" · "+h.Env, " ·")
			rows = append(rows, []string{lipgloss.NewStyle().Foreground(cCyan).Render(h.Name), sText.Render(orStr(h.User, defUser)),
				sText.Render(h.Address), sMuted.Render(h.Jump), sMuted.Render(g)})
		}
		for _, l := range m.grid(cols, rows, w, min(len(rows)+1, 12), false) {
			out = append(out, ind+l)
		}
		if len(rows) > 11 {
			out = append(out, ind+sMuted.Render(m.t.F("{n} more", "n", strconv.Itoa(len(rows)-11))))
		}
	} else {
		for _, h := range hs {
			l := ind + sOK.Render("✓ ") + sText.Render(orStr(h.User, defUser)+"@"+h.Address)
			if h.Jump != "" {
				l += "  " + sMuted.Render(m.t.F("via {j}", "j", h.Jump))
			}
			out = append(out, l)
		}
	}
	if n := len(wz.parsed.Errors); n > 0 {
		out = append(out, ind+lipgloss.NewStyle().Foreground(cP["P3"]).Render("! "+m.t.F("{n} skipped", "n", strconv.Itoa(n))))
		for _, e := range wz.parsed.Errors {
			out = append(out, ind+"  "+sMuted.Render(e))
		}
	}
	return out
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
			l += sMuted.Render(" · " + m.t.F("via {j}", "j", h.Jump))
		}
		if j == p.cur {
			l = sSel.Render(fit(ansi.Strip(l), min(w-4, 70), false))
		}
		lines = append(lines, l)
	}
	if len(list) == 0 {
		lines = append(lines, " "+sMuted.Render(m.t.T("nothing here")))
	}
	lines = append(lines, "", " "+sKey.Render("<space>")+" "+sMuted.Render(m.t.T("toggle"))+"  "+sKey.Render("<enter>")+" "+
		sMuted.Render(m.t.T("Add selected"))+"  "+sKey.Render("<esc>")+" "+sMuted.Render(m.t.T("Cancel")))
	return append(panel(sTitle.Render(m.t.T("Choose from ~/.ssh/config")), lines, min(w, 74), len(lines)+2), "")
}

// checkView: the hosts as their checks answer, grouped: still checking, each cause of failure once (in plain
// words, its hosts on one line, the raw error folded away: e), the ones that answered.
func (m *Model) checkView(w int) []string {
	wz := m.setup
	out := wrapText(m.t.T("Kanareika logs in to each server and runs uname -sr. Nothing is changed."), sText, w)
	if m.err != "" && wz.hosts == nil {
		return append(out, "", " "+sErr.Render("✗ "+m.err))
	}
	if wz.hosts == nil {
		return append(out, "", " "+sRun.Render(m.spinChar())+" "+sMuted.Render(m.t.T("loading")))
	}
	var ok, waiting []hostRef
	type cause struct {
		hint, err string
		hosts     []hostRef
	}
	var causes []*cause
	for _, h := range wz.hosts {
		r := wz.res[h.name]
		switch {
		case r == nil:
			waiting = append(waiting, h)
		case r.OK:
			ok = append(ok, h)
		default:
			k := orStr(r.Hint, r.Error)
			i := slices.IndexFunc(causes, func(c *cause) bool { return orStr(c.hint, c.err) == k })
			if i < 0 {
				causes = append(causes, &cause{hint: r.Hint, err: r.Error})
				i = len(causes) - 1
			}
			causes[i].hosts = append(causes[i].hosts, h)
		}
	}
	out = append(out, "")
	if len(waiting) > 0 {
		secs := strconv.Itoa(int(m.now().Sub(wz.started).Seconds()))
		out = append(out, " "+sRun.Render(m.spinChar()+" ")+sBold.Render(m.t.F("Checking {n}… {s} s", "n", strconv.Itoa(len(waiting)), "s", secs)),
			"   "+hostLine(waiting, w-4, sMuted), "")
	}
	for _, c := range causes {
		for i, l := range strings.Split(ansi.Wordwrap(orStr(c.hint, c.err), max(w-5, 20), ""), "\n") {
			p := "   "
			if i == 0 {
				p = " " + sErr.Render("✗ ")
			}
			out = append(out, p+sBold.Render(l))
		}
		out = append(out, "   "+hostLine(c.hosts, w-4, lipgloss.NewStyle().Foreground(cCyan)))
		if c.hint != "" && wz.raw {
			for _, l := range strings.Split(ansi.Wordwrap(c.err, max(w-6, 20), ""), "\n") {
				out = append(out, "   "+sDim.Render(l))
			}
		}
		out = append(out, "")
	}
	if len(ok) > 0 {
		out = append(out, " "+sOK.Render("✓ "+m.t.F("{n} answered", "n", strconv.Itoa(len(ok)))), "   "+hostLine(ok, w-4, sText), "")
	}
	for _, s := range wz.skipped {
		out = append(out, " "+lipgloss.NewStyle().Foreground(cP["P3"]).Render("! ")+sMuted.Render(s+" · "+m.t.T("skipped")))
	}
	if wz.file != "" {
		out = append(out, " "+sMuted.Render(m.t.F("Addresses and logins are saved in {file}.", "file", wz.file[strings.LastIndex(wz.file, "/")+1:])))
	}
	var keys []string
	switch {
	case len(waiting) > 0:
	case len(ok) > 0:
		scan := m.t.T("Start the first scan")
		if len(causes) > 0 {
			scan = m.t.F("Scan the {n} that answered", "n", strconv.Itoa(len(ok)))
		}
		if m.dlNeeded() && (m.db == nil || !m.db.Updating) {
			scan += " · " + m.t.F("downloads {size} first", "size", dbsize.Bytes(m.dbSize.Total))
		}
		keys = append(keys, sKey.Render("<enter>")+" "+sText.Render(scan))
		if len(causes) > 0 {
			keys = append(keys, sKey.Render("<r>")+" "+sMuted.Render(m.t.T("Check the failed again")))
		}
	default:
		keys = append(keys, sKey.Render("<r>")+" "+sText.Render(m.t.T("Check again")))
	}
	if len(causes) > 0 && slices.ContainsFunc(causes, func(c *cause) bool { return c.hint != "" }) {
		keys = append(keys, sKey.Render("<e>")+" "+sMuted.Render(m.t.T("Details")))
	}
	keys = append(keys, sKey.Render("<esc>")+" "+sMuted.Render(m.t.T("later")))
	return append(out, " "+strings.Join(keys, "  "))
}

// hostLabel: a host as the check shows it: its address, or name · address when the name says something else.
func hostLabel(h hostRef) string {
	a := orStr(h.address, h.name)
	if h.name == a || h.name == strings.Trim(slugRE.ReplaceAllString(strings.ToLower(a), "-"), "-") {
		return a
	}
	return h.name + " · " + a
}

// hostLine: hosts on one line, w cells at most: a name or an address is never cut or wrapped; what doesn't fit is
// counted (+12).
func hostLine(hs []hostRef, w int, style lipgloss.Style) string {
	var b strings.Builder
	used := 0
	for i, h := range hs {
		l := hostLabel(h)
		more := ""
		if rest := len(hs) - i - 1; rest > 0 {
			more = "  +" + strconv.Itoa(rest)
		}
		sep := 0
		if i > 0 {
			sep = 2
		}
		if used+sep+ansi.StringWidth(l)+len(more) > w && i > 0 {
			b.WriteString(sMuted.Render("  +" + strconv.Itoa(len(hs)-i)))
			break
		}
		if i > 0 {
			b.WriteString("  ")
		}
		if ansi.StringWidth(l) > w-len(more) { // one alone wider than the line: cut at its end
			l = ansi.Truncate(l, max(w-len(more), 4), "…")
		}
		b.WriteString(style.Render(l))
		used += sep + ansi.StringWidth(l)
	}
	return b.String()
}

// firstScanView: the first scan's output, then on to the results.
func (m *Model) firstScanView(w int) []string {
	wz := m.setup
	out := wrapText(m.t.T("Databases download first, then every server is read. This takes a few minutes; you can leave the page."), sText, w)
	j := m.jobOf(wz.job)
	if j == nil {
		return append(out, "", " "+sRun.Render(m.spinChar())+" "+sMuted.Render(m.t.T("loading")))
	}
	st := map[string]string{"running": sRun.Render(m.spinChar() + " " + m.t.T("running")), "done": sOK.Render("✓ " + m.t.T("done")),
		"failed": sErr.Render("✗ " + m.t.T("finished with errors")), "cancelled": sMuted.Render(m.t.T("cancelled"))}[j.State]
	out = append(out, "", " "+st, "")
	lines := j.Output
	if len(lines) > 14 {
		lines = lines[len(lines)-14:]
	}
	for _, l := range lines {
		out = append(out, "   "+sMuted.Render(fit(l, max(w-4, 10), false)))
	}
	if j.State != "running" {
		out = append(out, "", " "+sKey.Render("<enter>")+" "+sText.Render(m.t.T("See the results")))
	}
	return out
}

// dlLine: the vulnerability list a scan needs, in one quiet line: how big, downloaded only when asked; its
// download under way; ready. "" where it can't be downloaded (read-only) or before its size is known.
func (m *Model) dlLine(w int) string {
	z, db, wz := m.dbSize, m.db, m.setup
	if !m.scanOK || z == nil {
		return ""
	}
	switch {
	case db != nil && db.Updating:
		secs := 0
		if !m.dlStart.IsZero() {
			secs = int(m.now().Sub(m.dlStart).Seconds())
		}
		return " " + sRun.Render(m.spinChar()) + " " + sText.Render(m.t.F("Downloading the vulnerability list… {s} s", "s", strconv.Itoa(secs)))
	case db != nil && db.Error != "" && wz != nil && wz.dlAsked:
		return ansi.Truncate(" "+sErr.Render("✗ "+m.t.T("The download failed")+": ")+sMuted.Render(db.Error), w-14, ellipsis) + "  " + sKey.Render("<d>") +
			" " + sText.Render(m.t.T("Try again"))
	case len(z.Need) == 0:
		return " " + sOK.Render("✓ "+m.t.T("Vulnerability list ready"))
	}
	return " " + sMuted.Render(m.t.F("Kanareika needs a list of known vulnerabilities: {size}, downloaded once.", "size", dbsize.Bytes(z.Total))) +
		"  " + sKey.Render("<d>") + " " + sText.Render(m.t.T("Download now"))
}
