package tui

import (
	"context"
	"errors"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// The first-run setup, as the web page has it: a form (POST /api/setup), then an SSH check of every host (POST
// /api/setup/check), then the first scan (POST /api/scan) with its progress in Scans, then ToDo. An env with no runs
// yet starts at the check (enter in ToDo).

type fieldKind int

const (
	fText fieldKind = iota
	fArea
	fChoice
	fCheck
	fButton
)

type field struct {
	key   string
	label string
	hint  string
	kind  fieldKind
	val   []rune
	pos   int      // the cursor in val
	opts  []string // a choice's values
	opt   int
	on    bool // a check box
}

type checkResult struct {
	Host    string `json:"host"`
	Address string `json:"address"`
	OK      bool   `json:"ok"`
	System  string `json:"system"`
	Error   string `json:"error"`
	Hint    string `json:"hint"`
}

type wizard struct {
	step     int // 0: the form, 1: the access check
	fields   []field
	cur      int
	errs     map[string][]string // by field key; "" the others
	busy     bool
	org, env string
	results  []checkResult
	checked  bool
	off      int
}

// setupMsg: an answer of the setup API.
type setupMsg struct {
	kind     string // invalid, created, checked
	org, env string
	errs     []string
	results  []checkResult
}

// setupReq: POST /api/setup.
type setupReq struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	User      string `json:"user"`
	Privilege string `json:"privilege"`
	Key       string `json:"key"`
	Port      int    `json:"port"`
	Hosts     string `json:"hosts"`
	Env       string `json:"env"`
	Internet  bool   `json:"internet"`
	Consent   string `json:"consent"`
	Confirmed bool   `json:"confirmed"`
}

func newWizard() *wizard {
	return &wizard{fields: []field{
		{key: "id", label: "organization id", hint: "a-z, 0-9, - and _: the file orgs/<id>.yml"},
		{key: "name", label: "organization name"},
		{key: "env", label: "environment", val: []rune("production"), pos: 10},
		{key: "hosts", label: "hosts", kind: fArea, hint: "one per line: an address, or a name and an address (web-01 192.0.2.11)"},
		{key: "internet", label: "internet-facing", kind: fChoice, opts: []string{"no", "yes"}, hint: "reachable from the internet: priorities go up"},
		{key: "user", label: "SSH user", hint: "a login on the servers, like audit"},
		{key: "privilege", label: "privilege", kind: fChoice, opts: []string{"none", "sudo"}, hint: "sudo: also what only root can read"},
		{key: "key", label: "SSH key file", hint: "empty: the keys of the ssh-agent"},
		{key: "port", label: "SSH port", val: []rune("22"), pos: 2},
		{key: "consent", label: "permission documented in", hint: "a contract, a ticket, an e-mail"},
		{key: "confirmed", label: "I am allowed to audit these servers", kind: fCheck},
		{key: "submit", label: "Create the organization", kind: fButton},
	}}
}

func checkWizard(org, env string) *wizard { return &wizard{step: 1, org: org, env: env} }

// texting: a text field has the keyboard (keys are text, not hotkeys).
func (w *wizard) texting() bool {
	return w.step == 0 && w.cur < len(w.fields) && (w.fields[w.cur].kind == fText || w.fields[w.cur].kind == fArea)
}

func (w *wizard) value(key string) string {
	for _, f := range w.fields {
		if f.key == key {
			switch f.kind {
			case fChoice:
				return f.opts[f.opt]
			case fCheck:
				return strconv.FormatBool(f.on)
			}
			return strings.TrimSpace(string(f.val))
		}
	}
	return ""
}

func (w *wizard) request() setupReq {
	port := 0
	if p := w.value("port"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = -1 // the server says what a port is
		}
		port = n
	}
	return setupReq{ID: strings.ToLower(w.value("id")), Name: w.value("name"), User: w.value("user"), Privilege: w.value("privilege"),
		Key: w.value("key"), Port: port, Hosts: w.value("hosts"), Env: w.value("env"), Internet: w.value("internet") == "yes",
		Consent: w.value("consent"), Confirmed: w.value("confirmed") == "true"}
}

// errField: the field a problem of the server's list is about.
func errField(e string) string {
	for _, p := range []struct{ prefix, key string }{
		{"organization id", "id"}, {"an organization with this id", "id"}, {"organization name", "name"}, {"SSH user", "user"},
		{"privilege", "privilege"}, {"SSH port", "port"}, {"environment", "env"}, {"say where", "consent"}, {"confirm", "confirmed"},
		{"line ", "hosts"}, {"no hosts", "hosts"}, {"host ", "hosts"}, {"key ", "key"},
	} {
		if strings.HasPrefix(e, p.prefix) {
			return p.key
		}
	}
	return ""
}

func (m *Model) submitSetup() tea.Cmd {
	w := m.setup
	if w.busy {
		return nil
	}
	w.busy, w.errs = true, nil
	req, c := w.request(), m.c
	env := req.Env
	if env == "" {
		env = "production"
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		err := c.Post(ctx, "/api/setup", req, nil)
		var ae *APIError
		switch {
		case errors.As(err, &ae) && len(ae.Errors) > 0:
			return setupMsg{kind: "invalid", errs: ae.Errors}
		case err != nil:
			return setupMsg{kind: "invalid", errs: []string{err.Error()}}
		}
		return setupMsg{kind: "created", org: req.ID, env: env}
	}
}

// check: log in to every host of the env (nothing is changed on them).
func (w *wizard) check(m *Model) tea.Cmd {
	w.busy, w.checked, w.results, m.err = true, false, nil, ""
	c, org, env := m.c, w.org, w.env
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout*3)
		defer cancel()
		var out struct {
			Results []checkResult `json:"results"`
		}
		if err := c.Post(ctx, "/api/setup/check", map[string]string{"org": org, "env": env}, &out); err != nil {
			return errMsg{err}
		}
		return setupMsg{kind: "checked", org: org, env: env, results: out.Results}
	}
}

func (m *Model) onSetup(msg setupMsg) tea.Cmd {
	w := m.setup
	if w == nil {
		return nil
	}
	w.busy = false
	switch msg.kind {
	case "invalid":
		w.errs = map[string][]string{}
		first := -1
		for _, e := range msg.errs {
			k := errField(e)
			w.errs[k] = append(w.errs[k], e)
			for i, f := range w.fields {
				if f.key == k && (first < 0 || i < first) {
					first = i
				}
			}
		}
		if first >= 0 {
			w.cur = first
		}
	case "created":
		w.step, w.org, w.env = 1, msg.org, msg.env
		m.say(m.t.F("Organization {org} created", "org", msg.org))
		sel := m.selectEnv(msg.org, msg.env)
		return tea.Batch(m.fetchOrgs(), sel, w.check(m))
	case "checked":
		w.results, w.checked = msg.results, true
	}
	return nil
}

func (m *Model) setupKey(k tea.KeyMsg) tea.Cmd {
	w := m.setup
	s := k.String()
	if w.step == 1 {
		switch s {
		case "esc", "q":
			m.setup = nil
			m.setView(vActions)
		case "r":
			if !w.busy {
				return w.check(m)
			}
		case "enter", "s":
			if !w.busy {
				return m.post("/api/scan", scanRequest{Org: w.org, Env: w.env}, func(v any) tea.Msg {
					id, _ := v.(map[string]any)["id"].(string)
					return startedMsg{id}
				})
			}
		case "up", "k":
			w.off = max(w.off-1, 0)
		case "down", "j":
			w.off++
		}
		return nil
	}
	f := &w.fields[w.cur]
	next := func(d int) { w.cur = min(max(w.cur+d, 0), len(w.fields)-1) }
	before := string(f.val) + strconv.Itoa(f.opt) + strconv.FormatBool(f.on)
	defer func() { // a field changed: its problems are the server's to tell again
		if string(f.val)+strconv.Itoa(f.opt)+strconv.FormatBool(f.on) != before {
			delete(w.errs, f.key)
		}
	}()
	switch s {
	case "esc":
		m.setup = nil
		return nil
	case "ctrl+s":
		return m.submitSetup()
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
	switch f.kind {
	case fButton:
		if s == "enter" || s == " " || s == "space" {
			return m.submitSetup()
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
	return nil
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

func (m *Model) setupTitle() string {
	if m.setup.step == 1 {
		return sTitle.Render(m.t.T("Access check")) + sText.Render("("+m.setup.org+"/"+m.setup.env+")")
	}
	return sTitle.Render(m.t.T("New organization"))
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

func (m *Model) setupView(w, h int) []string {
	wz := m.setup
	if wz.step == 1 {
		return m.checkView(w, h)
	}
	labelW := 0
	for _, f := range wz.fields {
		if f.kind != fCheck && f.kind != fButton {
			labelW = max(labelW, ansi.StringWidth(m.t.T(f.label)))
		}
	}
	labelW = min(labelW+2, 30)
	out := []string{" " + sText.Render(m.t.T("Kanareika logs in to your servers over SSH and only reads: it changes nothing.")),
		" " + sMuted.Render(m.t.T("Auditing servers without their owner's permission is illegal in most countries.")), ""}
	curLine := 0
	errLines := func(key string) {
		for _, e := range wz.errs[key] {
			out = append(out, strings.Repeat(" ", labelW+4)+sErr.Render("✗ "+e))
		}
	}
	for i := range wz.fields {
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
		switch f.kind {
		case fText:
			box := textBox(f, focus, m.t.T(f.hint))
			if len(f.val) > 0 || focus {
				box[0] += "  " + hint
			}
			out = append(out, " "+mark+label+" "+box[0])
		case fArea:
			box := textBox(f, focus, "")
			out = append(out, " "+mark+label+" "+hint)
			for len(box) < 4 {
				box = append(box, "")
			}
			for _, l := range box {
				out = append(out, strings.Repeat(" ", labelW+2)+sDim.Render("│ ")+l)
			}
		case fChoice:
			var o []string
			for j, v := range f.opts {
				if j == f.opt {
					o = append(o, sBrand.Render("(•) "+m.t.T(choiceWords[v])))
				} else {
					o = append(o, sMuted.Render("( ) "+m.t.T(choiceWords[v])))
				}
			}
			out = append(out, " "+mark+label+" "+strings.Join(o, "  ")+"   "+hint)
		case fCheck:
			box := sDim.Render("[ ]")
			if f.on {
				box = sBrand.Render("[x]")
			}
			l := box + " " + sText.Render(m.t.T(f.label))
			if focus {
				l = sKey.Render(ansi.Strip(l))
			}
			out = append(out, " "+mark+strings.Repeat(" ", labelW+1)+l)
		case fButton:
			b := sCrumb.Render(m.t.T(f.label))
			if wz.busy {
				b += " " + sMuted.Render(m.t.T("checking…"))
			}
			out = append(out, "", " "+mark+strings.Repeat(" ", labelW+1)+b)
		}
		errLines(f.key)
	}
	for _, e := range wz.errs[""] {
		out = append(out, " "+sErr.Render("✗ "+e))
	}
	out = append(out, "", " "+sKey.Render("<tab>")+" "+sMuted.Render(m.t.T("next field"))+"  "+sKey.Render("<ctrl+s>")+" "+
		sMuted.Render(m.t.T("create"))+"  "+sKey.Render("<esc>")+" "+sMuted.Render(m.t.T("Cancel")))
	off := 0
	if curLine >= h-2 {
		off = curLine - h + 6
	}
	off = min(max(off, 0), max(len(out)-h, 0))
	return out[off:]
}

func (m *Model) checkView(w, h int) []string {
	wz := m.setup
	out := []string{" " + sText.Render(m.t.T("Kanareika logs in to every host and runs uname: nothing is changed on the servers.")), ""}
	switch {
	case wz.busy:
		out = append(out, " "+sRun.Render(m.t.T("Checking SSH access to every host…")))
	case !wz.checked && m.err != "": // the check could not run at all
		out = append(out, " "+sErr.Render("✗ "+m.err))
	case wz.checked:
		ok := 0
		hw := 0
		for _, r := range wz.results {
			hw = max(hw, ansi.StringWidth(r.Host))
			if r.OK {
				ok++
			}
		}
		for _, r := range wz.results {
			if r.OK {
				out = append(out, " "+sOK.Render("✓ ")+sBold.Render(fit(r.Host, hw, false))+"  "+sMuted.Render(r.Address)+"  "+sText.Render(r.System))
				continue
			}
			out = append(out, " "+sErr.Render("✗ ")+sBold.Render(fit(r.Host, hw, false))+"  "+sMuted.Render(r.Address)+"  "+sErr.Render(r.Error))
			if r.Hint != "" {
				for _, l := range strings.Split(ansi.Wordwrap(r.Hint, max(w-hw-8, 20), ""), "\n") {
					out = append(out, strings.Repeat(" ", hw+5)+sMuted.Render(l))
				}
			}
		}
		style := sOK
		if ok < len(wz.results) {
			style = lipgloss.NewStyle().Foreground(cP["P3"])
		}
		out = append(out, "", " "+style.Render(m.t.F("{ok} of {n} hosts answered", "ok", strconv.Itoa(ok), "n", strconv.Itoa(len(wz.results)))))
		if ok < len(wz.results) {
			out = append(out, " "+sMuted.Render(m.t.T("Hosts that did not answer are left out of the scan's results until they do.")))
		}
	}
	out = append(out, "", " "+sKey.Render("<enter>")+" "+sMuted.Render(m.t.T("Start the first scan"))+"  "+sKey.Render("<r>")+" "+
		sMuted.Render(m.t.T("check again"))+"  "+sKey.Render("<esc>")+" "+sMuted.Render(m.t.T("later")))
	wz.off = min(wz.off, max(len(out)-h, 0))
	return out[wz.off:]
}
