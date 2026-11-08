package tui

import (
	"cmp"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// ToDo: the environment's findings as a tree (GET /api/tree), grouped by fix, CVE or host, the same nodes the web
// page and MCP (list_fixes / get_fix) show; the details of the node under the cursor from GET /api/node.

// tnode: a node of /api/tree.
type tnode struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	Path      string `json:"path"`
	Runtime   string `json:"runtime"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	OS        string `json:"os"`
	Exposure  int    `json:"exposure"`
	Priority  string `json:"priority"`
	Due       string `json:"due"`
	DueWhy    string `json:"due_why"`
	Hosts     int    `json:"hosts"`
	Groups    []struct {
		Name string `json:"name"`
		N    int    `json:"n"`
	} `json:"groups"`
	HostList []string       `json:"host_list"`
	CVEs     int            `json:"cves"`
	EPSS     float64        `json:"epss"`
	KEV      bool           `json:"kev"`
	RCE      bool           `json:"rce"`
	Preauth  bool           `json:"preauth"`
	States   map[string]int `json:"states"`
	Kids     []*tnode       `json:"kids"`
}

type treeResp struct {
	By     string         `json:"by"`
	Nodes  []*tnode       `json:"nodes"`
	Counts map[string]int `json:"counts"`
	Fixes  int            `json:"fixes"`
	CVEs   int            `json:"cves"`
	Hosts  int            `json:"hosts"`
	Hidden int            `json:"hidden_backported"`
}

type reason struct {
	Code string         `json:"code"`
	Args map[string]any `json:"args"`
}

type dueInfo struct {
	Date       string `json:"date"`
	Why        string `json:"why"`
	ClockStart string `json:"clock_start"`
	FirstSeen  string `json:"first_seen"`
	KEVDue     string `json:"kev_due"`
	Overdue    int    `json:"overdue"`
	In         int    `json:"in"`
}

type cveInfo struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	CVSS     *float64 `json:"cvss"`
	EPSS     *float64 `json:"epss"`
	KEV      bool     `json:"kev"`
	RCE      bool     `json:"rce"`
	Preauth  bool     `json:"preauth"`
	Hosts    int      `json:"hosts"`
}

type whereInfo struct {
	Group    string         `json:"group"`
	Hosts    []string       `json:"hosts"`
	OS       string         `json:"os"`
	Exposure int            `json:"exposure"`
	States   map[string]int `json:"states"`
}

type applyStep struct {
	OS      string   `json:"os"`
	Hosts   []string `json:"hosts"`
	Command string   `json:"command"`
	Reboot  bool     `json:"reboot"`
}

// nodeDetail: GET /api/node.
type nodeDetail struct {
	Node    *tnode      `json:"node"`
	Why     []reason    `json:"why"`
	Due     dueInfo     `json:"due"`
	CVEs    []cveInfo   `json:"cves"`
	Where   []whereInfo `json:"where"`
	Apply   []applyStep `json:"apply"`
	Actions []string    `json:"actions"`
}

type (
	treeMsg struct {
		key string
		d   *treeResp
	}
	nodeMsg struct {
		key string
		d   *nodeDetail
	}
	// jumpTreeMsg: a tree of the jump palette (all fixes or all CVEs, no filters)
	jumpTreeMsg struct {
		by string
		d  *treeResp
	}
)

// Groupings and filters, in the order g and the filter menu go through them.
var (
	groupings   = []string{"fix", "cve", "host"}
	treeFilters = []struct{ key, label string }{
		{key: "kev", label: "in CISA KEV"},
		{key: "rce", label: "remote code execution"},
		{key: "epss", label: "EPSS 10% or more"},
		{key: "front", label: "internet-facing"},
		{key: "ready", label: "fix ready"},
		{key: "nofix", label: "no fix yet"},
		{key: "overdue", label: "overdue"},
		{key: "backported", label: "fixed by a backport too"},
	}
)

// Names on screen: of the groupings, of the sections inside an image, of the popup lists, of a form's choices.
var (
	groupNames   = map[string]string{"fix": "fix", "cve": "CVE", "host": "host"}
	sectionNames = map[string]string{"parts": "components", "where": "runs on"}
	menuTitles   = map[string]string{"filters": "Filters", "orgs": "Organizations", "envs": "Environments", "jump": "Jump to"}
	choiceWords  = map[string]string{"no": "no", "yes": "yes", "none": "none", "sudo": "sudo"}
)

const wideDetails = 140 // from this width the details pane stands next to the tree

// treeQuery: the query of /api/tree for the grouping, filters and text filter on screen.
func (m *Model) treeQuery() string {
	v := url.Values{}
	v.Set("org", m.org)
	v.Set("env", m.env)
	v.Set("run", m.run)
	v.Set("by", m.by)
	var f []string
	for _, x := range treeFilters {
		if m.flt[x.key] && x.key != "backported" {
			f = append(f, x.key)
		}
	}
	if len(f) > 0 {
		v.Set("f", strings.Join(f, ","))
	}
	if m.view == vActions && m.filter != "" {
		v.Set("q", m.filter)
	}
	if m.flt["backported"] {
		v.Set("backported", "1")
	}
	return v.Encode()
}

func (m *Model) wantTree() string { return m.wantKey() + "?" + m.treeQuery() }

// sync: fetch what the screen needs and doesn't have yet: the tree, the details of the node under the cursor.
func (m *Model) sync() tea.Cmd {
	if m.run == "" || m.org == "" || m.runKey != m.wantKey() {
		return nil
	}
	if k := m.wantTree(); k != m.treeKey && k != m.pending["tree"] {
		m.pending["tree"] = k
		q := "/api/tree?" + m.treeQuery()
		return m.get(q, func(v any) tea.Msg { return treeMsg{k, v.(*treeResp)} }, &treeResp{})
	}
	if m.tree == nil || m.view != vActions || !m.full && m.w < wideDetails {
		return nil
	}
	n := m.curNode()
	if n == nil || n.Kind == "section" {
		return nil
	}
	return m.fetchNode(n.ID, nil)
}

// fetchNode: the details of node id (then done with them, if given); nil when they are here or on the way.
func (m *Model) fetchNode(id string, done func(*nodeDetail) tea.Msg) tea.Cmd {
	k := m.treeKey + "#" + id
	if d := m.nodes[k]; d != nil {
		if done != nil {
			return func() tea.Msg { return done(d) }
		}
		return nil
	}
	if m.pending[k] != "" && done == nil {
		return nil
	}
	m.pending[k] = k
	q := "/api/node?" + m.treeQuery() + "&id=" + url.QueryEscape(id)
	return m.get(q, func(v any) tea.Msg {
		d := v.(*nodeDetail)
		if done != nil {
			return tea.BatchMsg{func() tea.Msg { return nodeMsg{k, d} }, func() tea.Msg { return done(d) }}
		}
		return nodeMsg{k, d}
	}, &nodeDetail{})
}

func (m *Model) onTree(msg treeMsg) {
	if msg.key == m.pending["tree"] {
		delete(m.pending, "tree")
	}
	if msg.key != m.wantTree() {
		return
	}
	m.tree, m.treeKey, m.nodes = msg.d, msg.key, map[string]*nodeDetail{}
	for k := range m.pending {
		if k != "tree" {
			delete(m.pending, k)
		}
	}
	if m.jumpTo != "" {
		m.curID, m.jumpTo = m.jumpTo, ""
	}
	m.placeCursor()
}

// placeCursor: the cursor back on the node it was on (the tree was rebuilt), or the nearest row.
func (m *Model) placeCursor() {
	rows := m.treeRows()
	if i := slices.IndexFunc(rows, func(r trow) bool { return r.n.ID == m.curID }); i >= 0 {
		m.cur[vActions] = i
		return
	}
	m.cur[vActions] = min(m.cur[vActions], max(len(rows)-1, 0))
	if len(rows) > 0 {
		m.curID = rows[m.cur[vActions]].n.ID
	}
}

// trow: a line of the tree as drawn: the node, how deep, the tree lines in front of it.
type trow struct {
	n      *tnode
	depth  int
	prefix string
}

// treeRows: the open part of the tree, most urgent first; P4 only when shown (p), only the selected with v.
func (m *Model) treeRows() []trow {
	if m.tree == nil {
		return nil
	}
	var out []trow
	var walk func(ns []*tnode, depth int, pre string)
	walk = func(ns []*tnode, depth int, pre string) {
		for i, n := range ns {
			if depth == 0 && m.onlySel && !m.anySel(n) {
				continue
			}
			if depth == 0 && !m.onlySel && !m.set.ShowP4 && (n.Priority == "P4" || n.Priority == "") && m.by != "host" {
				continue
			}
			last := i == len(ns)-1
			p := ""
			if depth > 0 {
				p = pre + map[bool]string{true: "└ ", false: "├ "}[last]
			}
			out = append(out, trow{n, depth, p})
			if m.opened[n.ID] && len(n.Kids) > 0 {
				np := pre
				if depth > 0 {
					np += map[bool]string{true: "  ", false: "│ "}[last]
				}
				walk(n.Kids, depth+1, np)
			}
		}
	}
	walk(m.tree.Nodes, 0, "")
	return out
}

func (m *Model) curNode() *tnode {
	rows := m.treeRows()
	if c := m.cur[vActions]; c < len(rows) {
		return rows[c].n
	}
	return nil
}

// --- selection: a node selects everything under it; a node is selected when everything under it is --------------------

func (m *Model) anySel(n *tnode) bool {
	if m.sel[n.ID] {
		return true
	}
	return slices.ContainsFunc(n.Kids, m.anySel)
}

func (m *Model) toggleSel(n *tnode) {
	if n.Kind == "section" {
		return
	}
	on := !m.sel[n.ID]
	var set func(*tnode)
	set = func(x *tnode) {
		if on && x.Kind != "section" {
			m.sel[x.ID] = true
		} else {
			delete(m.sel, x.ID)
		}
		for _, k := range x.Kids {
			set(k)
		}
	}
	set(n)
	m.fixParents()
}

func (m *Model) fixParents() {
	if m.tree == nil {
		return
	}
	var walk func(n *tnode) bool
	walk = func(n *tnode) bool {
		all, any := true, false
		for _, k := range n.Kids {
			if k.Kind == "section" {
				continue
			}
			any = true
			if !walk(k) {
				all = false
			}
		}
		switch {
		case any && all:
			m.sel[n.ID] = true
		case any:
			delete(m.sel, n.ID)
		}
		return m.sel[n.ID]
	}
	for _, n := range m.tree.Nodes {
		walk(n)
	}
}

// picked: the selected nodes, the topmost of each branch, in the order of the tree.
func (m *Model) picked() []*tnode {
	if m.tree == nil {
		return nil
	}
	var out []*tnode
	var walk func([]*tnode)
	walk = func(ns []*tnode) {
		for _, n := range ns {
			if m.sel[n.ID] {
				out = append(out, n)
				continue
			}
			walk(n.Kids)
		}
	}
	walk(m.tree.Nodes)
	return out
}

// --- keys -----------------------------------------------------------------------------------------------------------

// todoKey: the keys of the tree; false when the key is not one of them.
func (m *Model) todoKey(s string) (tea.Cmd, bool) {
	if m.full {
		switch s {
		case "up", "k":
			m.detOff = max(m.detOff-1, 0)
		case "down", "j":
			m.detOff++
		case "pgup", "ctrl+b":
			m.detOff = max(m.detOff-m.page(), 0)
		case "pgdown", "ctrl+f", " ", "space":
			m.detOff += m.page()
		case "home":
			m.detOff = 0
		case "esc", "enter", "backspace", "left", "h":
			m.full, m.detOff = false, 0
		case "c", "[", "]", "y", "Y":
			return m.detailKey(s), true
		default:
			return nil, s != "q" && s != "?" && s != "ctrl+c"
		}
		return nil, true
	}
	rows := m.treeRows()
	c := m.cur[vActions]
	var n *tnode
	if c < len(rows) {
		n = rows[c].n
	}
	switch s {
	case "right", "l":
		if n != nil && len(n.Kids) > 0 {
			if m.opened[n.ID] {
				m.move(1)
			} else {
				m.opened[n.ID] = true
			}
		}
	case "left", "h":
		if n == nil {
			break
		}
		if m.opened[n.ID] && len(n.Kids) > 0 {
			delete(m.opened, n.ID)
			break
		}
		for i := c - 1; i >= 0; i-- { // to the parent
			if rows[i].depth < rows[c].depth {
				m.cur[vActions], m.curID = i, rows[i].n.ID
				break
			}
		}
	case "space", " ", "x":
		if n != nil {
			m.toggleSel(n)
			m.move(1)
		}
	case "a":
		var top []*tnode
		for _, r := range rows {
			if r.depth == 0 {
				top = append(top, r.n)
			}
		}
		all := len(top) > 0 && !slices.ContainsFunc(top, func(t *tnode) bool { return !m.sel[t.ID] })
		for _, t := range top {
			if m.sel[t.ID] == all {
				m.toggleSel(t)
			}
		}
	case "enter":
		if n == nil {
			return nil, false // no tree (no runs yet): the view's enter
		}
		if n.Kind != "section" {
			m.full, m.detOff = true, 0
		}
	case "g":
		m.by = groupings[(slices.Index(groupings, m.by)+1)%len(groupings)]
		m.cur[vActions], m.off[vActions], m.curID = 0, 0, ""
	case "G":
		m.move(1 << 30)
	case "f":
		m.menu = &menuDlg{kind: "filters"}
	case "p":
		m.toggleP4()
	case "v":
		m.onlySel = !m.onlySel
		m.cur[vActions], m.off[vActions] = 0, 0
		if m.onlySel && len(m.sel) == 0 {
			m.say(m.t.T("Nothing selected yet: space selects a node"))
		}
	case "y", "Y", "c", "[", "]":
		return m.detailKey(s), true
	default:
		return nil, false
	}
	return nil, true
}

// detailKey: copying (the task, the context, a command) and choosing the command.
func (m *Model) detailKey(s string) tea.Cmd {
	n := m.curNode()
	switch s {
	case "y":
		return m.copyTask()
	case "Y":
		if n == nil || n.Kind == "section" {
			return nil
		}
		return m.fetchNode(n.ID, func(d *nodeDetail) tea.Msg {
			return m.copyText(m.agentContext(d), m.t.T("Context copied to the clipboard"))
		})
	case "[", "]":
		if d := m.curDetail(); d != nil && len(d.Apply) > 0 {
			step := map[string]int{"[": -1, "]": 1}[s]
			m.cmdCur = (m.cmdCur + step + len(d.Apply)) % len(d.Apply)
		}
	case "c":
		d := m.curDetail()
		if d == nil || len(d.Apply) == 0 {
			m.say(m.t.T("No command to copy for this node"))
			return nil
		}
		cmd := d.Apply[min(m.cmdCur, len(d.Apply)-1)].Command
		return func() tea.Msg { return m.copyText(cmd, m.t.T("Command copied to the clipboard")) }
	}
	return nil
}

func (m *Model) curDetail() *nodeDetail {
	if n := m.curNode(); n != nil {
		return m.nodes[m.treeKey+"#"+n.ID]
	}
	return nil
}

// copyText: text to the terminal clipboard (OSC 52, also over SSH); the message to show.
func (m *Model) copyText(text, done string) tea.Msg {
	if m.clip == nil {
		return toastMsg(m.t.T("This terminal session can't copy"))
	}
	_, _ = fmt.Fprintf(m.clip, "\x1b]52;c;%s\a", b64(text))
	return toastMsg(done)
}

// copyTask: the agent task for the selected nodes (or the one under the cursor), built by the server from the
// actions under them (GET /api/prompt?nodes=).
func (m *Model) copyTask() tea.Cmd {
	var ids []string
	for _, n := range m.picked() {
		ids = append(ids, n.ID)
	}
	if n := m.curNode(); len(ids) == 0 && n != nil && n.Kind != "section" {
		ids = []string{n.ID}
	}
	if len(ids) == 0 || m.run == "" {
		return nil
	}
	if m.clip == nil {
		m.say(m.t.T("This terminal session can't copy"))
		return nil
	}
	q := "/api/prompt?" + m.treeQuery() + "&lang=" + url.QueryEscape(m.t.lang) + "&nodes=" + url.QueryEscape(strings.Join(ids, ","))
	done := fmt.Sprintf("%s (%d)", m.t.T("Task copied to the clipboard"), len(ids))
	var out struct {
		Text string `json:"text"`
	}
	return m.get(q, func(any) tea.Msg { return m.copyText(out.Text, done) }, &out)
}

// agentContext: the node under the cursor in a few lines for an AI agent's chat: what, where, why, due, how, and
// how to ask kanareika's MCP server for more. English: what agents read best, whatever the interface's language.
func (m *Model) agentContext(d *nodeDetail) string {
	n := d.Node
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}
	line("kanareika finding", m.org+"/"+m.env+" (run "+m.run+")")
	line("node", n.ID)
	line("what", ansi.Strip(m.nodeText(n, true, false)))
	facts := []string{n.Priority, plural(n.Hosts, "host"), plural(n.CVEs, "CVE")}
	if n.EPSS > 0 {
		facts = append(facts, "EPSS "+epssText(n.EPSS))
	}
	if n.KEV {
		facts = append(facts, "in CISA KEV")
	}
	if n.RCE {
		facts = append(facts, "RCE without login")
	}
	line("facts", strings.Join(facts, ", "))
	var why []string
	for _, r := range d.Why {
		why = append(why, whyText(&tr{lang: "en"}, r))
	}
	line("why", strings.Join(why, "; "))
	line("due", ansi.Strip(dueText(&tr{lang: "en"}, n.Priority, d.Due, m.today())))
	for _, c := range d.CVEs {
		s := c.ID + " " + c.Severity
		if c.EPSS != nil {
			s += " EPSS " + epssText(*c.EPSS)
		}
		if c.KEV {
			s += " KEV"
		}
		if c.RCE {
			s += " RCE"
		}
		line("cve", s+" — "+c.Title)
	}
	for _, w := range d.Where {
		s := fmt.Sprintf("%s (%s, %s)", w.Group, plural(len(w.Hosts), "host"), w.OS)
		if len(w.Hosts) <= 12 {
			s += ": " + strings.Join(w.Hosts, ", ")
		}
		line("where", s)
	}
	for _, a := range d.Apply {
		line("apply on "+a.OS+" ("+plural(len(a.Hosts), "host")+")", a.Command)
	}
	if len(d.Actions) > 0 {
		line("action ids", strings.Join(d.Actions, ", "))
	}
	fmt.Fprintf(&b, "more: kanareika MCP get_fix org=%s env=%s by=%s id=%q; fix_prompt / fix_plan take the action ids\n", m.org, m.env, m.by, n.ID)
	return b.String()
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return strconv.Itoa(n) + " " + what + "s"
}

// --- drawing ----------------------------------------------------------------------------------------------------------

func epssText(e float64) string {
	switch {
	case e <= 0:
		return ""
	case e < 0.01:
		return "<1%"
	case e < 0.1:
		return strconv.FormatFloat(math.Round(e*1000)/10, 'f', -1, 64) + "%"
	}
	return strconv.Itoa(int(math.Round(e*100))) + "%"
}

var sevStyle = map[string]lipgloss.Style{
	"CRITICAL": lipgloss.NewStyle().Foreground(cP["P1"]).Bold(true), "HIGH": lipgloss.NewStyle().Foreground(cP["P2"]),
	"MEDIUM": lipgloss.NewStyle().Foreground(cP["P3"]), "LOW": sMuted,
}

var sevShort = map[string]string{"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "UNKNOWN": "?"}

// kindOf: the kind slot of a row: what sort of fix it is, or a CVE's severity.
func kindOf(n *tnode) string {
	switch n.Kind {
	case "pkg":
		if n.Path != "" {
			return sMuted.Render("lib")
		}
		return sMuted.Render("os")
	case "image":
		return lipgloss.NewStyle().Foreground(cCyan).Render(n.Runtime)
	case "part":
		if n.Path != "" {
			return sMuted.Render("lib")
		}
		return sMuted.Render("os")
	case "cve":
		if s, ok := sevShort[n.Severity]; ok {
			return sevStyle[n.Severity].Render(s)
		}
		return ""
	case "other":
		check := ""
		if p := strings.SplitN(n.ID, ":", 4); len(p) >= 3 {
			check = p[2]
		}
		switch {
		case strings.Contains(check, "eol"):
			return sMuted.Render("eol")
		case n.Title == "access" || n.Title == "health":
			return sMuted.Render(n.Title)
		}
		return sMuted.Render("config")
	}
	return ""
}

// shortImage: an image without its registry (registry.example.com/api:2.11.3 -> api:2.11.3).
func shortImage(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// nodeText: what a node is in a line (the tree's text column; full: the details pane's title).
func (m *Model) nodeText(n *tnode, full, styled bool) string {
	st := func(s lipgloss.Style, t string) string {
		if !styled {
			return t
		}
		return s.Render(t)
	}
	arrow := " " + st(sMuted, "→") + " "
	switch n.Kind {
	case "pkg", "part":
		s := st(sBold, n.Label) + " "
		if n.Fixed == "" {
			s += st(sMuted, n.Installed) + "  " + st(lipgloss.NewStyle().Foreground(cP["P3"]), m.t.T("no fix yet"))
		} else {
			s += st(sMuted, n.Installed) + arrow + st(sOK, n.Fixed)
		}
		if n.Path != "" && (full || n.Kind == "part") {
			s += "  " + st(sDim, n.Path)
		}
		if r := n.States["reboot"]; r > 0 && n.Kind == "pkg" {
			s += "  " + st(sMuted, m.t.F("{n} reboot", "n", strconv.Itoa(r)))
		}
		return s
	case "image":
		label := n.Label
		if !full {
			label = shortImage(label)
		}
		var parts []string
		for _, k := range n.Kids {
			if k.Kind == "part" && !slices.Contains(parts, k.Label) {
				parts = append(parts, k.Label)
			}
		}
		s := st(sBold, label)
		if len(parts) > 0 {
			s += "  " + st(sMuted, m.t.F("rebuild: {parts}", "parts", strings.Join(parts, ", ")))
		}
		return s
	case "where":
		l := strings.TrimPrefix(n.Label, "image:")
		if !full {
			l = shortImage(l)
		}
		return st(lipgloss.NewStyle().Foreground(cCyan), l) + "  " + st(sMuted, m.hostsN(n.Hosts))
	case "section":
		return st(sDim, strings.ToUpper(m.t.T(sectionNames[n.Label])))
	case "group":
		s := st(lipgloss.NewStyle().Foreground(cCyan), cmp.Or(n.Label, "—")) + "  " + st(sText, m.hostsN(n.Hosts))
		if n.OS != "" {
			s += st(sMuted, " · "+n.OS)
		}
		return s
	case "host":
		s := st(lipgloss.NewStyle().Foreground(cCyan), n.Label)
		if n.OS != "" {
			s += st(sMuted, " · "+n.OS)
		}
		if n.Exposure == 1 {
			s += "  " + st(lipgloss.NewStyle().Foreground(cP["P2"]), m.t.T("internet-facing"))
		}
		return s
	case "cve":
		return st(sBold, n.Label) + "  " + st(sMuted, n.Title)
	}
	return st(sText, n.Label)
}

// today: the date due dates are judged by (UTC, as the server's "overdue").
func (m *Model) today() string { return m.now().UTC().Format(time.DateOnly) }

// days: from one date to another (YYYY-MM-DD); 0 when either can't be read.
func days(from, to string) int {
	a, err1 := time.Parse(time.DateOnly, from)
	b, err2 := time.Parse(time.DateOnly, to)
	if err1 != nil || err2 != nil {
		return 0
	}
	return int(b.Sub(a).Hours() / 24)
}

func (m *Model) hostsN(n int) string {
	if n == 1 {
		return m.t.T("1 host")
	}
	return m.t.F("{n} hosts", "n", strconv.Itoa(n))
}

// dueCell: the due date as the tree shows it: how late, how soon, or the date.
func (m *Model) dueCell(due string) string {
	if _, err := time.Parse(time.DateOnly, due); err != nil {
		return due
	}
	days := days(m.today(), due)
	switch {
	case days < 0:
		return sErr.Render(m.t.F("{n} d late", "n", strconv.Itoa(-days)))
	case days == 0:
		return sErr.Render(m.t.T("today"))
	case days <= 14:
		return lipgloss.NewStyle().Foreground(cP["P3"]).Render(m.t.F("in {n} d", "n", strconv.Itoa(days)))
	}
	return sMuted.Render(due)
}

// treeCols: check, caret, priority, kind, the text with the tree in it, hosts, CVE, EPSS, flag, due. Every row has
// every cell, so they line up.
func (m *Model) treeCols() []col {
	text := groupNames[m.by]
	return []col{{width: 1}, {width: 1}, {width: 2}, {width: 6}, {title: text, min: 18},
		{title: "hosts", width: 5, right: true, drop: 2}, {title: "CVE", width: 4, right: true, drop: 4},
		{title: "EPSS", width: 5, right: true, drop: 5}, {width: 3, drop: 3}, {title: "due by", width: 11, right: true, drop: 1}}
}

func (m *Model) treeView(w, h int) []string {
	if m.rund == nil {
		return m.noData()
	}
	if m.tree == nil {
		return []string{" " + sMuted.Render(m.t.T("loading"))}
	}
	rows := m.treeRows()
	cells := make([][]string, 0, len(rows))
	for _, r := range rows {
		n := r.n
		box := sDim.Render("○")
		switch {
		case n.Kind == "section":
			box = ""
		case m.sel[n.ID]:
			box = sBrand.Render("●")
		case m.anySel(n):
			box = sBrand.Render("◐")
		}
		caret := ""
		if len(n.Kids) > 0 {
			caret = sMuted.Render("▸")
			if m.opened[n.ID] {
				caret = sMuted.Render("▾")
			}
		}
		p := ""
		if n.Kind != "section" && m.primary(r) {
			p = prio(n.Priority)
		}
		var hosts, cves, epss, flag, due string
		if n.Kind != "section" {
			hosts = sBold.Render(strconv.Itoa(n.Hosts))
			if n.CVEs > 0 {
				cves = sMuted.Render(strconv.Itoa(n.CVEs))
			}
			if e := epssText(n.EPSS); e != "" {
				epss = sMuted.Render(e)
				if n.EPSS >= 0.1 {
					epss = sErr.Render(e)
				}
			}
			switch {
			case n.KEV:
				flag = lipgloss.NewStyle().Foreground(cP["P2"]).Bold(true).Render("KEV")
			case n.RCE:
				flag = sErr.Render("RCE")
			}
			if m.primary(r) {
				due = m.dueCell(n.Due)
			}
		}
		cells = append(cells, []string{box, caret, p, kindOf(n), sDim.Render(r.prefix) + m.nodeText(n, false, true), hosts, cves, epss, flag, due})
	}
	if len(rows) == 0 && m.tree.Hidden > 0 && !m.flt["backported"] {
		return append(m.table(m.treeCols(), nil, w, h), "", " "+sMuted.Render(m.t.F("{n} found CVEs are fixed by backports (f: show them)", "n", strconv.Itoa(m.tree.Hidden))))
	}
	return m.table(m.treeCols(), cells, w, h)
}

// primary: a row that is a thing to do, with its own priority and due date shown; hosts and groups under a fix or
// a CVE only say where it is (grouped by host they are what the tree is about).
func (m *Model) primary(r trow) bool {
	return r.depth == 0 || m.by == "host" || r.n.Kind != "group" && r.n.Kind != "host" && r.n.Kind != "where"
}

// todoTitle: ToDo(org/env)[nodes listed] P1 n P2 n ... </query> and the filters on.
func (m *Model) todoTitle() string {
	n := 0
	for _, r := range m.treeRows() {
		if r.depth == 0 {
			n++
		}
	}
	t := m.title(viewNames[vActions], n, true)
	if m.tree != nil {
		var c []string
		for _, p := range []string{"P1", "P2", "P3", "P4"} {
			c = append(c, prio(p)+" "+count(p, m.tree.Counts[p], true))
		}
		t += " " + strings.Join(c, " ")
	}
	for _, f := range treeFilters {
		if m.flt[f.key] {
			t += " " + sCrumb2.Render(m.t.T(f.label))
		}
	}
	if m.onlySel {
		t += " " + sKey.Render("<v>") + sMuted.Render(" "+m.t.T("selected only"))
	}
	return t
}

// todoBody: the tree, with the details pane at its right on a wide terminal; the details alone when opened.
func (m *Model) todoMain(h int) []string {
	w := m.w
	if m.full {
		n := m.curNode()
		title := sTitle.Render(m.t.T("Details"))
		if n != nil {
			title += sText.Render("(" + ansi.Strip(m.nodeText(n, false, false)) + ")")
		}
		lines := m.detailView(w-2, true)
		m.detOff = min(m.detOff, max(len(lines)-(h-2), 0))
		return panel(title, lines[m.detOff:], w, h)
	}
	if w < wideDetails || m.rund == nil {
		return panel(m.todoTitle(), m.treeView(w-2, h-2), w, h)
	}
	right := min(max(w*2/5, 50), 80)
	left := panel(m.todoTitle(), m.treeView(w-right-2, h-2), w-right, h)
	det := panel(sTitle.Render(m.t.T("Details")), m.detailView(right-2, false), right, h)
	for i := range left {
		left[i] = fit(left[i], w-right, false) + det[i]
	}
	return left
}

// whyTexts: the reasons for a priority in words (GET /api/node .why codes).
var whyTexts = map[string]string{
	"kev":      "in CISA KEV: exploited in the wild",
	"rce":      "remote code execution without login",
	"preauth":  "exploitable without logging in",
	"epss":     "EPSS {epss}: likely to be exploited within 30 days",
	"front":    "{n} of {of} hosts are internet-facing",
	"nofix":    "no fix in the repositories yet on {n} hosts",
	"reboot":   "installed, waiting for a reboot on {n} hosts",
	"severity": "severity {severity}",
}

func whyText(t *tr, r reason) string {
	tmpl, ok := whyTexts[r.Code]
	if !ok {
		return r.Code
	}
	var kv []string
	for k, v := range r.Args {
		s := str(v)
		if k == "epss" {
			s = epssText(num(v))
		}
		kv = append(kv, k, s)
	}
	return t.F(tmpl, kv...)
}

// dueWhy: where a due date comes from, in words ({date}: the day the clock started, {p} {n}: the SLA).
var dueWhy = map[string]string{
	"first_seen":      "first seen {date}, {p} = {n} days",
	"fix_available":   "a fix since {date}, {p} = {n} days",
	"published":       "published {date}, {p} = {n} days",
	"scan":            "scanned {date}, {p} = {n} days",
	"escalated":       "priority raised {date}, {p} = {n} days",
	"exception_ended": "accepted risk ended {date}, {p} = {n} days",
	"kev":             "CISA KEV due date",
	"no_fix":          "no fix yet: the clock starts when there is one",
}

// dueText: "due 2026-11-09 · overdue 1 d · first seen 2026-11-02, P1 = 7 days".
func dueText(t *tr, p string, d dueInfo, today string) string {
	var parts []string
	if d.Date != "" {
		parts = append(parts, t.F("due {date}", "date", d.Date))
		in := days(today, d.Date) // by the clock on screen, as the tree's column
		switch {
		case in < 0:
			parts = append(parts, sErr.Render(t.F("overdue {n} d", "n", strconv.Itoa(-in))))
		case in == 0:
			parts = append(parts, sErr.Render(t.T("today")))
		default:
			parts = append(parts, t.F("in {n} d", "n", strconv.Itoa(in)))
		}
	}
	if tmpl, ok := dueWhy[d.Why]; ok {
		start := d.ClockStart
		if d.Why == "first_seen" && d.FirstSeen != "" {
			start = d.FirstSeen
		}
		sla := ""
		if a, err1 := time.Parse(time.DateOnly, d.ClockStart); err1 == nil {
			if b, err2 := time.Parse(time.DateOnly, d.Date); err2 == nil {
				sla = strconv.Itoa(int(b.Sub(a).Hours() / 24))
			}
		}
		switch {
		case d.Why == "kev" && d.KEVDue != "":
			parts = append(parts, t.T(tmpl)+" "+d.KEVDue)
		case strings.Contains(tmpl, "{n}") && (sla == "" || start == ""):
		default:
			parts = append(parts, t.F(tmpl, "date", start, "p", p, "n", sla))
		}
		if d.FirstSeen != "" && d.Why != "first_seen" {
			parts = append(parts, t.F("first seen {date}", "date", d.FirstSeen))
		}
	}
	return strings.Join(parts, " · ")
}

// stateWords: hosts per fix state, as the details pane says them.
var stateWords = []struct{ key, label string }{
	{key: "available", label: "ready"}, {key: "reboot", label: "reboot pending"}, {key: "vendor", label: "no fix yet"},
	{key: "backported", label: "fixed by a backport"}, {key: "other", label: "to do"},
}

func (m *Model) states(st map[string]int) string {
	var out []string
	for _, s := range stateWords {
		if n := st[s.key]; n > 0 {
			style := sMuted
			switch s.key {
			case "available":
				style = sOK
			case "vendor":
				style = lipgloss.NewStyle().Foreground(cP["P3"])
			}
			out = append(out, style.Render("● "+m.t.T(s.label)+" "+strconv.Itoa(n)))
		}
	}
	return strings.Join(out, " ")
}

// detailView: why the priority, the due date, the CVEs, where, the commands; w cells wide.
func (m *Model) detailView(w int, full bool) []string {
	n := m.curNode()
	if n == nil {
		return []string{" " + sMuted.Render(m.t.T("nothing here"))}
	}
	if n.Kind == "section" {
		return nil
	}
	d := m.nodes[m.treeKey+"#"+n.ID]
	var out []string
	wrap := func(prefix, s string) {
		for _, l := range strings.Split(ansi.Wordwrap(s, max(w-ansi.StringWidth(prefix)-1, 10), ""), "\n") {
			out = append(out, prefix+l)
			prefix = strings.Repeat(" ", ansi.StringWidth(prefix))
		}
	}
	head := func(s string) { out = append(out, "", " "+sLabel.Render(strings.ToUpper(s))) }
	wrap(" "+prio(n.Priority)+" ", m.nodeText(n, true, true))
	if d == nil {
		return append(out, "", " "+sMuted.Render(m.t.T("loading")))
	}
	facts := []string{m.hostsN(n.Hosts)}
	if n.CVEs > 0 {
		facts = append(facts, fmt.Sprintf("%d CVE", n.CVEs))
	}
	if len(n.Groups) > 1 {
		facts = append(facts, m.t.F("{n} groups", "n", strconv.Itoa(len(n.Groups))))
	}
	if n.EPSS > 0 {
		facts = append(facts, "EPSS "+epssText(n.EPSS))
	}
	out = append(out, " "+sMuted.Render(strings.Join(facts, " · ")))

	head(m.t.F("why {p}", "p", n.Priority))
	if len(d.Why) == 0 {
		out = append(out, " "+sMuted.Render(m.t.T("the priority of its findings")))
	}
	for _, r := range d.Why {
		mark := sMuted.Render(" ● ")
		if r.Code == "kev" || r.Code == "rce" || r.Code == "epss" {
			mark = sErr.Render(" ▲ ")
		}
		wrap(mark, sText.Render(whyText(m.t, r)))
	}
	if dt := dueText(m.t, n.Priority, d.Due, m.today()); dt != "" {
		head(m.t.T("due by"))
		wrap(" ", sText.Render(dt))
	}
	if len(d.CVEs) > 0 {
		head(fmt.Sprintf("CVE (%d)", len(d.CVEs)))
		limit := len(d.CVEs)
		if !full {
			limit = min(limit, 6)
		}
		for _, c := range d.CVEs[:limit] {
			e := ""
			if c.EPSS != nil {
				e = epssText(*c.EPSS)
			}
			flag := ""
			switch {
			case c.KEV:
				flag = lipgloss.NewStyle().Foreground(cP["P2"]).Bold(true).Render("KEV")
			case c.RCE:
				flag = sErr.Render("RCE")
			}
			sev := sevStyle[c.Severity].Render(fit(sevShort[c.Severity], 4, false))
			l := " " + sText.Render(fit(c.ID, 16, false)) + " " + sev + " " + fit(sMuted.Render(e), 5, true) + " " + fit(flag, 3, false)
			if full {
				l += " " + sMuted.Render(c.Title)
			}
			out = append(out, l)
		}
		if limit < len(d.CVEs) {
			out = append(out, " "+sMuted.Render(m.t.F("{n} more: enter", "n", strconv.Itoa(len(d.CVEs)-limit))))
		}
	}
	if len(d.Where) > 0 {
		head(m.t.T("where"))
		gw := 0
		for _, x := range d.Where {
			gw = max(gw, ansi.StringWidth(x.Group))
		}
		for _, x := range d.Where {
			l := " " + lipgloss.NewStyle().Foreground(cCyan).Render(fit(x.Group, min(gw, 16), false)) + " " + sBold.Render(fit(strconv.Itoa(len(x.Hosts)), 4, true)) +
				" " + sMuted.Render(x.OS) + "  " + m.states(x.States)
			if x.Exposure == 1 {
				l += " " + lipgloss.NewStyle().Foreground(cP["P2"]).Render(m.t.T("internet-facing"))
			}
			out = append(out, l)
			if full || len(x.Hosts) <= 3 {
				wrap("   ", sMuted.Render(strings.Join(x.Hosts, ", ")))
			}
		}
	}
	if len(d.Apply) > 0 {
		head(m.t.T("apply"))
		cur := min(m.cmdCur, len(d.Apply)-1)
		for i, a := range d.Apply {
			mark := "   "
			if i == cur {
				mark = sKey.Render(" ▶ ")
			}
			out = append(out, mark+sMuted.Render(a.OS+" · "+m.hostsN(len(a.Hosts))))
			wrap("   "+sMuted.Render("$ "), sText.Render(a.Command))
			if a.Reboot {
				out = append(out, "     "+lipgloss.NewStyle().Foreground(cP["P3"]).Render(m.t.T("then reboot")))
			}
		}
	}
	if full {
		out = append(out, "", " "+sDim.Render(m.t.T("node")+": "+n.ID))
	}
	return out
}
