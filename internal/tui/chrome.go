package tui

import (
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// The frame around the views: the status bar, the key hints above it, and the popup lists: filters (f),
// organizations (O), environments (E), and the jump palette (:), the web page's ⌘K.

var sEnv = lipgloss.NewStyle().Foreground(lipgloss.Color("#0b0b0b")).Background(lipgloss.Color("#5aa9d6")).Bold(true).Padding(0, 1)

// --- popup lists ------------------------------------------------------------------------------------------------------

type menuDlg struct {
	kind  string // filters, orgs, envs, jump
	q     string // what is typed (all but filters)
	cur   int
	trees map[string]*treeResp // jump: the fixes and the CVEs of the env
}

type menuItem struct {
	kind  string // filter, org, new, env, view, fix, cve, host
	id    string
	label string   // what is matched and shown
	cols  []string // more columns, aligned (styled)
	on    bool     // a filter on
}

func (m *Model) newMenu(kind string) *menuDlg {
	d := &menuDlg{kind: kind, trees: map[string]*treeResp{}}
	switch kind {
	case "orgs":
		d.cur = max(slices.IndexFunc(m.menuItems(d), func(it menuItem) bool { return it.id == m.org }), 0)
	case "envs":
		d.cur = max(slices.IndexFunc(m.menuItems(d), func(it menuItem) bool { return it.id == m.env }), 0)
	}
	return d
}

// fetchJumpTrees: every fix and every CVE of the env, unfiltered, for the jump palette.
func (m *Model) fetchJumpTrees() tea.Cmd {
	if m.run == "" {
		return nil
	}
	var cmds []tea.Cmd
	for _, by := range []string{"fix", "cve"} {
		q := "/api/tree?org=" + url.QueryEscape(m.org) + "&env=" + url.QueryEscape(m.env) + "&run=" + url.QueryEscape(m.run) + "&by=" + by
		cmds = append(cmds, m.get(q, func(v any) tea.Msg { return jumpTreeMsg{by, v.(*treeResp)} }, &treeResp{}))
	}
	return tea.Batch(cmds...)
}

func (m *Model) envLabel(env string) string {
	if env == "default" {
		return m.t.T("all")
	}
	return env
}

func (m *Model) menuItems(d *menuDlg) []menuItem {
	var all []menuItem
	switch d.kind {
	case "filters":
		for _, f := range treeFilters {
			all = append(all, menuItem{kind: "filter", id: f.key, label: m.t.T(f.label), on: m.flt[f.key]})
		}
		return all
	case "orgs":
		for _, o := range m.orgs.Orgs {
			hosts := 0
			for _, e := range o.Envs {
				hosts += e.Hosts
			}
			all = append(all, menuItem{kind: "org", id: o.ID, label: o.ID, cols: []string{sText.Render(o.Name),
				sMuted.Render(m.t.F("{n} environments", "n", strconv.Itoa(len(o.Envs)))), sMuted.Render(m.hostsN(hosts))}})
		}
		if m.scanOK {
			all = append(all, menuItem{kind: "new", label: "+ " + m.t.T("New organization")})
		}
	case "envs":
		if o := m.orgRow(); o != nil {
			for _, e := range o.Envs {
				pc, known := map[string]int{}, false
				last := sDim.Render(m.t.T("no runs"))
				if e.Last != nil {
					last = sMuted.Render(m.t.runShort(e.Last.RunID))
					if e.Last.PlanCounts != nil {
						pc, known = e.Last.PlanCounts, true
					}
				}
				state := sMuted.Render(m.t.T("idle"))
				if e.Running != nil {
					state = sRun.Render(m.t.T("running"))
				}
				all = append(all, menuItem{kind: "env", id: e.Env, label: m.envLabel(e.Env), cols: []string{
					sMuted.Render(m.hostsN(e.Hosts)),
					prio("P1") + " " + count("P1", pc["P1"], known), prio("P2") + " " + count("P2", pc["P2"], known),
					prio("P3") + " " + count("P3", pc["P3"], known), last, state}})
			}
		}
	case "jump":
		for v := range nViews {
			all = append(all, menuItem{kind: "view", id: strconv.Itoa(int(v)), label: m.t.T(viewNames[v]), cols: []string{sMuted.Render(m.t.T("view"))}})
		}
		if t := d.trees["fix"]; t != nil {
			for _, n := range t.Nodes {
				all = append(all, menuItem{kind: "fix", id: n.ID, label: ansi.Strip(m.nodeText(n, true, false)), cols: []string{prio(n.Priority) + " " + sMuted.Render(m.t.T("fix"))}})
			}
		}
		if t := d.trees["cve"]; t != nil {
			for _, n := range t.Nodes {
				if n.Kind == "cve" {
					all = append(all, menuItem{kind: "cve", id: n.ID, label: n.Label + " " + n.Title, cols: []string{prio(n.Priority) + " " + sMuted.Render("CVE")}})
				}
			}
		}
		if m.rund != nil {
			var hosts []string
			for h := range m.rund.Hosts {
				hosts = append(hosts, h)
			}
			sort.Strings(hosts)
			for _, h := range hosts {
				all = append(all, menuItem{kind: "host", id: h, label: h + " " + m.rund.Facts[h].OS, cols: []string{sMuted.Render(m.t.T("host"))}})
			}
		}
	}
	q := strings.ToLower(strings.TrimSpace(d.q))
	if q == "" {
		return all
	}
	var out []menuItem
	for _, it := range all {
		if it.kind == "new" || strings.Contains(strings.ToLower(it.label+" "+it.id), q) {
			out = append(out, it)
		}
	}
	return out
}

func (m *Model) menuKey(k tea.KeyMsg) tea.Cmd {
	d := m.menu
	s := k.String()
	items := m.menuItems(d)
	switch s {
	case "esc":
		m.menu = nil
		return nil
	case "up", "ctrl+p", "shift+tab":
		d.cur = max(d.cur-1, 0)
		return nil
	case "down", "ctrl+n", "tab":
		d.cur = min(d.cur+1, max(len(items)-1, 0))
		return nil
	case "pgup":
		d.cur = max(d.cur-10, 0)
		return nil
	case "pgdown":
		d.cur = min(d.cur+10, max(len(items)-1, 0))
		return nil
	case "backspace":
		if r := []rune(d.q); len(r) > 0 {
			d.q, d.cur = string(r[:len(r)-1]), 0
		}
		return nil
	}
	if d.kind == "filters" {
		switch s {
		case "k":
			d.cur = max(d.cur-1, 0)
		case "j":
			d.cur = min(d.cur+1, len(items)-1)
		case "f", "q":
			m.menu = nil
		case "enter", " ", "space", "x":
			if d.cur < len(items) {
				m.flt[items[d.cur].id] = !m.flt[items[d.cur].id]
				m.cur[vActions], m.off[vActions] = 0, 0
			}
		}
		return nil
	}
	if s == "enter" {
		if d.cur >= len(items) {
			return nil
		}
		m.menu = nil
		return m.pick(items[d.cur])
	}
	if k.Type == tea.KeyRunes || k.Type == tea.KeySpace {
		d.q += string(k.Runes)
		d.cur = 0
	}
	return nil
}

// pick: what choosing an item of a popup list does.
func (m *Model) pick(it menuItem) tea.Cmd {
	switch it.kind {
	case "new":
		m.newOrg()
	case "org":
		for _, o := range m.orgs.Orgs {
			if o.ID == it.id && len(o.Envs) > 0 && o.ID != m.org {
				cmd := m.selectEnv(o.ID, o.Envs[0].Env)
				m.say(m.t.F("{org}: environment {env} (E: another)", "org", o.ID, "env", m.envLabel(o.Envs[0].Env)))
				return cmd
			}
		}
	case "env":
		return m.selectEnv(m.org, it.id)
	case "view":
		v, _ := strconv.Atoi(it.id)
		m.setView(view(v))
	case "fix", "cve":
		m.setView(vActions)
		m.by, m.flt, m.onlySel = it.kind, map[string]bool{}, false
		m.cur[vActions], m.off[vActions] = 0, 0
		m.jumpTo, m.curID = it.id, it.id
		if m.wantTree() == m.treeKey {
			m.jumpTo = ""
			m.placeCursor()
		}
	case "host":
		m.setView(vHosts)
		m.host, m.hostOff = it.id, 0
	}
	return nil
}

// menuBox: the popup list drawn over the screen.
func (m *Model) menuBox() []string {
	d := m.menu
	items := m.menuItems(d)
	title := menuTitles[d.kind]
	var lines []string
	if d.kind != "filters" {
		lines = append(lines, " "+sKey.Render("> ")+sText.Render(d.q)+sBrand.Render("_"), "")
	}
	// the columns of the items, aligned
	labelW := 0
	colW := []int{}
	for _, it := range items {
		labelW = max(labelW, ansi.StringWidth(it.label))
		for i, c := range it.cols {
			if i >= len(colW) {
				colW = append(colW, 0)
			}
			colW[i] = max(colW[i], ansi.StringWidth(c))
		}
	}
	rest := 0
	for _, c := range colW {
		rest += c + 2
	}
	// as wide as its items (the jump list: wide at once, its items change as one types)
	w := min(m.w-4, max(labelW+rest+8, 48))
	if d.kind == "jump" {
		w = min(m.w-4, 100)
	}
	inner := w - 2
	labelW = max(min(labelW, inner-rest-6), 8)
	room := max(min(m.h-8, 20), 3)
	d.cur = min(d.cur, max(len(items)-1, 0))
	off := max(d.cur-room+1, 0)
	for i := off; i < min(off+room, len(items)); i++ {
		it := items[i]
		l := " "
		if d.kind == "filters" {
			box := sDim.Render("[ ]")
			if it.on {
				box = sBrand.Render("[x]")
			}
			l += box + " "
		}
		l += sText.Render(fit(it.label, labelW, false))
		for j, c := range it.cols {
			l += "  " + fit(c, colW[j], false)
		}
		if i == d.cur {
			l = sSel.Render(fit(ansi.Strip(l), inner, false))
		}
		lines = append(lines, l)
	}
	if len(items) == 0 {
		lines = append(lines, " "+sMuted.Render(m.t.T("nothing here")))
	}
	hint := sKey.Render("<enter>") + " " + sMuted.Render(m.t.T("choose")) + "  " + sKey.Render("<esc>") + " " + sMuted.Render(m.t.T("close"))
	if d.kind == "filters" {
		hint = sKey.Render("<space>") + " " + sMuted.Render(m.t.T("toggle")) + "  " + sKey.Render("<esc>") + " " + sMuted.Render(m.t.T("close"))
	}
	lines = append(lines, "", " "+hint)
	return panel(sTitle.Render(m.t.T(title)), lines, w, len(lines)+2)
}

// overlay: box drawn over lines at column x, line y.
func overlay(lines, box []string, x, y, w int) []string {
	out := slices.Clone(lines)
	for i, b := range box {
		r := y + i
		if r < 0 || r >= len(out) {
			continue
		}
		base := fit(out[r], w, false)
		bw := ansi.StringWidth(b)
		out[r] = ansi.Cut(base, 0, x) + b + ansi.Cut(base, x+bw, w)
	}
	return out
}

// --- the bottom: key hints and the status bar ----------------------------------------------------------------------------

// hints: the keys of what is on screen, as many as fit, ending with the help key.
func (m *Model) hints() string {
	if m.setup != nil {
		return m.setupHints()
	}
	if m.form != nil || m.menu != nil || m.help || m.panels != nil || m.langs != nil {
		return "" // dialogs say their own keys
	}
	type k struct{ key, what string }
	var l []k
	switch {
	case m.view == vActions && m.full:
		l = []k{{"↑↓", "scroll"}, {"[ ]", "command"}, {"c", "copy command"}, {"y", "copy task"}, {"Y", "copy context"}, {"esc", "back"}}
	case m.view == vActions && m.run == "" && m.org != "":
		l = []k{{"enter", "check access, first scan"}, {"s", "scan"}, {"E", "environment"}, {"O", "organization"}}
	case m.view == vActions:
		// the main ones only; c, f, g, E, O, p, v are in ? (and g, f in the title line)
		l = []k{{"space", "select"}, {"→←", "open/close"}, {"enter", "details"}, {"y", "copy task"}, {"Y", "copy context"},
			{"/", "filter"}, {":", "jump"}}
	default:
		l = map[view][]k{
			vHosts:      {{"enter", "host card"}, {"p", "P4"}},
			vPackages:   {{"p", "P4"}},
			vAccess:     {{"enter", "host card"}},
			vNetwork:    {{"enter", "host card"}, {"f", "outside only"}},
			vHealth:     {{"enter", "host card"}},
			vRuns:       {{"enter", "open"}, {"i", "errors and log"}, {"c", "current state"}},
			vScans:      {{"enter", "output"}, {"x", "stop"}},
			vChanges:    {},
			vExceptions: {},
		}[m.view]
		if m.host != "" && m.view == vHosts {
			l = []k{{"↑↓", "scroll"}, {"esc", "back"}}
		}
		l = append(l, k{"/", "filter"}, k{":", "jump"})
	}
	if m.scanOK && !m.full {
		l = append(l, k{"s", "scan"})
	}
	// key in colour, what it does dim, a dot between pairs: easy to scan
	sep := sDim.Render("  ·  ")
	help := sKey.Render("?") + " " + sMuted.Render(m.t.T("all keys"))
	out := " "
	for _, x := range l {
		part := sKey.Render(x.key) + " " + sMuted.Render(m.t.T(x.what)) + sep
		if ansi.StringWidth(out+part+help) > m.w {
			break
		}
		out += part
	}
	return out + help
}

// statusBar: org │ env │ hosts · data age · DB, the last message; at the right what is selected and the time.
func (m *Model) statusBar() string {
	if m.setup != nil {
		return m.setupStatus()
	}
	l := ""
	if m.org != "" {
		l = sCrumb2.Render(m.org) + sEnv.Render(m.envLabel(m.env))
	} else {
		l = sCrumb.Render("Kanareika")
	}
	var info []string
	if o := m.orgRow(); o != nil {
		for _, e := range o.Envs {
			if e.Env != m.env {
				continue
			}
			info = append(info, m.hostsN(e.Hosts))
			switch {
			case m.run != "" && m.run != "current":
				info = append(info, sBrand.Render(m.t.F("run {run}", "run", m.t.runShort(m.run))))
			case e.Last != nil:
				if at, ok := parseTime(e.Last.Finished); ok {
					info = append(info, m.t.F("data {age}", "age", agoShort(max(m.now().Sub(at), 0))))
				}
			}
		}
	}
	if s := m.scanState(); s != "" {
		info = append(info, s)
	}
	if db := m.dbShort(); db != "" {
		info = append(info, db)
	}
	if len(info) > 0 {
		l += " " + sMuted.Render(strings.Join(info, sDim.Render(" · ")))
	}
	switch {
	case m.err != "":
		l += "  " + sErr.Render(m.err)
	case m.toast != "" && m.now().Sub(m.toastAt).Seconds() < 5:
		l += "  " + sOK.Render(m.toast)
	case len(m.orgs.Errors) > 0:
		l += "  " + sErr.Render(fmt.Sprintf("%s: %d (kanareika validate)", m.t.T("Config errors"), len(m.orgs.Errors)))
	}
	// the time now at the right, in the zone times are shown in (z switches it); the screen refreshes often enough
	z := m.t.zone
	if z == nil {
		z = time.UTC
	}
	right := sMuted.Render(m.now().In(z).Format("15:04") + " " + m.t.zoneName(m.now()))
	if n := len(m.picked()); n > 0 {
		right = sCrumb.Render(m.t.F("{n} selected", "n", strconv.Itoa(n))) + " " + right
	}
	if room := m.w - ansi.StringWidth(l) - ansi.StringWidth(right) - 1; room >= 1 {
		return l + strings.Repeat(" ", room) + right
	}
	return l
}

// dbShort: the vulnerability DB in the status bar: ok, its age, a newer one out, missing, or updating; old feeds.
func (m *Model) dbShort() string {
	if m.db == nil {
		return ""
	}
	warn := lipgloss.NewStyle().Foreground(cP["P3"])
	s := ""
	switch {
	case m.db.Updating:
		s = sRun.Render(m.t.T("DB updating…"))
	case m.dbAttention() == "missing":
		s = sErr.Render(m.t.T("no DB")) + " " + sKey.Render("U")
	case m.dbAttention() == "outdated":
		s = warn.Render(m.t.T("newer DB out")) + " " + sKey.Render("U")
	default:
		s = "DB " + sOK.Render(m.t.T("ok"))
	}
	if m.db.FeedsOutdated {
		s += sDim.Render(" · ") + warn.Render(m.t.T("KEV/EPSS old"))
	}
	return s
}
