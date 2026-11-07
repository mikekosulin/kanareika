package tui

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Palette: the web page's priority colors on a dark terminal, k9s-like chrome.
var (
	cP      = map[string]lipgloss.Color{"P1": "#e5484d", "P2": "#f2894f", "P3": "#f5c518", "P4": "#7d7c75"}
	cBrand  = lipgloss.Color("#f5c518")
	cAccent = lipgloss.Color("#3b82f6")
	cCyan   = lipgloss.Color("#22d3ee")
	cText   = lipgloss.Color("#e6e5e1")
	cMuted  = lipgloss.Color("#8a8984")
	cDim    = lipgloss.Color("#4a4945")
	cOK     = lipgloss.Color("#22c55e")
	cBad    = lipgloss.Color("#f87171")

	sBrand  = lipgloss.NewStyle().Foreground(cBrand).Bold(true)
	sText   = lipgloss.NewStyle().Foreground(cText)
	sMuted  = lipgloss.NewStyle().Foreground(cMuted)
	sDim    = lipgloss.NewStyle().Foreground(cDim)
	sBold   = lipgloss.NewStyle().Foreground(cText).Bold(true)
	sLabel  = lipgloss.NewStyle().Foreground(cBrand)
	sKey    = lipgloss.NewStyle().Foreground(cCyan).Bold(true)
	sHead   = lipgloss.NewStyle().Foreground(cText).Bold(true)
	sSel    = lipgloss.NewStyle().Foreground(lipgloss.Color("#0b0b0b")).Background(cCyan).Bold(true)
	sErr    = lipgloss.NewStyle().Foreground(cBad)
	sOK     = lipgloss.NewStyle().Foreground(cOK)
	sRun    = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	sFrame  = lipgloss.NewStyle().Foreground(cCyan)
	sTitle  = lipgloss.NewStyle().Foreground(cBrand).Bold(true)
	sCrumb  = lipgloss.NewStyle().Foreground(lipgloss.Color("#0b0b0b")).Background(cBrand).Bold(true).Padding(0, 1)
	sCrumb2 = lipgloss.NewStyle().Foreground(lipgloss.Color("#0b0b0b")).Background(cCyan).Padding(0, 1)
)

// logo: KANAREIKA in half blocks, two rows.
var logo = [2]string{
	"█▄▀ ▄▀█ █▄ █ ▄▀█ █▀█ █▀▀ █ █▄▀ ▄▀█",
	"█ █ █▀█ █ ▀█ █▀█ █▀▄ ██▄ █ █ █ █▀█",
}

const ellipsis = "~" // single cell everywhere (… is double width in some terminals)

func prio(p string) string {
	if p == "" {
		return sDim.Render("--")
	}
	return lipgloss.NewStyle().Foreground(cP[p]).Bold(true).Render(p)
}

func count(p string, n int, known bool) string {
	switch {
	case !known:
		return sDim.Render("-")
	case n == 0:
		return sDim.Render("0")
	}
	return lipgloss.NewStyle().Foreground(cP[p]).Bold(true).Render(fmt.Sprint(n))
}

// fit: s cut or padded to exactly w cells (ANSI-aware).
func fit(s string, w int, right bool) string {
	if w <= 0 {
		return ""
	}
	if ansi.StringWidth(s) > w {
		s = ansi.Truncate(s, w, ellipsis)
	}
	pad := strings.Repeat(" ", max(w-ansi.StringWidth(s), 0))
	if right {
		return pad + s
	}
	return s + pad
}

// col: a table column; width 0 = takes the rest.
type col struct {
	title string
	width int
	right bool
}

// table: rows under headers in width cells and height lines, the cursor row a full-width bar kept in view.
func (m *Model) table(cols []col, rows [][]string, width, height int) []string {
	fixed := 0
	flex := 0
	for _, c := range cols {
		fixed += c.width + 1
		if c.width == 0 {
			flex++
		}
	}
	rest := max(width-fixed, 6)
	line := func(cells []string) string {
		var l strings.Builder
		for i, c := range cols {
			w := c.width
			if w == 0 {
				w = rest / max(flex, 1)
			}
			l.WriteString(fit(cells[i], w, c.right) + " ")
		}
		return fit(l.String(), width, false)
	}
	head := make([]string, len(cols))
	for i, c := range cols {
		head[i] = sHead.Render(strings.ToUpper(m.t.T(c.title)))
	}
	out := []string{line(head)}
	if len(rows) == 0 {
		return append(out, sMuted.Render(" "+m.t.T("nothing here")))
	}
	h := max(height-1, 1)
	cur := min(m.cur[m.view], len(rows)-1)
	off := min(m.off[m.view], cur)
	if cur >= off+h {
		off = cur - h + 1
	}
	m.off[m.view] = off
	for i := off; i < min(off+h, len(rows)); i++ {
		l := line(rows[i])
		if i == cur {
			l = sSel.Render(ansi.Strip(l))
		}
		out = append(out, l)
	}
	return out
}

// panel: a k9s-style frame with the title set into its top border; content cut to the inside.
func panel(title string, content []string, w, h int) []string {
	inner := max(w-2, 1)
	t := " " + title + " "
	if ansi.StringWidth(t) > inner-2 {
		t = ansi.Truncate(t, inner-2, ellipsis)
	}
	dashes := max(inner-ansi.StringWidth(t), 0)
	left := dashes / 2
	top := sFrame.Render("┌"+strings.Repeat("─", left)) + t + sFrame.Render(strings.Repeat("─", dashes-left)+"┐")
	out := []string{top}
	for i := 0; i < max(h-2, 0); i++ {
		c := ""
		if i < len(content) {
			c = content[i]
		}
		out = append(out, sFrame.Render("│")+fit(c, inner, false)+sFrame.Render("│"))
	}
	return append(out, sFrame.Render("└"+strings.Repeat("─", inner)+"┘"))
}

const headerH = 6

func (m *Model) bodyHeight() int { return max(m.h-headerH-1-2, 3) } // inside the panel

// View: exactly the terminal's size, every line clipped, so nothing ever wraps or scrolls.
func (m *Model) View() string {
	if m.w == 0 || m.h == 0 {
		return ""
	}
	lines := append(m.header(), m.main()...)
	lines = append(lines, m.crumbs())
	for len(lines) < m.h {
		lines = append(lines, "")
	}
	lines = lines[:m.h]
	for i, l := range lines {
		lines[i] = fit(l, m.w, false)
	}
	return strings.Join(lines, "\n")
}

// --- header: context, priority gauges, keys, logo -------------------------------------------------------------------

func (m *Model) header() []string {
	info := m.info()
	gauges := m.gauges()
	keys := m.keys()
	showLogo := m.w >= 150
	infoW, gaugeW := 40, 30
	logoW := 0
	if showLogo {
		logoW = ansi.StringWidth(logo[0]) + 2
	}
	keysW := max(m.w-infoW-gaugeW-logoW-2, 0)
	if m.w < 100 {
		gaugeW, keysW = 0, max(m.w-infoW-logoW, 0)
	}
	out := make([]string, headerH)
	for i := range out {
		l := fit(get(info, i), infoW-2, false) + "  "
		if gaugeW > 0 {
			l += fit(get(gauges, i), gaugeW, false) + "  "
		}
		l += fit(get(keys, i), keysW, false)
		if showLogo {
			switch i {
			case 1, 2:
				l += "  " + sBrand.Render(logo[i-1])
			case 3:
				l += "  " + sMuted.Render(fit(m.t.T("read-only security audit"), logoW-2, true))
			}
		}
		out[i] = l
	}
	return out
}

func get(l []string, i int) string {
	if i < len(l) {
		return l[i]
	}
	return ""
}

func (m *Model) info() []string {
	kv := func(k, v string) string { return sLabel.Render(fit(m.t.T(k)+":", 9, false)) + " " + v }
	org, env, data, scan := sDim.Render("-"), sDim.Render("-"), sDim.Render("-"), sMuted.Render(m.t.T("no scans"))
	if o := m.orgRow(); o != nil {
		org = sBold.Render(o.ID)
		if o.Name != "" {
			org += " " + sMuted.Render(o.Name)
		}
		for _, e := range o.Envs {
			if e.Env == m.env {
				name := e.Env
				if name == "default" {
					name = m.t.T("all")
				}
				env = sBold.Render(name) + sMuted.Render(fmt.Sprintf(" %d %s", e.Hosts, m.t.T("hosts")))
			}
		}
	}
	if m.run != "" {
		data = sText.Render(m.t.runShort(m.run))
	}
	if l := m.envd.Live; l != nil && (l.State == "running" || l.State == "stale") {
		fin := 0
		for _, h := range l.Hosts {
			switch h.State {
			case "ok", "warn", "failed", "skipped":
				fin++
			}
		}
		scan = sRun.Render(fmt.Sprintf("%s %d/%d", m.t.T("running"), fin, len(l.Hosts)))
		if l.State == "stale" {
			scan = sErr.Render(m.t.T("scan not responding"))
		}
	} else if n := m.runningJobs(); n > 0 {
		scan = sRun.Render(fmt.Sprintf("%s: %d", m.t.T("running"), n))
	}
	trivy := sDim.Render("-")
	if m.rund != nil && m.rund.Meta.TrivyVersion != "" {
		trivy = sText.Render(m.rund.Meta.TrivyVersion)
		if m.rund.Meta.FeedsUpdated == nil {
			trivy += sMuted.Render(" · KEV/EPSS " + m.t.T("not loaded"))
		}
	}
	return []string{kv("Org", org), kv("Env", env), kv("Data", data), kv("Scan", scan), kv("Trivy", trivy)}
}

func (m *Model) runningJobs() int {
	n := 0
	for _, j := range m.jobs.Jobs {
		if j.State == "running" {
			n++
		}
	}
	return n
}

// gauges: P1..P4 of the data on screen as bars, btop style.
func (m *Model) gauges() []string {
	if m.rund == nil {
		return nil
	}
	pc := m.rund.PlanCounts
	top := 1
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		top = max(top, pc[p])
	}
	const barW = 18
	var out []string
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		n := pc[p]
		fill := (n*barW + top - 1) / top
		bar := lipgloss.NewStyle().Foreground(cP[p]).Render(strings.Repeat("■", fill)) + sDim.Render(strings.Repeat("■", barW-fill))
		out = append(out, prio(p)+" "+bar+" "+fit(count(p, n, true), 4, true))
	}
	return append(out, sMuted.Render(fmt.Sprintf("   %d CVE", pc["cves"])))
}

// keys: k9s-style hints in columns, for the view on screen.
func (m *Model) keys() []string {
	type k struct{ key, what string }
	global := []k{{"1-6", "views"}, {"/", "filter"}, {"r", "refresh"}, {"L", "language"}, {"?", "help"}, {"q", "quit"}}
	local := map[view][]k{
		vOrgs:     {{"enter", "open"}},
		vActions:  {{"space", "select"}, {"a", "select all"}, {"y", "copy task"}, {"enter", "details"}, {"p", "P4"}},
		vHosts:    {{"p", "P4"}},
		vPackages: {{"p", "P4"}},
		vRuns:     {{"enter", "open"}, {"c", "current state"}},
		vScans:    {{"enter", "output"}, {"x", "stop"}},
	}[m.view]
	if m.scanOK {
		local = append(local, k{"s", "scan"})
	}
	all := append(slices.Clip(local), global...)
	rows := headerH
	colW := 19
	var out []string
	for r := 0; r < rows; r++ {
		var l strings.Builder
		for c := 0; c*rows+r < len(all); c++ {
			x := all[c*rows+r]
			l.WriteString(fit(sKey.Render("<"+x.key+">")+" "+sMuted.Render(m.t.T(x.what)), colW, false))
		}
		out = append(out, l.String())
	}
	return out
}

// --- main panel -------------------------------------------------------------------------------------------------------

func (m *Model) main() []string {
	h := m.h - headerH - 1
	w := m.w
	switch {
	case m.help:
		return panel(sTitle.Render(m.t.T("Keys")), m.helpView(), w, h)
	case m.form != nil:
		return panel(sTitle.Render(m.t.T("Scan"))+sText.Render("("+m.form.org+"/"+m.form.env+")"), m.formView(h-2), w, h)
	case !m.loaded:
		msg := m.t.T("loading")
		if m.err != "" {
			msg = sErr.Render(m.err)
		}
		return panel(sTitle.Render("Kanareika"), []string{" " + msg}, w, h)
	}
	title, content := m.body(w-2, h-2)
	return panel(title, content, w, h)
}

// title: k9s-style: View(scope)[count] </filter>.
func (m *Model) title(name string, n int, scoped bool) string {
	t := sTitle.Render(m.t.T(name))
	if scoped && m.org != "" {
		scope := m.org + "/" + m.env
		if m.run != "" && m.run != "current" {
			scope += "@" + m.t.runShort(m.run)
		}
		t += sText.Render("(" + scope + ")")
	}
	t += sBold.Render(fmt.Sprintf("[%d]", n))
	if m.typing || m.filter != "" {
		cur := ""
		if m.typing {
			cur = "_"
		}
		t += " " + sKey.Render("</"+m.filter+cur+">")
	}
	return t
}

func (m *Model) body(w, h int) (string, []string) {
	switch m.view {
	case vOrgs:
		l := m.envList()
		return m.title(viewNames[vOrgs], len(l), false), m.orgsView(l, w, h)
	case vActions:
		l := m.actions()
		return m.title(viewNames[vActions], len(l), true), m.actionsView(l, w, h)
	case vHosts:
		l := m.hostList()
		return m.title(viewNames[vHosts], len(l), true), m.hostsView(l, w, h)
	case vPackages:
		l := m.packages()
		return m.title(viewNames[vPackages], len(l), true), m.packagesView(l, w, h)
	case vRuns:
		l := m.runList()
		return m.title(viewNames[vRuns], len(l), true), m.runsView(l, w, h)
	}
	return m.title(viewNames[vScans], len(m.jobs.Jobs), false), m.scansView(w, h)
}

func (m *Model) noData() []string {
	if m.org == "" {
		return []string{"", " " + sMuted.Render(m.t.T("no organizations")+": ") + sKey.Render("kanareika org new <id>")}
	}
	if m.run == "" {
		cmd := "kanareika scan " + m.org
		if m.env != "default" {
			cmd += " --env " + m.env
		}
		l := []string{"", " " + sMuted.Render(m.t.T("No runs yet. Run")+": ") + sKey.Render(cmd)}
		if m.scanOK {
			l = append(l, " "+sMuted.Render(m.t.T("or press"))+" "+sKey.Render("<s>"))
		}
		return l
	}
	return []string{" " + sMuted.Render(m.t.T("loading"))}
}

func (m *Model) orgsView(list []envItem, w, h int) []string {
	var rows [][]string
	for _, it := range list {
		env := it.env
		if env == "default" {
			env = m.t.T("all")
		}
		pc, known := map[string]int{}, false
		last := sDim.Render(m.t.T("no runs"))
		if it.e.Last != nil {
			last = m.t.runShort(it.e.Last.RunID)
			if it.e.Last.PlanCounts != nil {
				pc, known = it.e.Last.PlanCounts, true
			}
		}
		state := sMuted.Render(m.t.T("idle"))
		if it.e.Running != nil {
			state = sRun.Render(m.t.T("running"))
		}
		name := sBold.Render(it.org)
		if it.org == m.org && it.env == m.env {
			name = sBrand.Render(it.org)
		}
		rows = append(rows, []string{name, env, fmt.Sprint(it.e.Hosts), count("P1", pc["P1"], known),
			count("P2", pc["P2"], known), count("P3", pc["P3"], known), last, state, sMuted.Render(it.name)})
	}
	return m.table([]col{{"Organization", 16, false}, {"environment", 14, false}, {"hosts", 6, true}, {"P1", 4, true},
		{"P2", 4, true}, {"P3", 4, true}, {"last run", 17, false}, {"state", 10, false}, {"name", 0, false}}, rows, w, h)
}

func (m *Model) actionsView(list []action, w, h int) []string {
	if m.rund == nil {
		return m.noData()
	}
	var rows [][]string
	for _, a := range list {
		box := sDim.Render("○")
		if m.sel[a.ID] {
			box = sBrand.Render("●")
		}
		tags := ""
		if a.KEV {
			tags += sErr.Render("KEV ")
		}
		if a.RCE > 0 {
			tags += sErr.Render("RCE ")
		}
		cves := ""
		if a.CVEs > 0 {
			cves = fmt.Sprint(a.CVEs)
		}
		rows = append(rows, []string{box, prio(a.Priority), sMuted.Render(a.Due), tags + sText.Render(m.t.title(a)),
			sText.Render(hostsCell(a.Hosts)), cves})
	}
	cols := []col{{"", 1, false}, {"", 2, false}, {"due by", 10, false}, {"action", 0, false}, {"hosts", 26, false},
		{"CVE", 4, true}}
	if !m.detail || len(list) == 0 {
		return m.table(cols, rows, w, h)
	}
	d := m.detailLines(list[min(m.cur[vActions], len(list)-1)], w)
	dh := min(len(d), h/2)
	return append(m.table(cols, rows, w, h-dh), d[:dh]...)
}

func hostsCell(hs []string) string {
	if len(hs) <= 2 {
		return strings.Join(hs, ", ")
	}
	return fmt.Sprintf("%s, %s +%d", hs[0], hs[1], len(hs)-2)
}

func (m *Model) detailLines(a action, w int) []string {
	out := []string{sFrame.Render(strings.Repeat("─", w)), " " + prio(a.Priority) + " " + sBold.Render(m.t.title(a))}
	if d := m.t.detail(a); d != "" {
		out = append(out, " "+sText.Render(d))
	}
	out = append(out, " "+sLabel.Render(m.t.T("hosts")+": ")+sText.Render(strings.Join(a.Hosts, ", ")))
	for _, p := range a.Packages {
		kev := ""
		if p.KEV {
			kev = " " + sErr.Render("KEV")
		}
		out = append(out, fmt.Sprintf("   %s %s %s %s %s%s", prio(p.Priority), sBold.Render(fit(p.Pkg, 24, false)),
			sMuted.Render(p.Installed), sMuted.Render("->"), sOK.Render(p.Fixed), sMuted.Render(fmt.Sprintf("  %d CVE", p.CVEs))+kev))
	}
	return out
}

// stack: a host's P1..P4 as one stacked bar of width w (btop style).
func stack(c map[string]int, top, w int) string {
	if top == 0 {
		return ""
	}
	var b strings.Builder
	used := 0
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		n := (c[p]*w + top - 1) / top
		n = min(n, w-used)
		b.WriteString(lipgloss.NewStyle().Foreground(cP[p]).Render(strings.Repeat("▇", n)))
		used += n
	}
	return b.String()
}

func (m *Model) hostsView(list []hostItem, w, h int) []string {
	if m.rund == nil {
		return m.noData()
	}
	top := 0
	for _, x := range list {
		top = max(top, x.counts["P1"]+x.counts["P2"]+x.counts["P3"]+x.counts["P4"])
	}
	var rows [][]string
	for _, x := range list {
		c := x.counts
		rows = append(rows, []string{sBold.Render(x.name), sText.Render(x.os), count("P1", c["P1"], true), count("P2", c["P2"], true),
			count("P3", c["P3"], true), count("P4", c["P4"], true), fmt.Sprint(c["cves"]), stack(c, top, 24)})
	}
	return m.table([]col{{"host", 26, false}, {"OS", 0, false}, {"P1", 4, true}, {"P2", 4, true}, {"P3", 4, true},
		{"P4", 4, true}, {"CVE", 5, true}, {"", 24, false}}, rows, w, h)
}

func (m *Model) packagesView(list []planRow, w, h int) []string {
	if m.rund == nil {
		return m.noData()
	}
	var rows [][]string
	for _, p := range list {
		kev := ""
		if p.KEV {
			kev = sErr.Render("KEV")
		}
		target := p.Target
		if target == "os" {
			target = m.t.T("OS")
		}
		rows = append(rows, []string{prio(p.Priority), sText.Render(p.Host), sMuted.Render(target), sBold.Render(p.Pkg),
			sMuted.Render(p.Installed), sOK.Render(p.Fixed), fmt.Sprint(p.CVEs), kev, sMuted.Render(p.Due)})
	}
	return m.table([]col{{"", 2, false}, {"host", 16, false}, {"where", 22, false}, {"package", 0, false},
		{"installed", 18, false}, {"fixed in", 18, false}, {"CVE", 4, true}, {"", 3, false}, {"due by", 10, false}}, rows, w, h)
}

func (m *Model) runsView(list []runInfo, w, h int) []string {
	if m.org == "" {
		return m.noData()
	}
	var rows [][]string
	for _, r := range list {
		name := sText.Render(m.t.runShort(r.RunID))
		if r.RunID == m.run {
			name = sBrand.Render(m.t.runShort(r.RunID))
		}
		state := sErr.Render(m.t.T(r.State))
		switch r.State {
		case "done":
			state = sOK.Render(m.t.T("done"))
		case "running":
			state = sRun.Render(m.t.T("running"))
		}
		kind := sText.Render(m.t.T("full"))
		if r.Partial {
			kind = sMuted.Render(m.t.T("partial"))
		}
		known := r.PlanCounts != nil
		rows = append(rows, []string{name, state, kind, fmt.Sprintf("%d/%d", r.HostsTotal-r.HostsFailed, r.HostsTotal),
			count("P1", r.PlanCounts["P1"], known), count("P2", r.PlanCounts["P2"], known), count("P3", r.PlanCounts["P3"], known)})
	}
	return m.table([]col{{"run", 18, false}, {"state", 14, false}, {"kind", 10, false}, {"hosts ok", 9, true},
		{"P1", 4, true}, {"P2", 4, true}, {"P3", 4, true}}, rows, w, h)
}

func (m *Model) scansView(w, h int) []string {
	var out []string
	if l := m.envd.Live; l != nil && (l.State == "running" || l.State == "stale") {
		names := make([]string, 0, len(l.Hosts))
		fin := 0
		for n, x := range l.Hosts {
			names = append(names, n)
			switch x.State {
			case "ok", "warn", "failed", "skipped":
				fin++
			}
		}
		sort.Strings(names)
		barW := max(w-40, 10)
		fill := fin * barW / max(len(names), 1)
		out = append(out, " "+sBold.Render(m.t.T("Scan running"))+sMuted.Render(" "+m.org+"/"+m.env+" ")+
			sRun.Render(strings.Repeat("■", fill))+sDim.Render(strings.Repeat("■", barW-fill))+sText.Render(fmt.Sprintf(" %d/%d", fin, len(names))))
		for _, n := range names {
			x := l.Hosts[n]
			st := map[string]string{"running": sRun.Render(">"), "ok": sOK.Render("+"), "warn": lipgloss.NewStyle().Foreground(cP["P3"]).Render("!"),
				"failed": sErr.Render("x")}[x.State]
			if st == "" {
				st = sDim.Render(".")
			}
			out = append(out, fmt.Sprintf("  %s %s %s %s", st, sBold.Render(fit(n, 20, false)), sMuted.Render(fit(x.Module, 14, false)), sMuted.Render(x.Last)))
		}
		out = append(out, "")
	}
	if !m.scanOK && len(m.jobs.Jobs) == 0 {
		return append(out, " "+sMuted.Render(m.t.T("Scans can't be started here (read-only)")))
	}
	var rows [][]string
	for _, j := range m.jobs.Jobs {
		st := map[string]string{"running": sRun.Render(m.t.T("running")), "done": sOK.Render(m.t.T("done")),
			"failed": sErr.Render(m.t.T("finished with errors")), "cancelled": sMuted.Render(m.t.T("cancelled"))}[j.State]
		var scope []string
		if len(j.Request.Hosts) > 0 {
			scope = append(scope, strings.Join(j.Request.Hosts, ","))
		}
		if len(j.Request.Modules) > 0 {
			scope = append(scope, strings.Join(j.Request.Modules, "+"))
		}
		if j.Request.DryRun {
			scope = append(scope, m.t.T("dry run"))
		}
		name := sText.Render(j.Request.Org + "/" + j.Request.Env)
		if j.ID == m.open {
			name = sBrand.Render(j.Request.Org + "/" + j.Request.Env)
		}
		rows = append(rows, []string{name, st, m.t.ago(j.Started.Format("2006-01-02T15:04:05Z07:00"), m.now()),
			sMuted.Render(strings.Join(scope, " "))})
	}
	if len(rows) == 0 {
		return append(out, "", " "+sMuted.Render(m.t.T("Press"))+" "+sKey.Render("<s>")+" "+
			sMuted.Render(m.t.T("to start a scan of"))+" "+sText.Render(m.org+"/"+m.env))
	}
	listH := min(len(rows)+1, max((h-len(out))/3, 3))
	out = append(out, m.table([]col{{"environment", 24, false}, {"state", 22, false}, {"started", 12, false},
		{"scope", 0, false}}, rows, w, listH)...)
	for _, j := range m.jobs.Jobs {
		if j.ID != m.open {
			continue
		}
		left := max(h-len(out)-1, 1)
		lines := j.Output
		if len(lines) > left {
			lines = lines[len(lines)-left:]
		}
		out = append(out, sFrame.Render(fit("─ "+m.t.T("output")+" ", w, false)))
		for _, l := range lines {
			out = append(out, " "+sText.Render(l))
		}
	}
	return out
}

func (m *Model) formView(h int) []string {
	f := m.form
	var lines []string
	for i, it := range f.items {
		var l string
		switch it.kind {
		case itemHead:
			l = " " + sLabel.Render(m.t.T(it.label))
		case itemStart:
			l = "   " + sCrumb.Render(m.t.T(it.label))
		default:
			box := sDim.Render("[ ]")
			if it.on {
				box = sBrand.Render("[x]")
			}
			label := it.label
			if it.kind == itemFlag {
				label = m.t.T(label)
			}
			l = "   " + box + " " + sText.Render(label)
		}
		if i == f.cur && it.kind != itemHead {
			l = sSel.Render(ansi.Strip(l))
		}
		lines = append(lines, l)
	}
	h = max(h-2, 3)
	off := 0
	if f.cur >= h-1 {
		off = f.cur - h + 2
	}
	lines = lines[min(off, len(lines)):]
	if len(lines) > h {
		lines = lines[:h]
	}
	return append(lines, "", " "+sKey.Render("<space>")+" "+sMuted.Render(m.t.T("toggle"))+"  "+sKey.Render("<enter>")+" "+
		sMuted.Render(m.t.T("Start"))+"  "+sKey.Render("<esc>")+" "+sMuted.Render(m.t.T("Cancel")))
}

func (m *Model) helpView() []string {
	rows := [][2]string{
		{"1-6, tab, left/right", "views: organizations, to do, hosts, packages, runs, scans"},
		{"up/down, j/k, pgup/pgdn, g/G", "move"},
		{"enter", "open (an environment, a run, details, a scan's output)"},
		{"/", "filter the list; esc clears"},
		{"space, a", "select an action, select all"},
		{"y", "copy the fix task for the selected actions (terminal clipboard, OSC 52)"},
		{"p", "show P4 too"},
		{"s", "start a scan of this environment"},
		{"x", "stop the scan under the cursor (Scans)"},
		{"c", "back to the current state (Runs)"},
		{"L", "language"},
		{"r", "refresh"},
		{"q, ctrl+c", "quit"},
	}
	out := []string{""}
	for _, r := range rows {
		out = append(out, "  "+sKey.Render(fit(r[0], 30, false))+" "+sText.Render(m.t.T(r[1])))
	}
	return append(out, "", "  "+sMuted.Render(m.t.T("any key closes this")))
}

// crumbs: the bottom line: where you are, k9s style, and the last message.
func (m *Model) crumbs() string {
	var parts []string
	if m.org != "" {
		parts = append(parts, sCrumb2.Render(m.org))
		env := m.env
		if env == "default" {
			env = m.t.T("all")
		}
		parts = append(parts, sCrumb2.Render(env))
	}
	parts = append(parts, sCrumb.Render(strings.ToLower(m.t.T(viewNames[m.view]))))
	l := strings.Join(parts, " ")
	switch {
	case m.err != "":
		l += "  " + sErr.Render(m.err)
	case m.toast != "" && m.now().Sub(m.toastAt).Seconds() < 5:
		l += "  " + sOK.Render(m.toast)
	case len(m.orgs.Errors) > 0:
		l += "  " + sErr.Render(fmt.Sprintf("%s: %d (kanareika validate)", m.t.T("Config errors"), len(m.orgs.Errors)))
	}
	return l
}
