package tui

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/mikekosulin/kanareika/assets"
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

// col: a table column. Columns are as wide as their content (up to width); a narrow terminal drops them by drop.
type col struct {
	title string
	width int // the widest it gets; 0: flexible, takes the rest
	right bool
	min   int                         // flexible: the narrowest it is still of use (default 12)
	drop  int                         // dropped when there is no room, the higher first; 0: never. >0 can be switched off
	fill  func(row, width int) string // drawn at its final width (bars)
}

func (c col) key() string { return c.title }

// layout: which columns fit in width and how wide each is.
func (m *Model) layout(v view, cols []col, rows [][]string, width int) (keep, widths []int) {
	natural := make([]int, len(cols))
	for i, c := range cols {
		if m.set.hidden(v, c.key()) && c.drop > 0 {
			continue
		}
		keep = append(keep, i)
		n := ansi.StringWidth(m.t.T(c.title))
		switch {
		case c.fill != nil:
			n = max(c.width, c.min)
		default:
			for _, r := range rows {
				n = max(n, ansi.StringWidth(r[i]))
			}
		}
		if c.width > 0 && !c.right { // numbers (right-aligned) are never cut: they take what they need
			n = min(n, c.width)
		}
		if c.width == 0 {
			n = max(c.minW(), 1)
		}
		natural[i] = n
	}
	need := func() int {
		t := 0
		for _, i := range keep {
			t += natural[i] + 1
		}
		return t
	}
	for need() > width {
		worst := -1
		for _, i := range keep {
			if cols[i].drop > 0 && (worst < 0 || cols[i].drop > cols[worst].drop) {
				worst = i
			}
		}
		if worst < 0 {
			break
		}
		keep = slices.DeleteFunc(keep, func(i int) bool { return i == worst })
	}
	flex := 0
	for _, i := range keep {
		if cols[i].width == 0 {
			flex++
		}
	}
	rest := width - need()
	widths = make([]int, len(cols))
	for _, i := range keep {
		widths[i] = natural[i]
		if cols[i].width == 0 && rest > 0 {
			widths[i] += rest / flex
		}
	}
	return keep, widths
}

func (c col) minW() int {
	if c.min > 0 {
		return c.min
	}
	return 12
}

// table: rows under headers in width cells and height lines, the cursor row a full-width bar kept in view.
func (m *Model) table(cols []col, rows [][]string, width, height int) []string {
	return m.grid(cols, rows, width, height, true)
}

// grid: a table; without a cursor it shows the first rows that fit.
func (m *Model) grid(cols []col, rows [][]string, width, height int, cursor bool) []string {
	keep, widths := m.layout(m.view, cols, rows, width)
	// line: a row; the selected one as a bar, its charts (fill columns) keeping their colors on it
	line := func(r int, cells []string, selected bool) string {
		var l strings.Builder
		for _, i := range keep {
			c := cells[i]
			chart := cols[i].fill != nil && r >= 0
			if chart {
				c = cols[i].fill(r, widths[i])
			}
			c = fit(c, widths[i], cols[i].right)
			if selected && !chart {
				c = sSel.Render(ansi.Strip(c))
			}
			l.WriteString(c)
			if selected {
				l.WriteString(sSel.Render(" "))
			} else {
				l.WriteString(" ")
			}
		}
		out := l.String()
		if pad := width - ansi.StringWidth(out); selected && pad > 0 {
			out += sSel.Render(strings.Repeat(" ", pad))
		}
		return fit(out, width, false)
	}
	head := make([]string, len(cols))
	for i, c := range cols {
		head[i] = sHead.Render(strings.ToUpper(m.t.T(c.title)))
	}
	out := []string{line(-1, head, false)}
	if len(rows) == 0 {
		return append(out, sMuted.Render(" "+m.t.T("nothing here")))
	}
	h := max(height-1, 1)
	cur, off := -1, 0
	if cursor {
		cur = min(m.cur[m.view], len(rows)-1)
		off = min(m.off[m.view], cur)
		if cur >= off+h {
			off = cur - h + 1
		}
		m.off[m.view] = off
	}
	for i := off; i < min(off+h, len(rows)); i++ {
		out = append(out, line(i, rows[i], i == cur))
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

const (
	headerH      = 6 // lines of the full header
	minW, minH   = 40, 8
	fullW, fullH = 80, 24 // the auto header is full from this size up
)

// headerMode: the header actually drawn (the setting, or by size when auto).
func (m *Model) headerMode() string {
	if m.set.Header != headerAuto {
		return m.set.Header
	}
	if m.w >= fullW && m.h >= fullH {
		return headerFull
	}
	return headerCompact
}

func (m *Model) headerLines() []string {
	switch m.headerMode() {
	case headerFull:
		return m.header()
	case headerCompact:
		return []string{m.compactHeader()}
	}
	return nil
}

func (m *Model) bodyHeight() int { return max(m.h-len(m.headerLines())-len(m.tabLines())-1-2, 3) } // inside the panel

// tabLines: the view tabs, unless switched off (o) or the terminal is too low for them.
func (m *Model) tabLines() []string {
	if m.set.NoTabs || m.h < 12 {
		return nil
	}
	return []string{m.tabs()}
}

// tabs: 1 Organizations  2 ToDo ... with the open one highlighted; numbers only for the others when the line is
// narrow. A scan running shows on the Scans tab.
func (m *Model) tabs() string {
	label := func(v view, full bool) string {
		n := viewHotkeys[v]
		name := m.t.T(viewNames[v])
		if v == vScans && m.busy() {
			name += " ●"
		}
		if v == m.view {
			return sCrumb.Render(n + " " + name)
		}
		if !full {
			return sKey.Render(n)
		}
		return sKey.Render(n) + " " + sMuted.Render(name)
	}
	var l string
	for _, f := range []struct {
		full bool
		sep  string
	}{{true, "  "}, {true, " "}, {false, "  "}} {
		parts := make([]string, nViews)
		for v := range nViews {
			parts[v] = label(v, f.full)
		}
		if l = " " + strings.Join(parts, f.sep); ansi.StringWidth(l) <= m.w {
			break
		}
	}
	return l
}

// View: exactly the terminal's size, every line clipped, so nothing ever wraps or scrolls.
func (m *Model) View() string {
	if m.w == 0 || m.h == 0 {
		return ""
	}
	var lines []string
	if m.w < minW || m.h < minH {
		lines = m.tooSmall()
	} else {
		hd := append(slices.Clip(m.headerLines()), m.tabLines()...)
		lines = append(slices.Clip(hd), m.main(m.h-len(hd)-1)...)
		lines = append(lines, m.crumbs())
	}
	for len(lines) < m.h {
		lines = append(lines, "")
	}
	lines = lines[:m.h]
	for i, l := range lines {
		lines[i] = fit(l, m.w, false)
	}
	return strings.Join(lines, "\n")
}

func (m *Model) tooSmall() []string {
	msg := []string{sBrand.Render("Kanareika"), sMuted.Render(fmt.Sprintf("%d×%d < %d×%d", m.w, m.h, minW, minH)),
		sMuted.Render(m.t.T("make the terminal bigger"))}
	out := make([]string, max((m.h-len(msg))/2, 0))
	for _, l := range msg {
		out = append(out, strings.Repeat(" ", max((m.w-ansi.StringWidth(l))/2, 0))+l)
	}
	return out
}

// --- header: context, priority gauges, keys, logo -------------------------------------------------------------------

func (m *Model) header() []string {
	info := m.info()
	showLogo := m.w >= 150
	logoW := 0
	if showLogo {
		logoW = ansi.StringWidth(logo[0]) + 2
	}
	infoW, gaugeW := 40, 30
	switch {
	case m.w < fullW:
		infoW, gaugeW = 34, 0
	case m.w < 100:
		infoW, gaugeW = 34, 22
	}
	keysW := max(m.w-infoW-gaugeW-logoW, 0)
	if gaugeW > 0 {
		keysW -= 2
	}
	gauges := m.gauges(gaugeW - 12)
	keys := m.keys(keysW)
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

// compactHeader: the header in one line: where, P1..P4, the scan, which data; what doesn't fit is left out
// (least needed first), the help key at the right.
func (m *Model) compactHeader() string {
	type part struct {
		text string
		rank int // lower: kept longer
	}
	var parts []part
	parts = append(parts, part{sBrand.Render("Kanareika"), 5})
	if m.org != "" {
		env := m.env
		if env == "default" {
			env = m.t.T("all")
		}
		parts = append(parts, part{sBold.Render(m.org) + sMuted.Render("/") + sBold.Render(env), 0})
	}
	if m.run != "" {
		parts = append(parts, part{sText.Render(m.t.runShort(m.run)), 4})
	}
	if m.rund != nil {
		pc := m.rund.PlanCounts
		var c []string
		for _, p := range []string{"P1", "P2", "P3", "P4"} {
			c = append(c, prio(p)+" "+count(p, pc[p], true))
		}
		parts = append(parts, part{strings.Join(c, " "), 1})
	}
	if s := m.scanState(); s != "" {
		parts = append(parts, part{s, 2})
	}
	if m.dbAttention() != "" || m.db != nil && m.db.Updating {
		parts = append(parts, part{m.dbState(), 3})
	}
	help := sKey.Render("<?>") + " " + sMuted.Render(m.t.T("help"))
	join := func(ps []part) string {
		t := make([]string, len(ps))
		for i, p := range ps {
			t[i] = p.text
		}
		return " " + strings.Join(t, sDim.Render(" │ "))
	}
	for rank := 5; rank > 0; rank-- {
		if ansi.StringWidth(join(parts))+ansi.StringWidth(help)+3 <= m.w {
			break
		}
		parts = slices.DeleteFunc(parts, func(p part) bool { return p.rank == rank })
	}
	l := join(parts)
	if room := m.w - ansi.StringWidth(help) - 1; ansi.StringWidth(l)+2 <= room {
		return fit(l, room, false) + help + " "
	}
	return l
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
				env = sBold.Render(name) + sMuted.Render(fmt.Sprintf(" · %s: %d", m.t.T("hosts"), e.Hosts))
			}
		}
	}
	if m.run != "" {
		data = sText.Render(m.t.runShort(m.run))
		if m.run != "current" {
			data += sMuted.Render(" " + m.t.zoneName(m.now()))
		}
	}
	if st := m.scanState(); st != "" {
		scan = st
	}
	trivy := sDim.Render("-")
	if m.rund != nil && m.rund.Meta.TrivyVersion != "" {
		trivy = sText.Render(m.rund.Meta.TrivyVersion)
		if m.rund.Meta.FeedsUpdated == nil {
			trivy += sMuted.Render(" · KEV/EPSS " + m.t.T("not loaded"))
		}
	}

	db := m.dbState()
	if db == "" {
		db = sDim.Render("-")
	}
	return []string{kv("Org", org), kv("Env", env), kv("Data", data), kv("Scan", scan), kv("Trivy", trivy), kv("DB", db)}
}

// dbState: the vulnerability DB in a few words: updating, missing, a newer one out, or its age.
func (m *Model) dbState() string {
	if m.db == nil {
		return ""
	}
	warn := lipgloss.NewStyle().Foreground(cP["P3"])
	switch {
	case m.db.Updating:
		return sRun.Render(m.t.T("DB updating…"))
	case m.dbAttention() == "missing":
		return sErr.Render(m.t.T("no DB")) + " " + sKey.Render("<U>")
	case m.dbAttention() == "outdated":
		return warn.Render(m.t.T("newer DB out")) + " " + sKey.Render("<U>")
	}
	for _, d := range m.db.DBs {
		if at, err := time.Parse(time.RFC3339, d.Updated); err == nil && d.Name == "db" {
			return sMuted.Render(agoShort(m.now().Sub(at)))
		}
	}
	return ""
}

// agoShort: a duration as 5m, 3h, 2d.
func agoShort(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// scanState: a scan running in this env (or scans started here), "" when none.
func (m *Model) scanState() string {
	if l := m.envd.Live; l != nil && (l.State == "running" || l.State == "stale") {
		if l.State == "stale" {
			return sErr.Render(m.t.T("scan not responding"))
		}
		p := progressOf(l)
		return sRun.Render(fmt.Sprintf("%s %d%% · %d/%d", m.t.T("running"), int(p.frac*100), p.finished, len(l.Hosts)))
	}
	if n := m.runningJobs(); n > 0 {
		return sRun.Render(fmt.Sprintf("%s: %d", m.t.T("running"), n))
	}
	return ""
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
func (m *Model) gauges(barW int) []string {
	if m.rund == nil || barW <= 0 {
		return nil
	}
	pc := m.rund.PlanCounts
	top := 1
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		top = max(top, pc[p])
	}
	var out []string
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		n := pc[p]
		fill := (n*barW + top - 1) / top
		bar := lipgloss.NewStyle().Foreground(cP[p]).Render(strings.Repeat("■", fill)) + sDim.Render(strings.Repeat("■", barW-fill))
		out = append(out, prio(p)+" "+bar+" "+fit(count(p, n, true), 4, true))
	}
	return append(out, sMuted.Render(fmt.Sprintf("   %d CVE", pc["cves"])))
}

// keys: k9s-style hints in columns, for the view on screen; what doesn't fit in width ends with <?> help.
func (m *Model) keys(width int) []string {
	type k struct{ key, what string }
	global := []k{{"1-0,S", "views"}, {"/", "filter"}, {"U", "update DBs"}, {"o", "panels"}, {"r", "refresh"}, {"L", "language"},
		{"q", "quit"}}
	local := map[view][]k{
		vOrgs:       {{"enter", "open"}},
		vActions:    {{"space", "select"}, {"a", "select all"}, {"v", "selected only"}, {"y", "copy task"}, {"enter", "details"}, {"p", "P4"}},
		vHosts:      {{"enter", "host card"}, {"p", "P4"}},
		vPackages:   {{"p", "P4"}},
		vChanges:    {{"/", "filter"}},
		vAccess:     {{"enter", "host card"}},
		vNetwork:    {{"enter", "host card"}, {"f", "outside only"}},
		vHealth:     {{"enter", "host card"}},
		vExceptions: {{"/", "filter"}},
		vRuns:       {{"enter", "open"}, {"i", "errors and log"}, {"c", "current state"}},
		vScans:      {{"enter", "output"}, {"x", "stop"}},
	}[m.view]
	if m.scanOK {
		local = append(local, k{"s", "scan"})
	}
	all := append(slices.Clip(local), global...)
	const colW = 19
	rows := headerH
	if fit := rows * max(width/colW, 0); fit < len(all)+1 {
		all = all[:max(fit-1, 0)]
	}
	if width >= colW {
		all = append(all, k{"?", "help"})
	}
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

func (m *Model) main(h int) []string {
	w := m.w
	switch {
	case m.help:
		return panel(sTitle.Render(m.t.T("Hotkeys")), m.helpView(w-2, h-2), w, h)
	case m.langs != nil:
		return panel(sTitle.Render(m.t.T("Language")), m.langView(), w, h)
	case m.panels != nil:
		return panel(sTitle.Render(m.t.T("Panels"))+sText.Render("("+m.t.T(viewNames[m.view])+")"), m.panelsView(h-2), w, h)
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
		t := m.title(viewNames[vActions], len(l), true)
		if len(m.sel) > 0 || m.onlySel {
			t += sBrand.Render(fmt.Sprintf(" ●%d", len(m.sel)))
			if m.onlySel {
				t += " " + sKey.Render("<v>") + sMuted.Render(" "+m.t.T("selected only"))
			}
		}
		return t, m.actionsView(l, w, h)
	case vHosts:
		if m.host != "" && m.rund != nil {
			lines := m.hostCard(m.host, w)
			m.hostOff = min(m.hostOff, max(len(lines)-h, 0))
			return sTitle.Render(m.t.T("Host")) + sText.Render("("+m.host+")"), lines[m.hostOff:]
		}
		l := m.hostList()
		return m.title(viewNames[vHosts], len(l), true), m.hostsView(l, w, h)
	case vPackages:
		l := m.packages()
		return m.title(viewNames[vPackages], len(l), true), m.packagesView(l, w, h)
	case vChanges:
		l := m.changes()
		return m.title(viewNames[vChanges], len(l), true), m.changesView(l, w, h)
	case vAccess:
		l := m.sectionHosts(m.rundAccess())
		return m.title(viewNames[vAccess], len(l), true), m.accessView(l, w, h)
	case vNetwork:
		l := m.sectionHosts(m.rundExposure())
		return m.title(viewNames[vNetwork], len(l), true), m.networkView(l, w, h)
	case vHealth:
		l := m.sectionHosts(m.rundHealth())
		return m.title(viewNames[vHealth], len(l), true), m.healthView(l, w, h)
	case vExceptions:
		l := m.exceptions()
		return m.title(viewNames[vExceptions], len(l), true), m.exceptionsView(l, w, h)
	case vRuns:
		if m.runInfo != nil {
			return sTitle.Render(m.t.T("Run")) + sText.Render("("+m.t.runShort(m.runInfo.id)+")"), m.runInfoView(w, h)
		}
		l := m.runList()
		return m.title(viewNames[vRuns], len(l), true), m.runsView(l, w, h)
	}
	return m.title(viewNames[vScans], len(m.jobs.Jobs), false), m.scansView(w, h)
}

// viewCols: the columns of each view, in the order of its cells. drop: what goes first on a narrow terminal.
var viewCols = [nViews][]col{
	vOrgs: {{title: "Organization", width: 20}, {title: "environment", width: 16}, {title: "hosts", width: 6, right: true, drop: 3},
		{title: "P1", width: 4, right: true}, {title: "P2", width: 4, right: true, drop: 2}, {title: "P3", width: 4, right: true, drop: 2},
		{title: "last run", width: 17, drop: 4}, {title: "state", width: 10, drop: 5}, {title: "name", min: 10, drop: 6}},
	vActions: {{width: 1}, {width: 2}, {title: "due by", width: 10, drop: 2}, {title: "action", min: 20},
		{title: "hosts", width: 26, drop: 3}, {title: "CVE", width: 4, right: true, drop: 1}},
	vHosts: {{title: "host", width: 26}, {title: "OS", width: 32, drop: 3}, {title: "P1", width: 4, right: true},
		{title: "P2", width: 4, right: true}, {title: "P3", width: 4, right: true, drop: 1}, {title: "P4", width: 4, right: true, drop: 1},
		{title: "CVE", width: 5, right: true, drop: 2}, {title: "chart", min: 8, drop: 4}},
	vPackages: {{width: 2}, {title: "host", width: 20, drop: 3}, {title: "where", width: 28, drop: 4}, {title: "package", min: 12},
		{title: "installed", width: 20, drop: 5}, {title: "fixed in", width: 20}, {title: "CVE", width: 4, right: true, drop: 2},
		{title: "KEV", width: 3, drop: 1}, {title: "due by", width: 10, drop: 6}},
	vChanges: {{width: 1}, {width: 2}, {title: "host", width: 20}, {title: "package / check", width: 40},
		{title: "where", min: 12, drop: 2}, {title: "CVE", width: 5, right: true, drop: 1}},
	vAccess: {{title: "host", width: 22}, {title: "password", width: 10}, {title: "root", width: 12, drop: 4},
		{title: "with password", width: 20, drop: 3}, {title: "keys", width: 5, right: true, drop: 2},
		{title: "logins", width: 6, right: true, drop: 1}, {title: "IPs", width: 4, right: true, drop: 1},
		{title: "failed", width: 8, right: true}, {title: "failed IPs", width: 6, right: true, drop: 2}},
	vNetwork: {{title: "host", width: 22}, {title: "public IP", width: 34, drop: 2}, {title: "open to the outside", width: 30},
		{title: "firewall", min: 12, drop: 1}},
	vHealth: {{title: "host", width: 22}, {title: "disk", width: 16}, {title: "inode", width: 5, right: true, drop: 3},
		{title: "memory", width: 10, drop: 2}, {title: "load", width: 8, drop: 2}, {title: "units", width: 5, right: true, drop: 4},
		{title: "kernel", width: 30, drop: 5}, {title: "journal", width: 7, right: true, drop: 4}, {title: "time zone", width: 16, drop: 6},
		{title: "time", width: 12, drop: 1}},
	vExceptions: {{width: 1}, {title: "host", width: 20}, {title: "id", width: 20}, {title: "package", width: 20, drop: 2},
		{title: "until", width: 10, drop: 3}, {title: "who", width: 12, drop: 4}, {title: "reason", min: 12, drop: 1}},
	vRuns: {{title: "run", width: 18}, {title: "state", width: 14}, {title: "kind", width: 10, drop: 3},
		{title: "hosts ok", width: 9, right: true, drop: 2}, {title: "P1", width: 4, right: true}, {title: "P2", width: 4, right: true, drop: 1},
		{title: "P3", width: 4, right: true, drop: 1}},
	vScans: {{title: "environment", width: 24}, {title: "state", width: 22}, {title: "started", width: 12, drop: 1},
		{title: "scope", min: 10, drop: 2}},
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
	return m.table(viewCols[vOrgs], rows, w, h)
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
			cves = compact(float64(a.CVEs))
		}
		rows = append(rows, []string{box, prio(a.Priority), sMuted.Render(a.Due), tags + sText.Render(m.t.title(a)),
			sText.Render(hostsCell(a.Hosts)), cves})
	}
	cols := viewCols[vActions]
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
			count("P3", c["P3"], true), count("P4", c["P4"], true), compact(float64(c["cves"])), ""})
	}
	cols := slices.Clone(viewCols[vHosts])
	cols[len(cols)-1].fill = func(r, w int) string { return stack(list[r].counts, top, w) }
	return m.table(cols, rows, w, h)
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
			sMuted.Render(p.Installed), sOK.Render(p.Fixed), compact(float64(p.CVEs)), kev, sMuted.Render(p.Due)})
	}
	return m.table(viewCols[vPackages], rows, w, h)
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
	return m.table(viewCols[vRuns], rows, w, h)
}

func (m *Model) scansView(w, h int) []string {
	var out []string
	if l := m.envd.Live; l != nil && (l.State == "running" || l.State == "stale") {
		out = append(out, m.liveView(l, w, h/2)...)
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
	out = append(out, m.table(viewCols[vScans], rows, w, listH)...)
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
			if w < 100 { // [12:00:01] web-01: ... -> web-01: ...
				if i := strings.Index(l, "] "); strings.HasPrefix(l, "[") && i > 0 && i < 12 {
					l = l[i+2:]
				}
			}
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

var helpRows = [][2]string{
	{"1-9, 0, S, tab", "views: organizations, ToDo, hosts, packages, changes, access, network, health, exceptions, runs, scans"},
	{"up/down, j/k, pgup/pgdn, g/G", "move"},
	{"enter", "open (an environment, a run, details, a scan's output)"},
	{"/", "filter the list; esc clears"},
	{"space, a", "select an action, select all"},
	{"v", "only the selected actions (ToDo)"},
	{"y", "copy the fix task for the selected actions (terminal clipboard, OSC 52)"},
	{"p", "show P4 too"},
	{"s", "start a scan of this environment"},
	{"x", "stop the scan under the cursor (Scans)"},
	{"c", "back to the current state (Runs)"},
	{"i", "a run's errors and log (Runs)"},
	{"f", "only ports open to the outside (Network)"},
	{"o", "panels: header, columns of this view (kept between sessions)"},
	{"z", "times in the system's time zone or in UTC"},
	{"U", "check for newer vulnerability DBs and download them (kanareika db update)"},
	{"L", "language"},
	{"r", "refresh"},
	{"q, ctrl+c", "quit"},
}

// helpView: the keys; scrolls (up/down) when the terminal is low.
func (m *Model) helpView(w, h int) []string {
	kw := min(30, max(w/3, 10))
	var out []string
	for _, r := range helpRows {
		text := strings.Split(ansi.Wordwrap(m.t.T(r[1]), max(w-kw-3, 10), ""), "\n")
		for i, t := range text {
			k := ""
			if i == 0 {
				k = r[0]
			}
			out = append(out, " "+sKey.Render(fit(k, kw, false))+" "+sText.Render(t))
		}
	}
	out = append(out, "",
		" "+sBrand.Render("★ ")+sText.Render(m.t.T("Like it? Star it on GitHub"))+"  "+sKey.Render(assets.Repo),
		" "+sErr.Render("! ")+sText.Render(m.t.T("Something wrong? Report an issue on GitHub (no real data, please)"))+"  "+sKey.Render(assets.Issues),
		"",
		" "+sMuted.Render(m.t.T("any key closes this")))
	m.helpOff = min(m.helpOff, max(len(out)-h, 0))
	return out[m.helpOff:]
}

// panelsView: the layout settings: the header, P4, the columns of the view on screen.
func (m *Model) panelsView(h int) []string {
	var lines []string
	for i, it := range m.panelItems() {
		var l string
		switch it.kind {
		case itemHead:
			l = " " + sLabel.Render(m.t.T(it.label))
		case itemChoice:
			l = "   " + sText.Render(m.t.T(it.label)+": ") + sBold.Render("< "+m.t.T(it.value)+" >")
		default:
			box := sDim.Render("[ ]")
			if it.on {
				box = sBrand.Render("[x]")
			}
			l = "   " + box + " " + sText.Render(m.t.T(it.label))
		}
		if i == m.panels.cur && it.kind != itemHead {
			l = sSel.Render(ansi.Strip(l))
		}
		lines = append(lines, l)
	}
	h = max(h-2, 3)
	if off := m.panels.cur - h + 1; off > 0 {
		lines = lines[off:]
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	return append(lines, "", " "+sKey.Render("<space>")+" "+sMuted.Render(m.t.T("toggle"))+"  "+sKey.Render("<esc>")+" "+
		sMuted.Render(m.t.T("close")))
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
	// the time now at the right, in the zone times are shown in (z switches it); the screen refreshes often enough
	z := m.t.zone
	if z == nil {
		z = time.UTC
	}
	clock := sMuted.Render(m.now().In(z).Format("15:04") + " " + m.t.zoneName(m.now()))
	if room := m.w - ansi.StringWidth(l) - ansi.StringWidth(clock) - 1; room >= 2 {
		l += strings.Repeat(" ", room) + clock
	}
	return l
}

// --- live scan -----------------------------------------------------------------------------------------------------

type progress struct {
	frac                                   float64 // modules done of all planned (finished hosts when unknown)
	finished, ok, warn, failed, running, n int
	elapsed, left                          time.Duration // left: 0 when it can't be told yet
}

// progressOf: how far a scan is. A host counts by its modules (the one running as half done) when the scan reports
// them, else as 0 or 1.
func progressOf(l *liveInfo) progress {
	p := progress{n: len(l.Hosts)}
	done := 0.0
	for _, h := range l.Hosts {
		switch h.State {
		case "ok":
			p.ok++
		case "warn":
			p.warn++
		case "failed":
			p.failed++
		case "running":
			p.running++
		}
		switch {
		case h.State == "ok" || h.State == "warn" || h.State == "failed" || h.State == "skipped":
			p.finished++
			done++
		case h.Steps > 0 && h.Step > 0:
			done += (float64(h.Step) - 0.5) / float64(h.Steps)
		}
	}
	if p.n > 0 {
		p.frac = max(0, min(done/float64(p.n), 1))
	}
	return p
}

// liveView: the scan running in this environment: a bar with the share of modules done, counts by state, time
// spent and left; then a line per host (state, its modules as a bar, the module, the last thing it said).
func (m *Model) liveView(l *liveInfo, w, h int) []string {
	p := progressOf(l)
	if at, err := time.Parse(time.RFC3339, l.Started); err == nil {
		p.elapsed = m.now().Sub(at).Truncate(time.Second)
		if p.frac > 0.05 && p.frac < 1 {
			p.left = time.Duration(float64(p.elapsed) * (1 - p.frac) / p.frac).Round(time.Second)
		}
	}
	head := " " + sBold.Render(m.t.T("Scan running")) + sMuted.Render(" "+m.org+"/"+m.env)
	pct := fmt.Sprintf(" %3d%%", int(p.frac*100))
	counts := " " + sOK.Render(fmt.Sprintf("✓%d", p.ok)) + " " + lipgloss.NewStyle().Foreground(cP["P3"]).Render(fmt.Sprintf("!%d", p.warn)) +
		" " + sErr.Render(fmt.Sprintf("✗%d", p.failed)) + " " + sRun.Render(fmt.Sprintf("▸%d", p.running)) +
		sMuted.Render(fmt.Sprintf(" %d/%d %s", p.finished, p.n, m.t.T("hosts")))
	times := ""
	if p.elapsed > 0 {
		times = sMuted.Render(" " + p.elapsed.String())
		if p.left > 0 {
			times += sMuted.Render(" · ~" + p.left.String() + " " + m.t.T("left"))
		}
	}
	if l.State == "stale" {
		times += " " + sErr.Render(m.t.T("scan not responding"))
	}
	var out []string
	if barW := w - ansi.StringWidth(head+pct+counts+times) - 1; barW >= 10 { // all in one line
		out = append(out, head+" "+bar(p.frac, barW)+pct+counts+times)
	} else { // the bar on a line of its own
		out = append(out, head+times, " "+bar(p.frac, max(w-ansi.StringWidth(pct+counts)-2, 4))+pct+counts)
	}

	names := make([]string, 0, len(l.Hosts))
	for n := range l.Hosts {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { // running first, then waiting, then finished; by name within
		a, b := stateRank(l.Hosts[names[i]].State), stateRank(l.Hosts[names[j]].State)
		if a != b {
			return a < b
		}
		return names[i] < names[j]
	})
	rows := make([][]string, 0, len(names))
	for _, n := range names {
		x := l.Hosts[n]
		st := map[string]string{"running": sRun.Render("▸"), "ok": sOK.Render("✓"), "warn": lipgloss.NewStyle().Foreground(cP["P3"]).Render("!"),
			"failed": sErr.Render("✗"), "skipped": sDim.Render("-")}[x.State]
		if st == "" {
			st = sDim.Render("·")
		}
		steps, errs := "", ""
		if x.Steps > 0 {
			steps = fmt.Sprintf("%d/%d", min(x.Step, x.Steps), x.Steps)
		}
		if x.Errors > 0 {
			errs = sErr.Render(strconv.Itoa(x.Errors))
		}
		rows = append(rows, []string{st, sBold.Render(n), "", sMuted.Render(steps), sText.Render(x.Module), errs, sMuted.Render(lastSaid(x))})
	}
	cols := []col{{width: 1}, {title: "host", width: 24}, {title: "modules", width: 12, min: 6, drop: 3},
		{width: 5, right: true, drop: 4}, {title: "module", width: 14, drop: 2}, {title: "err", width: 3, right: true, drop: 1},
		{title: "last", min: 16}}
	cols[2].fill = func(r, w int) string {
		x := l.Hosts[names[r]]
		if x.Steps == 0 {
			return ""
		}
		f := float64(x.Step) / float64(x.Steps)
		if x.State == "running" && x.Step > 0 {
			f = (float64(x.Step) - 0.5) / float64(x.Steps)
		}
		return bar(f, w)
	}
	return append(out, m.grid(cols, rows, w, max(h-len(out), 2), false)...)
}

func stateRank(s string) int {
	switch s {
	case "running":
		return 0
	case "pending", "":
		return 1
	case "failed":
		return 2
	case "warn":
		return 3
	}
	return 4
}

// bar: a share as a w-cell bar, eighths of a cell at its edge.
func bar(f float64, w int) string {
	if w <= 0 {
		return ""
	}
	f = max(0, min(f, 1))
	cells := f * float64(w)
	full := int(cells)
	part := ""
	if full < w {
		if e := int((cells - float64(full)) * 8); e > 0 {
			part = string([]rune("▏▎▍▌▋▊▉")[e-1])
		}
	}
	empty := w - full - ansi.StringWidth(part)
	return sRun.Render(strings.Repeat("█", full)+part) + sDim.Render(strings.Repeat("░", max(empty, 0)))
}

// lastSaid: the host's last log line without the module name it starts with (the module has its own column);
// "" for the bare "module ..." of a module starting.
func lastSaid(x liveHost) string {
	l := x.Last
	if x.Module != "" {
		if r, ok := strings.CutPrefix(l, x.Module); ok {
			l = strings.TrimPrefix(strings.TrimPrefix(r, ":"), " ")
		}
	}
	if l == "..." {
		return ""
	}
	return l
}

func (m *Model) langView() []string {
	out := []string{""}
	for i, l := range m.languages() {
		mark := "  "
		if l == m.t.lang {
			mark = sOK.Render("✓ ")
		}
		name := langNames[l]
		if name == "" {
			name = l
		}
		line := "  " + mark + sText.Render(fit(name, 12, false)) + sMuted.Render(strings.ToUpper(l))
		if i == m.langs.cur {
			line = sSel.Render(ansi.Strip(fit(line, 30, false)))
		}
		out = append(out, line)
	}
	return append(out, "", "  "+sKey.Render("<enter>")+" "+sMuted.Render(m.t.T("choose"))+"  "+sKey.Render("<esc>")+" "+sMuted.Render(m.t.T("close")))
}
