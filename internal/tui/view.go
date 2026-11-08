package tui

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/mikekosulin/kanareika/assets"
	"github.com/mikekosulin/kanareika/internal/i18n"
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

// col: a table column. A column is as wide as its widest value (or its header), up to width; a narrow terminal first
// squeezes the squeezable ones (width 0, or min set) down to their minimum, then drops columns by drop.
type col struct {
	title string
	width int // the widest it gets; 0: as wide as its content, squeezed first when there is no room
	right bool
	min   int                         // squeezed: the narrowest it is still of use (default 12)
	drop  int                         // dropped when there is no room, the higher first; 0: never. >0 can be switched off
	fill  func(row, width int) string // drawn at its final width (bars); width is its width
	tight bool                        // one space after it instead of two (the tree's narrow marks)
	grow  bool                        // takes the width left over (the tree's text: its numbers at the right edge)
}

func (c col) key() string { return c.title }

func (c col) squeezable() bool { return c.fill == nil && (c.width == 0 || c.min > 0) }

func (c col) minW() int {
	if c.min > 0 {
		return c.min
	}
	return 12
}

// gapAfter: the space after a column: two, so that columns never run together; one for tight ones.
func (c col) gapAfter() int {
	if c.tight {
		return 1
	}
	return 2
}

// layout: which columns fit in width and how wide each is. Columns empty in every row are left out; what does not
// fit is squeezed, then the least useful columns go. Leftover width stays at the right, never as gaps.
func (m *Model) layout(v view, cols []col, rows [][]string, width int) (keep, widths []int) {
	natural := make([]int, len(cols))
	for i, c := range cols {
		if m.set.hidden(v, c.key()) && c.drop > 0 {
			continue
		}
		empty := len(rows) > 0 && c.fill == nil && c.title != ""
		n := ansi.StringWidth(m.t.T(c.title))
		if c.fill != nil {
			n = max(n, c.width, c.min)
		}
		for _, r := range rows {
			if i < len(r) && c.fill == nil {
				w := ansi.StringWidth(r[i])
				n = max(n, w)
				if strings.TrimSpace(ansi.Strip(r[i])) != "" {
					empty = false
				}
			}
		}
		if empty { // nothing to show in any row: no column
			continue
		}
		if c.width > 0 && !c.right && c.fill == nil { // numbers (right-aligned) are never cut: they take what they need
			n = min(n, c.width)
		}
		keep = append(keep, i)
		natural[i] = max(n, 1)
	}
	for {
		widths = slices.Clone(natural)
		need := 0
		for j, i := range keep {
			need += widths[i]
			if j < len(keep)-1 {
				need += cols[i].gapAfter()
			}
		}
		excess := need - width
		for _, i := range keep { // squeeze the squeezable, the widest first
			if excess <= 0 {
				break
			}
			if cols[i].squeezable() {
				r := min(excess, max(widths[i]-cols[i].minW(), 0))
				widths[i] -= r
				excess -= r
			}
		}
		if excess <= 0 {
			for _, i := range keep {
				if cols[i].grow {
					widths[i] -= excess // excess <= 0: what is left over
					break
				}
			}
			return keep, widths
		}
		worst := -1
		for _, i := range keep {
			if cols[i].drop > 0 && (worst < 0 || cols[i].drop > cols[worst].drop) {
				worst = i
			}
		}
		if worst < 0 {
			return keep, widths
		}
		keep = slices.DeleteFunc(keep, func(i int) bool { return i == worst })
	}
}

// table: rows under headers in width cells and height lines, the cursor row a full-width bar kept in view.
func (m *Model) table(cols []col, rows [][]string, width, height int) []string {
	return m.grid(cols, rows, width, height, true)
}

// grid: a table; without a cursor it shows the first rows that fit. With one, every row is clickable (rowClick).
func (m *Model) grid(cols []col, rows [][]string, width, height int, cursor bool) []string {
	keep, widths := m.layout(m.view, cols, rows, width)
	// line: a row; the selected one as a bar, its charts (fill columns) keeping their colors on it
	line := func(r int, cells []string, selected bool) string {
		var l strings.Builder
		for j, i := range keep {
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
			if j < len(keep)-1 {
				gap := strings.Repeat(" ", cols[i].gapAfter())
				if selected {
					gap = sSel.Render(gap)
				}
				l.WriteString(gap)
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
		l := line(i, rows[i], i == cur)
		if cursor {
			i := i
			l = m.zone(fmt.Sprintf("row:%d", i), l, func(dx int) tea.Cmd { return m.rowClick(i, dx) })
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

const minW, minH = 40, 8

func (m *Model) bodyHeight() int { return max(m.h-len(m.tabLines())-2-2, 3) } // inside the panel

// tabLines: the view tabs, unless switched off (o) or the terminal is too low for them.
func (m *Model) tabLines() []string {
	if m.set.NoTabs || m.h < 12 {
		return nil
	}
	return []string{m.tabs()}
}

// tabs: 1 ToDo  2 Hosts ... with the open one highlighted; numbers only for the others when the line is narrow. A
// scan running shows on the Scans tab; ToDo's grouping (g) at the right.
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
			parts[v] = m.zone(fmt.Sprintf("tab:%d", v), label(v, f.full), func(int) tea.Cmd { m.setView(v); return nil })
		}
		if l = " " + strings.Join(parts, f.sep); ansi.StringWidth(l) <= m.w {
			break
		}
	}
	if m.view == vActions && m.run != "" {
		g := sMuted.Render(m.t.T("group by")) + " "
		for _, by := range groupings {
			name := m.t.T(groupNames[by])
			s := sMuted.Render(" " + name + " ")
			if by == m.by {
				s = sCrumb2.Render(name)
			}
			g += m.zone("by:"+by, s, func(int) tea.Cmd {
				if m.by != by {
					m.by = by
					m.cur[vActions], m.off[vActions], m.curID = 0, 0, ""
				}
				return nil
			})
		}
		g += " " + sKey.Render("g") + " "
		if room := m.w - ansi.StringWidth(l) - ansi.StringWidth(g); room >= 2 {
			l += strings.Repeat(" ", room) + g
		}
	}
	return l
}

// View: exactly the terminal's size, every line clipped, so nothing ever wraps or scrolls.
func (m *Model) View() string {
	if m.w == 0 || m.h == 0 {
		return ""
	}
	m.handlers = map[string]func(int) tea.Cmd{}
	m.zoneSeq = 0
	var lines []string
	if m.w < minW || m.h < minH {
		lines = m.tooSmall()
	} else {
		hd := m.tabLines()
		lines = append(slices.Clip(hd), m.main(m.h-len(hd)-2)...)
		lines = append(lines, m.hints(), m.statusBar())
		if m.menu != nil {
			box := m.menuBox()
			lines = overlay(lines, box, max((m.w-ansi.StringWidth(box[0]))/2, 0), min(len(hd)+1, max(m.h-len(box), 0)), m.w)
		}
	}
	for len(lines) < m.h {
		lines = append(lines, "")
	}
	lines = lines[:m.h]
	for i, l := range lines {
		lines[i] = fit(l, m.w, false)
	}
	lines = m.scanZones(lines)
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
	case m.setup != nil:
		return panel(m.setupTitle(), m.setupView(w-2, h-2), w, h)
	case !m.loaded:
		msg := m.t.T("loading")
		if m.err != "" {
			msg = sErr.Render(m.err)
		}
		return panel(sTitle.Render("Kanareika"), []string{" " + msg}, w, h)
	case m.view == vActions:
		return m.todoMain(h)
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
	vHosts: {{title: "host", width: 24}, {title: "group", width: 16, drop: 3}, {title: "OS", width: 28, min: 12, drop: 4},
		{title: "P1", right: true}, {title: "P2", right: true}, {title: "P3", right: true, drop: 2}, {title: "P4", right: true, drop: 1},
		{title: "CVE", right: true, drop: 2}, {width: barW, min: barW, drop: 6}, {title: "facing", width: 10, drop: 5}},
	vPackages: {{width: 2}, {title: "host", width: 20, drop: 3}, {title: "where", width: 24, min: 8, drop: 4},
		{title: "package", width: 32, min: 14}, {title: "installed", width: 28, right: true, drop: 5}, {title: "fixed in", width: 28},
		{title: "CVE", right: true, drop: 2}, {title: "KEV", drop: 1}, {title: "due by", width: 10, drop: 6}},
	vChanges: {{width: 1, tight: true}, {width: 2}, {title: "host", width: 20}, {title: "package / check", width: 40, min: 16},
		{title: "where", width: 32, min: 12, drop: 2}, {title: "CVE", right: true, drop: 1}},
	vAccess: {{title: "host", width: 22}, {title: "password", width: 10}, {title: "root", width: 12, drop: 4},
		{title: "with password", width: 24, min: 10, drop: 3}, {title: "keys", right: true, drop: 2},
		{title: "logins", right: true, drop: 1}, {title: "IPs", right: true, drop: 1},
		{title: "failed", right: true}, {title: "failed IPs", right: true, drop: 2}},
	vNetwork: {{title: "host", width: 22}, {title: "public IP", width: 34, min: 15, drop: 2}, {title: "open to the outside", width: 30, min: 12},
		{title: "firewall", width: 48, min: 12, drop: 1}},
	vHealth: {{title: "host", width: 22}, {title: "disk", width: 18}, {title: "inode", right: true, drop: 3},
		{title: "mem free", right: true, drop: 2}, {title: "load /cpu", right: true, drop: 2}, {title: "failed units", right: true, drop: 4},
		{title: "kernel", width: 30, min: 12, drop: 5}, {title: "journal /7d", right: true, drop: 4}, {title: "time zone", width: 18, drop: 6},
		{title: "clock offset", width: 12, drop: 1}},
	vExceptions: {{width: 1, tight: true}, {title: "host", width: 20}, {title: "id", width: 20}, {title: "package", width: 24, drop: 2},
		{title: "until", width: 10, drop: 3}, {title: "who", width: 16, drop: 4}, {title: "reason", width: 60, min: 12, drop: 1}},
	vRuns: {{title: "run", width: 18}, {title: "state", width: 22}, {title: "kind", width: 10, drop: 3},
		{title: "hosts ok", right: true, drop: 2}, {title: "P1", right: true}, {title: "P2", right: true, drop: 1},
		{title: "P3", right: true, drop: 1}},
	vScans: {{title: "environment", width: 24}, {title: "state", width: 22}, {title: "started", width: 12, drop: 1},
		{title: "scope", width: 60, min: 10, drop: 2}},
}

func (m *Model) noData() []string {
	if m.org == "" {
		l := []string{"", " " + sMuted.Render(m.t.T("no organizations")+": ") + sKey.Render("kanareika org new <id>")}
		if m.scanOK {
			l = append(l, " "+m.t.FS("or press {key} to set one up here", sMuted, "key", sKey.Render("<N>")))
		}
		return l
	}
	if m.run == "" {
		cmd := "kanareika scan " + m.org
		if m.env != "default" {
			cmd += " --env " + m.env
		}
		l := []string{"", " " + sMuted.Render(m.t.T("No runs yet. Run")+": ") + sKey.Render(cmd)}
		if m.scanOK {
			l = append(l, " "+m.t.FS("or press {key}", sMuted, "key", sKey.Render("<s>")),
				" "+m.t.FS("{key} checks SSH access to every host, then starts the first scan", sMuted, "key", sKey.Render("<enter>")))
		}
		return l
	}
	return []string{" " + sMuted.Render(m.t.T("loading"))}
}

// stack: a host's P1..P4 as one stacked bar of width w (btop style).
const barW = 16 // the hosts' bar: a line, never the whole free width

// stack: a host's P1..P3 as one thin line of at most w cells, scaled to top (the largest row's); P4 is background
// and left out.
func stack(c map[string]int, top, w int) string {
	if top == 0 {
		return ""
	}
	var b strings.Builder
	used := 0
	for _, p := range []string{"P1", "P2", "P3"} {
		n := (c[p]*w + top - 1) / top
		n = min(n, w-used)
		b.WriteString(lipgloss.NewStyle().Foreground(cP[p]).Render(strings.Repeat("━", n)))
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
		top = max(top, x.counts["P1"]+x.counts["P2"]+x.counts["P3"])
	}
	group, facing := map[string]string{}, map[string]string{}
	for _, h := range m.envd.Hosts {
		group[h.Name] = h.Group
		if h.Exposure == 1 {
			facing[h.Name] = lipgloss.NewStyle().Foreground(cP["P2"]).Render(m.t.T("internet"))
		}
	}
	var rows [][]string
	for _, x := range list {
		c := x.counts
		rows = append(rows, []string{sBold.Render(x.name), sMuted.Render(group[x.name]), sText.Render(x.os), count("P1", c["P1"], true),
			count("P2", c["P2"], true), count("P3", c["P3"], true), sDim.Render(strconv.Itoa(c["P4"])), compact(float64(c["cves"])),
			"", facing[x.name]})
	}
	cols := slices.Clone(viewCols[vHosts])
	cols[len(cols)-2].fill = func(r, w int) string { return stack(list[r].counts, top, w) }
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
			sMuted.Render(p.Installed + " →"), sOK.Render(p.Fixed), compact(float64(p.CVEs)), kev, sMuted.Render(p.Due)})
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
		return append(out, "", " "+m.t.FS("Press {key} to start a scan of {target}", sMuted,
			"key", sKey.Render("<s>"), "target", sText.Render(m.org+"/"+m.env)))
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
	{"1-9, 0, S, tab", "views: ToDo, hosts, packages, changes, access, network, health, exceptions, runs, scans"},
	{"O, E", "organization, environment (popup lists; type to narrow them)"},
	{":, ctrl+k", "jump to a fix, a CVE, a host or a view"},
	{"up/down, j/k, pgup/pgdn, g/G", "move (ToDo: home/end, G)"},
	{"right/left, l/h", "ToDo: open and close a node; other views: the next and previous view"},
	{"enter", "open (details of a node, a run, a host card, a scan's output)"},
	{"/", "filter the list; esc clears"},
	{"g", "ToDo: group by fix, CVE or host"},
	{"f", "ToDo: filters (KEV, RCE, EPSS, internet-facing, fix ready, no fix, overdue); Network: only ports open to the outside"},
	{"space, x, a", "select a node and everything under it, select all"},
	{"v", "only the selected (ToDo)"},
	{"y", "copy the fix task for the selected nodes (terminal clipboard, OSC 52): paste it into an AI agent"},
	{"Y", "copy the context of the node under the cursor (what, where, why, due, commands, its id) for an AI agent's chat"},
	{"c, [ ]", "copy the chosen command of the details; choose another"},
	{"p", "show P4 too"},
	{"s", "start a scan of this environment"},
	{"N", "set up a new organization (hosts, SSH access check, the first scan)"},
	{"x", "stop the scan under the cursor (Scans)"},
	{"c", "back to the current state (Runs)"},
	{"i", "a run's errors and log (Runs)"},
	{"o", "panels: tabs, columns of this view, time zone (kept between sessions)"},
	{"z", "times in the system's time zone or in UTC"},
	{"U", "check for newer vulnerability DBs and download them (kanareika db update)"},
	{"L", "language"},
	{"r", "refresh"},
	{"mouse", "click tabs, rows, the check and caret of a node, commands, hints, the org and env below; the wheel scrolls. Shift+drag selects text; o turns the mouse off"},
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
		" "+sTitle.Render(m.t.T("AI agent in the next pane")),
		" "+sText.Render(m.t.T("y copies the task, Y the context of one node. An agent with kanareika's MCP server gets the same data itself:")),
		" "+sKey.Render("list_fixes")+sMuted.Render(" · ")+sKey.Render("get_fix")+sMuted.Render(" · ")+sKey.Render("fix_prompt")+sMuted.Render(" · ")+
			sKey.Render("fix_plan")+sMuted.Render("  (kanareika mcp)"))
	if m.db != nil && m.db.Trivy != "" {
		out = append(out, " "+sMuted.Render("Trivy "+m.db.Trivy+" · "+m.t.T("built in")))
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
		name := i18n.Name(l)
		line := "  " + mark + sText.Render(fit(name, 12, false)) + sMuted.Render(strings.ToUpper(l))
		if i == m.langs.cur {
			line = sSel.Render(ansi.Strip(fit(line, 30, false)))
		}
		out = append(out, line)
	}
	return append(out, "", "  "+sKey.Render("<enter>")+" "+sMuted.Render(m.t.T("choose"))+"  "+sKey.Render("<esc>")+" "+sMuted.Render(m.t.T("close")))
}

// FS: as F, with the sentence's own words in base and the values as given (already styled: a key, a name).
func (t *tr) FS(s string, base lipgloss.Style, kv ...string) string { return fill(t.T(s), &base, kv) }

// fill puts the values into a template's {name}s; the words around them in base when there is one. A {name}
// without a value stays as written.
func fill(tmpl string, base *lipgloss.Style, kv []string) string {
	vals := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		vals[kv[i]] = kv[i+1]
	}
	var b strings.Builder
	words := func(s string) {
		if s != "" && base != nil {
			s = base.Render(s)
		}
		b.WriteString(s)
	}
	last := 0
	for _, m := range argRE.FindAllStringSubmatchIndex(tmpl, -1) {
		v, ok := vals[tmpl[m[2]:m[3]]]
		if !ok {
			continue
		}
		words(tmpl[last:m[0]])
		b.WriteString(v)
		last = m[1]
	}
	words(tmpl[last:])
	return b.String()
}
