package tui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Three places: Servers (with lenses: what to show of each server), ToDo (what to fix; accepted risks as a
// filter), History (runs, what changed, running scans). The views behind them are the place's sub-views.

// places: the tabs, their keys 1, 2, 3.
var places = []view{vServers, vActions, vRuns}

// place: the tab a view belongs to.
func place(v view) view {
	switch v {
	case vActions, vPackages, vExceptions:
		return vActions
	case vRuns, vScans, vChanges:
		return vRuns
	}
	return vServers
}

// lens: what Servers shows of each server. The backend lists them (GET /api/lens); priorities is the tree.
type lensDef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type lensCol struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	Kind  string `json:"kind"`
	Align string `json:"align"`
	Unit  string `json:"unit"`
	Width int    `json:"width_hint"`
	Drop  int    `json:"drop"`
}

type lensCell struct {
	V     any    `json:"v"`
	S     string `json:"s"`
	Level string `json:"level"` // ok, warn, bad
	Note  string `json:"note"`
}

// lensResp: GET /api/lens.
type lensResp struct {
	Lenses []lensDef `json:"lenses"`
	Lens   struct {
		ID      string    `json:"id"`
		Columns []lensCol `json:"columns"`
	} `json:"lens"`
	Rows []struct {
		Host  string              `json:"host"`
		State string              `json:"state"`
		Cells map[string]lensCell `json:"cells"`
	} `json:"rows"`
}

type lensMsg struct {
	key string
	d   *lensResp
	err error // 404: the server has no lenses yet
}

// stubLenses: the lenses until the server lists them, each drawn by the view it had before.
var stubLenses = []struct {
	lensDef
	v view
}{
	{lensDef{ID: "priorities", Title: "priorities"}, vServers}, {lensDef{ID: "logins", Title: "logins"}, vAccess},
	{lensDef{ID: "network", Title: "network"}, vNetwork}, {lensDef{ID: "health", Title: "health"}, vHealth},
}

// lenses: the lenses to choose from.
func (m *Model) lenses() []lensDef {
	if m.lensData != nil && len(m.lensData.Lenses) > 0 {
		return m.lensData.Lenses
	}
	out := make([]lensDef, len(stubLenses))
	for i, l := range stubLenses {
		out[i] = l.lensDef
	}
	return out
}

// setLens: Servers showing lens id: the tree, the server's lens, or (no lens API yet) the view that showed it.
func (m *Model) setLens(id string) {
	m.lens = id
	switch {
	case id == "priorities" || id == "":
		m.lens = "priorities"
		m.setView(vServers)
	case m.lensAPI:
		m.setView(vLens)
	default:
		for _, l := range stubLenses {
			if l.ID == id {
				m.setView(l.v)
			}
		}
	}
	m.cur[m.view], m.off[m.view] = 0, 0
}

// toPlace: a tab: Servers with its lens, ToDo, History.
func (m *Model) toPlace(v view) {
	if v == vServers {
		m.setLens(m.lens)
		return
	}
	m.setView(v)
}

// goPlace: the next or previous tab.
func (m *Model) goPlace(d int) {
	i := slices.Index(places, place(m.view))
	m.toPlace(places[(i+d+len(places))%len(places)])
}

func (m *Model) nextLens() {
	ls := m.lenses()
	i := slices.IndexFunc(ls, func(l lensDef) bool { return l.ID == m.lens })
	m.setLens(ls[(i+1)%len(ls)].ID)
}

func (m *Model) lensKey() string { return m.wantKey() + "?" + m.lens }

// fetchLens: the rows of the lens on screen (and the list of lenses); nil when they are here or on the way.
func (m *Model) fetchLens() tea.Cmd {
	if m.run == "" || m.lensNone || m.lensFail != "" && m.lensFail == m.lensKey() { // failed: again with r
		return nil
	}
	id := m.lens
	if id == "priorities" {
		if m.lensData != nil || m.pending["lens"] != "" {
			return nil
		}
		id = "" // the list only
	} else if k := m.lensKey(); m.lensFor == k || m.pending["lens"] == k {
		return nil
	}
	k := m.lensKey()
	m.pending["lens"] = k
	c := m.c
	q := "/api/lens?org=" + url.QueryEscape(m.org) + "&env=" + url.QueryEscape(m.env) + "&run=" + url.QueryEscape(m.run) + "&id=" + url.QueryEscape(id)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var d lensResp
		if err := c.Get(ctx, q, &d); err != nil {
			return lensMsg{k, nil, err}
		}
		return lensMsg{k, &d, nil}
	}
}

func (m *Model) onLens(msg lensMsg) {
	if m.pending["lens"] == msg.key {
		delete(m.pending, "lens")
	}
	var ae *APIError
	switch {
	case errors.As(msg.err, &ae) && ae.Status == http.StatusNotFound: // no lens API: the views that showed them
		m.lensNone = true
		return
	case msg.err != nil: // shown; asked again with r
		m.lensFail, m.err = msg.key, msg.err.Error()
		return
	case msg.d == nil || msg.key != m.lensKey(): // for a screen left since
		return
	}
	m.lensFail = ""
	m.lensAPI, m.lensData, m.lensFor = true, msg.d, msg.key
	if m.view != vLens && place(m.view) == vServers && m.lens != "priorities" {
		m.setLens(m.lens)
	}
}

// lensView: a lens from the server, drawn from its columns with the table rules.
func (m *Model) lensView(w, h int) []string {
	d := m.lensData
	if d == nil || m.lensFor != m.lensKey() {
		return []string{" " + sMuted.Render(m.t.T("loading"))}
	}
	cols := []col{{title: "server", width: 24}}
	for _, c := range d.Lens.Columns {
		cl := col{title: c.Title, width: c.Width, right: c.Align == "right", drop: c.Drop}
		if c.Unit != "" {
			cl.title += " " + c.Unit
		}
		if cl.width == 0 && !cl.right {
			cl.width, cl.min = 40, 10
		}
		cols = append(cols, cl)
	}
	var rows [][]string
	for _, r := range d.Rows {
		row := []string{sBold.Render(r.Host)}
		if r.State == "failed" {
			row[0] = sErr.Render("✗ " + r.Host)
		}
		for _, c := range d.Lens.Columns {
			cell := r.Cells[c.Key]
			s := cell.S
			if s == "" && cell.V != nil {
				s = fmt.Sprint(cell.V)
			}
			switch cell.Level { // colour only what needs attention
			case "warn":
				s = lipgloss.NewStyle().Foreground(cP["P3"]).Render(s)
			case "bad":
				s = sErr.Render(s)
			}
			row = append(row, s)
		}
		rows = append(rows, row)
	}
	return m.table(cols, rows, w, h)
}

// showSwitch: Servers' lenses in the header line: show  priorities  logins  network  health  w.
func (m *Model) showSwitch() string {
	g := sMuted.Render(m.t.T("show")) + " "
	for _, l := range m.lenses() {
		name := strings.ToLower(m.t.T(l.Title)) // lowercase like the group-by switch beside it
		s := sMuted.Render(" " + name + " ")
		if l.ID == m.lens {
			s = sCrumb2.Render(name)
		}
		id := l.ID
		g += m.zone("lens:"+id, s, func(int) tea.Cmd { m.setLens(id); return nil })
	}
	return g + " " + sKey.Render("w") + " "
}

// historyView: the runs, newest first, under the scans running or started here.
func (m *Model) historyView(w, h int) []string {
	var out []string
	if l := m.envd.Live; l != nil && (l.State == "running" || l.State == "stale") {
		out = append(out, m.liveView(l, w, h/2)...)
		out = append(out, "")
	}
	for _, j := range m.jobs.Jobs {
		if j.State != "running" {
			continue
		}
		last := ""
		if n := len(j.Output); n > 0 {
			last = j.Output[n-1]
		}
		out = append(out, " "+sRun.Render(m.spinChar()+" "+j.Request.Org+"/"+j.Request.Env)+"  "+sMuted.Render(ansi.Truncate(last, max(w-30, 10), "…"))+
			"  "+m.zoneKey("S", sKey.Render("S")+" "+sMuted.Render(m.t.T("output"))))
	}
	if len(out) > 0 {
		out = append(out, "")
	}
	return append(out, m.runsView(m.runList(), w, max(h-len(out), 3))...)
}
