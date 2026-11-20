package tui

// The server card's fixes and history: the lists the web page's server page shows (GET /api/host?detail=1 and
// /api/host/history), so a server reads the same in both: what to fix on it, each fix with its CVEs, why and the
// command for this server, and what changed on it run by run.

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type hostResp struct {
	ID      string        `json:"id"`
	Fixes   []*tnode      `json:"fixes"`
	Details []*nodeDetail `json:"details"`
}

type hostChange struct {
	Pkg      string   `json:"pkg"`
	Priority string   `json:"priority"`
	IDs      []string `json:"ids"`
}

type hostRun struct {
	RunID    string       `json:"run_id"`
	State    string       `json:"state"` // ok, failed
	New      []hostChange `json:"new"`
	Resolved []hostChange `json:"resolved"`
}

// hostMsg: a host's fixes and runs; d nil when the server has no /api/host (before 0.8): the card keeps its own lists.
type hostMsg struct {
	key  string
	d    *hostResp
	runs []hostRun
}

// fetchHost: the fixes (with their details) and the runs of the host on screen; once per host and run.
func (m *Model) fetchHost() tea.Cmd {
	host := m.cardHost()
	if host == "" || m.rund == nil || m.pending["host"] != "" {
		return nil
	}
	k := m.fwKey(host)
	if _, ok := m.hostData[k]; ok {
		return nil
	}
	m.pending["host"] = k
	c := m.c
	q := url.Values{"org": {m.org}, "env": {m.env}, "run": {m.run}, "host": {host}, "detail": {"1"}}
	h := url.Values{"org": {m.org}, "env": {m.env}, "host": {host}}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var d hostResp
		if err := c.Get(ctx, "/api/host?"+q.Encode(), &d); err != nil {
			return hostMsg{key: k}
		}
		var r struct {
			Runs []hostRun `json:"runs"`
		}
		_ = c.Get(ctx, "/api/host/history?"+h.Encode(), &r) // none: the card goes without its history
		return hostMsg{key: k, d: &d, runs: r.Runs}
	}
}

// hostFixes: the loaded fixes of the host on the card, nil while they are on the way (or the server has none).
func (m *Model) hostFixes(name string) *hostMsg {
	if hd := m.hostData[m.fwKey(name)]; hd != nil && hd.d != nil {
		return hd
	}
	return nil
}

// fixLine: one fix of the card: priority, due, what it is, its CVEs and flags.
func (m *Model) fixLine(n *tnode) string {
	s := " " + prio(n.Priority) + " " + fit(m.dueCell(n.Due), 10, false) + " " + m.nodeText(n, false, true) +
		sMuted.Render(fmt.Sprintf("  %d CVE", n.CVEs))
	if n.EPSS >= 0.01 {
		s += sMuted.Render(" · EPSS " + epssText(n.EPSS))
	}
	if n.KEV {
		s += " " + lipgloss.NewStyle().Foreground(cP["P2"]).Bold(true).Render("KEV")
	}
	if n.RCE {
		s += " " + sErr.Render("RCE")
	}
	return s
}

// fixDetail: what a fix closes on this server: why its priority, its CVEs, what inside an image needs it and the
// command for this server's OS.
func (m *Model) fixDetail(n *tnode, d *nodeDetail) []string {
	out := []string{m.fixLine(n)}
	pad := "     "
	if d == nil {
		return out
	}
	var why []string
	for _, r := range d.Why {
		why = append(why, whyText(m.t, r))
	}
	if len(why) > 0 {
		out = append(out, pad+sMuted.Render(strings.Join(why, " · ")))
	}
	for _, c := range d.CVEs {
		s := pad + sText.Render(fit(c.ID, 16, false)) + " " + fit(c.Severity, 8, false)
		if c.EPSS != nil && *c.EPSS > 0 {
			s += sMuted.Render(" EPSS " + epssText(*c.EPSS))
		}
		if c.KEV {
			s += " " + lipgloss.NewStyle().Foreground(cP["P2"]).Bold(true).Render("KEV")
		}
		out = append(out, s+"  "+sMuted.Render(c.Title))
	}
	if d.More > 0 {
		out = append(out, pad+sMuted.Render(m.t.F("+{n} more", "n", strconv.Itoa(d.More))))
	}
	for _, k := range n.Kids {
		if k.Kind == "part" {
			out = append(out, pad+m.nodeText(k, false, true))
		}
	}
	for _, a := range d.Apply {
		out = append(out, pad+sOK.Render("$ "+a.Command))
	}
	return out
}

// historyLines: the runs that changed something on the server (+ appeared, − went) or did not reach it; nothing when
// every run was quiet.
func (m *Model) historyLines(runs []hostRun) []string {
	var out []string
	for _, r := range runs {
		if r.State == "ok" && len(r.New) == 0 && len(r.Resolved) == 0 {
			continue
		}
		s := " " + sText.Render(fit(m.t.runShort(r.RunID), 16, false))
		if r.State == "failed" {
			s += " " + sErr.Render(m.t.T("not reached"))
		}
		for _, x := range r.New {
			s += " " + sErr.Render("+"+x.Pkg)
		}
		for _, x := range r.Resolved {
			s += " " + sOK.Render("−"+x.Pkg)
		}
		out = append(out, s)
	}
	return out
}

// hostTask: the agent task for the server on the card, about that server only (/api/prompt?host=).
func (m *Model) hostTask(name string) tea.Cmd {
	hd := m.hostFixes(name)
	if hd == nil || hd.d.ID == "" {
		return nil
	}
	if m.clip == nil {
		m.say(m.t.T("This terminal session can't copy"))
		return nil
	}
	q := url.Values{"org": {m.org}, "env": {m.env}, "run": {m.run}, "by": {"host"}, "nodes": {hd.d.ID}, "host": {name},
		"lang": {m.t.lang}}
	done := m.t.T("Task copied to the clipboard")
	var out struct {
		Text string `json:"text"`
	}
	return m.get("/api/prompt?"+q.Encode(), func(any) tea.Msg { return copyMsg{text: out.Text, done: done} }, &out)
}
