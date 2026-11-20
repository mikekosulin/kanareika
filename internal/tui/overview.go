package tui

// Overview: every organization and environment in one list (place 0, there only when there is more than one): its
// servers, its fixes by priority, when it was last scanned and how many servers that scan did not reach. enter opens
// its fixes; s asks to scan everything and s again starts it (POST /api/scan/all: one environment after another).

import (
	"strconv"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type ovRow struct {
	org orgRow
	env envRow
}

// ovRows: every org/env, in the order the server lists them.
func (m *Model) ovRows() []ovRow {
	var out []ovRow
	for _, o := range m.orgs.Orgs {
		for _, e := range o.Envs {
			out = append(out, ovRow{o, e})
		}
	}
	return out
}

// multiScope: more than one org/env: Overview is a place.
func (m *Model) multiScope() bool { return len(m.ovRows()) > 1 }

func (m *Model) overviewView(w, h int) []string {
	var rows [][]string
	for _, r := range m.ovRows() {
		pc, known := r.env.Last.counts()
		last := sDim.Render(m.t.T("never"))
		if r.env.Last != nil {
			last = sMuted.Render(m.t.runShort(r.env.Last.RunID))
			if at, ok := parseTime(r.env.Last.Finished); ok {
				last = sMuted.Render(agoShort(max(m.now().Sub(at), 0)))
			}
			if n := r.env.Last.HostsFailed; n > 0 {
				last += " " + sErr.Render(m.t.F("{n} not reached", "n", strconv.Itoa(n)))
			}
		}
		name := r.org.Name
		if name == "" {
			name = r.org.ID
		}
		rows = append(rows, []string{sText.Render(name), sBold.Render(m.envLabel(r.env.Env)), sMuted.Render(strconv.Itoa(r.env.Hosts)),
			count("P1", pc["P1"], known), count("P2", pc["P2"], known), count("P3", pc["P3"], known), count("P4", pc["P4"], known), last})
	}
	return m.table(viewCols[vOverview], rows, w, h)
}

// openScope: the row's fixes.
func (m *Model) openScope() tea.Cmd {
	rs := m.ovRows()
	if c := m.cur[vOverview]; c < len(rs) {
		cmd := m.selectEnv(rs[c].org.ID, rs[c].env.Env)
		m.toPlace(vActions)
		return cmd
	}
	return nil
}

// scanEverything: the first s asks (how many environments and servers), a second one within a few seconds starts a
// scan of each, one after another.
func (m *Model) scanEverything() tea.Cmd {
	if !m.scanOK {
		m.say(m.t.T("Scans can't be started here (read-only)"))
		return nil
	}
	if m.askAll.IsZero() || m.now().Sub(m.askAll) > 5*time.Second {
		servers := 0
		for _, r := range m.ovRows() {
			servers += r.env.Hosts
		}
		m.askAll = m.now()
		m.say(m.t.F("Scan {e} environments, {s} servers, one after another?", "e", strconv.Itoa(len(m.ovRows())), "s", strconv.Itoa(servers)) +
			" " + m.t.T("s again: start"))
		return nil
	}
	m.askAll = time.Time{}
	t := m.t // read here, not in the command's goroutine
	none := t.T("Nothing to scan: every environment is being scanned already")
	return m.post("/api/scan/all", map[string]string{}, func(v any) tea.Msg {
		ids, _ := obj(v)["ids"].([]any)
		if len(ids) == 0 {
			return toastMsg(none)
		}
		return tea.BatchMsg{func() tea.Msg { return toastMsg(t.F("Scans queued: {n}", "n", strconv.Itoa(len(ids)))) }, m.fetchJobs()}
	})
}
