package tui

import (
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TestStaleWizardAnswers: a check, the hosts or the setup's answer for a wizard closed since (esc, N) is dropped; a
// wizard without results takes one; the checks in flight never go below zero.
func TestStaleWizardAnswers(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, false)
	m := h.m
	old := m.checkWizard("acme", "production")
	m.setup = m.newWizard() // the old one closed, a new one open
	m.Update(checkedMsg{gen: old.gen, host: "web-1", r: checkResult{Host: "web-1", OK: true}})
	m.Update(hostsMsg{gen: old.gen, hosts: []hostRef{{name: "web-1"}}})
	m.Update(setupMsg{gen: old.gen, kind: "created", org: "x", env: "y"})
	if len(m.setup.res) != 0 || m.setup.hosts != nil || m.setup.step != 1 || m.setup.inflight != 0 {
		t.Fatalf("a stale answer taken: %+v", m.setup)
	}
	m.setup = &wizard{gen: m.setup.gen, step: 2} // no results map yet
	m.Update(checkedMsg{gen: m.setup.gen, host: "web-1", r: checkResult{Host: "web-1", OK: true}})
	m.Update(checkedMsg{gen: m.setup.gen, host: "web-2", r: checkResult{Host: "web-2"}})
	if r := m.setup.res["web-1"]; r == nil || !r.OK || m.setup.inflight != 0 {
		t.Fatalf("%+v %d", m.setup.res, m.setup.inflight)
	}
	m.setup = nil
	m.Update(checkedMsg{gen: 1, host: "web-1"}) // no wizard at all
}

// TestClicksBehindDialogs: with a dialog open a click behind it does nothing; a panels cursor past its list is
// pulled back instead of indexing out of range.
func TestClicksBehindDialogs(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, false)
	x, y := h.where("History")
	for _, open := range []func(){
		func() { h.key("o") },
		func() { h.key("?") },
		func() { h.m.setup = h.m.checkWizard("acme", "production") },
	} {
		open()
		h.mouse(x, y, tea.MouseButtonLeft)
		if h.m.view == vRuns {
			t.Fatal("a click went through a dialog")
		}
		h.m.panels, h.m.help, h.m.setup = nil, false, nil
	}
	h.key("o")
	h.m.panels.cur = 999
	h.screen()
	h.key("enter")
	h.key("down")
	if h.m.panels != nil && h.m.panels.cur >= len(h.m.panelItems()) {
		t.Fatal(h.m.panels.cur)
	}
}

// TestLensErrors: only a 404 means the server has no lenses; another error shows, is not asked again on every frame,
// and r asks again; an answer for a lens left since is dropped.
func TestLensErrors(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, false)
	m := h.m
	h.key("1")
	k := m.lensKey()
	m.onLens(lensMsg{key: k, err: &APIError{Status: 500, Msg: "boom"}})
	if m.lensNone || m.err != "boom" || m.fetchLens() != nil {
		t.Fatalf("none %v err %q", m.lensNone, m.err)
	}
	h.key("r")
	if m.lensFail != "" || m.lensNone {
		t.Fatal("r keeps the failure")
	}
	m.onLens(lensMsg{key: "elsewhere", d: &lensResp{}})
	if m.lensFor == "elsewhere" {
		t.Fatal("a stale lens taken")
	}
	m.onLens(lensMsg{key: k, err: &APIError{Status: 404}})
	if !m.lensNone {
		t.Fatal("404: no lens API")
	}
	h.key("r")
	if m.lensNone {
		t.Fatal("r asks again")
	}
}

// TestQuickWins: a forced theme never asks the terminal its background; end/G reach the bottom of full details;
// right/left switch places outside the trees (in them they open and close nodes).
func TestQuickWins(t *testing.T) {
	oldDark, oldOnce := hasDark, detectOnce
	t.Cleanup(func() { hasDark, detectOnce = oldDark, oldOnce; lipgloss.SetHasDarkBackground(true) })
	asked := 0
	hasDark = func() bool { asked++; return true }
	detectOnce = sync.Once{}
	h := newHarness(t, Options{Org: "acme", Env: "production", Theme: "light"}, false)
	if asked != 0 {
		t.Fatal("asked the terminal with the theme forced")
	}
	h.m.theme, h.m.set.Theme = "", ""
	h.m.applyTheme()
	if asked != 1 {
		t.Fatal("auto: the terminal decides", asked)
	}

	h.size(100, 14)
	h.key("2", "enter")
	if !h.m.full {
		t.Skip("no node to open")
	}
	h.screen()
	h.key("end")
	h.screen()
	bottom := h.m.detOff
	h.key("g")
	h.screen()
	if bottom == 0 || h.m.detOff != 0 {
		t.Fatal(bottom, h.m.detOff)
	}
	h.key("G")
	h.screen()
	if h.m.detOff != bottom {
		t.Fatal(h.m.detOff, bottom)
	}
	h.key("esc", "3")
	h.key("right")
	if h.m.view == vRuns {
		t.Fatal("right stayed on History")
	}
	h.key("3", "left")
	if h.m.view != vActions {
		t.Fatal("left from History", h.m.view)
	}
}

// TestSetupOrgWithoutEnvs: adding servers to an organization with no environments yet goes to production.
func TestSetupOrgWithoutEnvs(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, false)
	m := h.m
	m.orgs.Orgs = append([]orgRow{{ID: "servers", Name: "Personal"}}, m.orgs.Orgs...)
	m.setup = m.newWizard()
	m.setup.field("hosts").val = []rune("web-1")
	m.setup.field("confirmed").on = true
	if m.submit() == nil || m.setup.errs != nil {
		t.Fatal(m.setup.errs)
	}
}
