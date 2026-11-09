package tui

import (
	"testing"
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
