package tui

import (
	"net/http"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestNewerRelease: a newer kanareika from /api/version shows in the status bar; none, nothing; a server without
// /api/version (before 0.7) is no error on the screen.
func TestNewerRelease(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, false)
	h.run(h.m.fetchVersion()) // the harness's server checks nothing: no newer release
	h.hasNot("Update:")
	h.run(func() tea.Msg { return versionMsg{Latest: "v0.7.0"} })
	h.has("Update: v0.7.0")

	m := New(Options{Client: Local(http.NotFoundHandler())})
	if msg := m.fetchVersion()(); msg != nil {
		t.Fatalf("%#v", msg)
	}
}
