package tui

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// TestTheme: light terminals get the light palette (darker priorities, dark text); KANAREIKA_THEME, the screenshot
// tool's Options.Theme and the panels' setting choose it; auto follows the terminal.
func TestTheme(t *testing.T) {
	old := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(old); lipgloss.SetHasDarkBackground(true) })
	p1 := func() string { return prio("P1") }

	t.Setenv("KANAREIKA_THEME", "light")
	New(Options{})
	if !strings.Contains(p1(), "38;2;192;31;38") {
		t.Fatalf("light P1: %q", p1())
	}
	t.Setenv("KANAREIKA_THEME", "")
	New(Options{Theme: "dark"})
	if !strings.Contains(p1(), "38;2;229;72;77") {
		t.Fatalf("dark P1: %q", p1())
	}
	// the panels: auto -> dark -> light, kept
	path := filepath.Join(t.TempDir(), "tui.json")
	h := newHarness(t, Options{Org: "acme", Env: "production", Settings: path}, true)
	h.key("o")
	h.has("theme: < auto >")
	for h.m.panelItems()[h.m.panels.cur].label != "theme" {
		h.key("down")
	}
	h.key("space")
	h.has("theme: < dark >")
	h.key("space")
	h.has("theme: < light >")
	if lipgloss.HasDarkBackground() || loadSettings(path).Theme != "light" {
		t.Fatal("light from the panels")
	}
	h.key("space")
	h.has("theme: < auto >")
}
