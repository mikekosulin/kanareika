package tui

import (
	"os"
	"sync"

	"github.com/charmbracelet/lipgloss"
)

// The theme: the palette for a dark or a light terminal. By default the terminal's own background decides
// (lipgloss asks it); the panels (o) and KANAREIKA_THEME can say dark or light.

var themes = []string{"", "dark", "light"}

// themeNames: the theme setting as the panels show it.
var themeNames = map[string]string{"": "auto", "dark": "dark", "light": "light"}

var (
	detectOnce sync.Once
	detected   bool // the terminal's background is dark (asked once, before any theme was forced)
)

// applyTheme: dark or light colors, by Options.Theme, KANAREIKA_THEME, the setting, or the terminal.
func (m *Model) applyTheme() {
	detectOnce.Do(func() { detected = lipgloss.HasDarkBackground() })
	theme := m.set.Theme
	if t := os.Getenv("KANAREIKA_THEME"); t == "dark" || t == "light" {
		theme = t
	}
	if m.theme != "" {
		theme = m.theme
	}
	switch theme {
	case "dark":
		lipgloss.SetHasDarkBackground(true)
	case "light":
		lipgloss.SetHasDarkBackground(false)
	default:
		lipgloss.SetHasDarkBackground(detected)
	}
}
