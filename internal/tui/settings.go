package tui

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// Header modes: "" picks by the terminal's size (full when there is room, one line when not).
const (
	headerAuto    = ""
	headerFull    = "full"
	headerCompact = "compact"
	headerOff     = "off"
)

var headerModes = []string{headerAuto, headerFull, headerCompact, headerOff}

// Settings: the panel layout the user chose; kept between sessions (Options.Settings).
type Settings struct {
	Header string              `json:"header,omitempty"`
	ShowP4 bool                `json:"show_p4,omitempty"`
	NoTabs bool                `json:"no_tabs,omitempty"` // the line of view tabs under the header
	UTC    bool                `json:"utc,omitempty"`     // times in UTC instead of the system's zone
	Hidden map[string][]string `json:"hidden,omitempty"`  // view -> column keys switched off
}

// DefaultSettingsPath: <user config dir>/kanareika/tui.json ("" when there is no such dir).
func DefaultSettingsPath() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "kanareika", "tui.json")
}

// loadSettings: the saved layout; a missing or unreadable file is the default one.
func loadSettings(path string) Settings {
	var s Settings
	if path == "" {
		return s
	}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if !slices.Contains(headerModes, s.Header) {
		s.Header = headerAuto
	}
	return s
}

func saveSettings(path string, s Settings) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func (s *Settings) hidden(v view, key string) bool {
	return slices.Contains(s.Hidden[viewKeys[v]], key)
}

func (s *Settings) toggle(v view, key string) {
	if s.Hidden == nil {
		s.Hidden = map[string][]string{}
	}
	k := viewKeys[v]
	if i := slices.Index(s.Hidden[k], key); i >= 0 {
		s.Hidden[k] = slices.Delete(s.Hidden[k], i, i+1)
		if len(s.Hidden[k]) == 0 {
			delete(s.Hidden, k)
		}
		return
	}
	s.Hidden[k] = append(s.Hidden[k], key)
}

// viewKeys: stable names of the views in the settings file.
var viewKeys = [nViews]string{"orgs", "actions", "hosts", "packages", "runs", "scans"}
