// Command screenshots renders one frame of the TUI, in color, for the README's screenshots:
//
//	go run ./tools/screenshots -home <dir> -lang ru -size 140x40 -keys 3,enter > frame.ans
//
// The frame is the interface over the working directory at -home (use demo data only: screenshots are published).
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/server"
	"github.com/mikekosulin/kanareika/internal/tui"
)

func main() {
	home := flag.String("home", ".", "working directory with orgs/ and reports/ (demo data)")
	lang := flag.String("lang", "en", "interface language")
	org := flag.String("org", "", "organization")
	env := flag.String("env", "", "environment")
	size := flag.String("size", "140x40", "terminal size, WxH")
	keys := flag.String("keys", "", "keys to press first, comma separated (enter, down, esc, or a letter)")
	at := flag.String("now", "", "the time it is, RFC 3339 (default: now)")
	flag.Parse()
	if err := run(os.Stdout, *home, *lang, *org, *env, *size, *keys, *at); err != nil {
		log.Fatal(err)
	}
}

func run(out io.Writer, home, lang, org, env, size, keys, at string) error {
	var w, h int
	if _, err := fmt.Sscanf(size, "%dx%d", &w, &h); err != nil {
		return fmt.Errorf("-size %q: %w", size, err)
	}
	now := time.Now()
	if at != "" {
		t, err := time.Parse(time.RFC3339, at)
		if err != nil {
			return err
		}
		now = t
	}
	lipgloss.SetColorProfile(termenv.TrueColor)
	s, err := server.New(server.Options{Paths: config.PathsAt(home), Log: log.New(io.Discard, "", 0)})
	if err != nil {
		return err
	}
	m := tui.New(tui.Options{Client: tui.Local(s.Handler()), Lang: lang, Org: org, Env: env, Zone: time.UTC,
		Now: func() time.Time { return now }, Tick: func(time.Duration) tea.Cmd { return nil }})
	m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	drive(m, m.Init())
	for _, k := range strings.Split(keys, ",") {
		if k = strings.TrimSpace(k); k == "" {
			continue
		}
		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "down":
			msg = tea.KeyMsg{Type: tea.KeyDown}
		case "space":
			msg = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")}
		}
		_, cmd := m.Update(msg)
		drive(m, cmd)
	}
	_, err = io.WriteString(out, m.View()+"\n")
	return err
}

// drive runs a command and what it leads to, synchronously (timers are not followed).
func drive(m tea.Model, cmd tea.Cmd) {
	for depth := 0; cmd != nil && depth < 20; depth++ {
		msg := cmd()
		if b, ok := msg.(tea.BatchMsg); ok {
			for _, c := range b {
				drive(m, c)
			}
			return
		}
		if msg == nil {
			return
		}
		_, cmd = m.Update(msg)
	}
}
