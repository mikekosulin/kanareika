package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/mikekosulin/kanareika/internal/server"
)

func TestFrame(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir()) // not the feeds of this machine: slow and not the same everywhere
	var out bytes.Buffer
	if err := run(&out, t.TempDir(), "ru", "", "", "80x20", "2, down,enter,esc,space,q", "2026-11-07T12:00:00Z"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 20 || ansi.StringWidth(lines[0]) != 80 {
		t.Fatalf("%d lines, %d wide", len(lines), ansi.StringWidth(lines[0]))
	}
	if !strings.Contains(out.String(), "\x1b[38;2;") || !strings.Contains(ansi.Strip(out.String()), "12:00 UTC") {
		t.Fatal("no colors or not the time given")
	}
	for _, bad := range [][2]string{{"80", ""}, {"80x20", "yesterday"}} {
		if err := run(&out, t.TempDir(), "en", "", "", bad[0], "", bad[1]); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if err := run(&out, t.TempDir(), "en", "", "", "80x20", "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestServerFails(t *testing.T) {
	old := newServer
	t.Cleanup(func() { newServer = old })
	newServer = func(server.Options) (*server.Server, error) { return nil, errors.New("no assets") }
	if err := run(io.Discard, t.TempDir(), "en", "", "", "80x20", "", ""); err == nil || err.Error() != "no assets" {
		t.Fatal(err)
	}
}

// counter counts the messages it is given.
type counter struct{ n int }

func (c *counter) Init() tea.Cmd                       { return nil }
func (c *counter) Update(tea.Msg) (tea.Model, tea.Cmd) { c.n++; return c, nil }
func (c *counter) View() string                        { return "" }

// TestDrive: a command with no message ends the chain; a batch is run command by command.
func TestDrive(t *testing.T) {
	c := &counter{}
	drive(c, func() tea.Msg { return nil })
	if c.n != 0 {
		t.Fatalf("nil message delivered: %d", c.n)
	}
	one := func() tea.Msg { return "x" }
	drive(c, tea.Batch(one, one, func() tea.Msg { return nil }))
	if c.n != 2 {
		t.Fatalf("%d messages, want 2", c.n)
	}
}

type fatalErr string

// TestMainFunc: main parses the flags, prints the frame, and a bad flag value is fatal.
func TestMainFunc(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	oldArgs, oldFlags, oldOut, oldFatal := os.Args, flag.CommandLine, os.Stdout, fatal
	t.Cleanup(func() { os.Args, flag.CommandLine, os.Stdout, fatal = oldArgs, oldFlags, oldOut, oldFatal })
	fatal = func(v ...any) { panic(fatalErr(fmt.Sprint(v...))) }
	main1 := func(args ...string) (stdout, msg string) {
		os.Args = append([]string{"screenshots"}, args...)
		flag.CommandLine = flag.NewFlagSet("screenshots", flag.ContinueOnError)
		f, err := os.CreateTemp(t.TempDir(), "out")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		os.Stdout = f
		func() {
			defer func() {
				if e, ok := recover().(fatalErr); ok {
					msg = string(e)
				}
			}()
			main()
		}()
		b, _ := os.ReadFile(f.Name())
		return string(b), msg
	}
	out, msg := main1("-home", t.TempDir(), "-size", "60x10", "-now", "2026-11-07T09:30:00Z")
	if msg != "" || strings.Count(out, "\n") != 10 || !strings.Contains(ansi.Strip(out), "09:30 UTC") {
		t.Fatalf("%q %q", out, msg)
	}
	if out, msg := main1("-home", t.TempDir(), "-size", "big"); out != "" || !strings.Contains(msg, `-size "big"`) {
		t.Fatalf("%q %q", out, msg)
	}
}
