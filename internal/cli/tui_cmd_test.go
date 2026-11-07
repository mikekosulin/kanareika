package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/tui"
)

func TestTUIEntry(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	oldTerm, oldRun := isTerminal, runTUI
	t.Cleanup(func() { isTerminal, runTUI = oldTerm, oldRun })
	runs := 0
	runTUI = func(m *tui.Model, _ io.Reader, _ io.Writer) error {
		if m == nil {
			t.Fatal("no model")
		}
		runs++
		return nil
	}
	// not a terminal: the help, never a screen
	isTerminal = func() bool { return false }
	if code, out, _ := cli(t); code != 0 || !strings.Contains(out, "Three interfaces") || runs != 0 {
		t.Fatal(code, out, runs)
	}
	isTerminal = func() bool { return true }
	if code, _, _ := cli(t); code != 0 || runs != 1 {
		t.Fatal(code, runs)
	}
	if code, _, _ := cli(t, "tui", "--org", "acme", "--env", "production", "--lang", "ru"); code != 0 || runs != 2 {
		t.Fatal(code, runs)
	}
	if code, _, _ := cli(t, "tui", "--url", "http://127.0.0.1:1", "--token", "x"); code != 0 || runs != 3 {
		t.Fatal(code, runs)
	}
	if code, _, _ := cli(t, "tui", "extra"); code != 1 {
		t.Fatal("arguments are refused")
	}
	// the web interface keeps its old names
	for _, name := range []string{"dashboard", "serve"} {
		if code, out, _ := cli(t, name, "--help"); code != 0 || !strings.Contains(out, "web interface") {
			t.Fatal(name, code)
		}
	}
	// config errors don't stop it: they are shown inside, as on the web
	write(t, home()+"/policy/profiles.yml", "default: [")
	if code, _, _ := cli(t, "tui"); code != 0 || runs != 4 {
		t.Fatal(code, runs)
	}
}

func TestLangFromEnv(t *testing.T) {
	for _, k := range []string{"KANAREIKA_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Setenv(k, "")
	}
	if langFromEnv() != "" {
		t.Fatal("empty")
	}
	t.Setenv("LANG", "ru_RU.UTF-8")
	if langFromEnv() != "ru" {
		t.Fatal(langFromEnv())
	}
	t.Setenv("LC_ALL", "C")
	if langFromEnv() != "ru" {
		t.Fatal("C is skipped")
	}
	t.Setenv("KANAREIKA_LANG", "en")
	if langFromEnv() != "en" {
		t.Fatal("KANAREIKA_LANG wins")
	}
}
