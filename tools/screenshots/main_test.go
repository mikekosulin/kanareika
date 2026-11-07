package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestFrame(t *testing.T) {
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
