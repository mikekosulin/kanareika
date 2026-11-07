package main

import (
	"os"
	"slices"
	"testing"
)

func TestRun(t *testing.T) {
	oldCLI, oldEngine := cliMain, engineMain
	t.Cleanup(func() { cliMain, engineMain = oldCLI, oldEngine })
	var cliArgs, engineArgs []string
	cliMain = func(v string, a []string) int {
		if v != version {
			t.Fatal(v)
		}
		cliArgs = a
		return 3
	}
	engineMain = func(a []string) int { engineArgs = a; return 7 }

	if rc := run([]string{"__trivy", "sbom", "x"}); rc != 7 || !slices.Equal(engineArgs, []string{"sbom", "x"}) || cliArgs != nil {
		t.Fatal(rc, engineArgs, cliArgs)
	}
	engineArgs = nil
	for _, args := range [][]string{{"scan", "--org", "acme"}, {}, {"db", "__trivy"}} {
		if rc := run(args); rc != 3 || !slices.Equal(cliArgs, args) || engineArgs != nil {
			t.Fatal(args, rc, cliArgs, engineArgs)
		}
	}
}

func TestMainEntry(t *testing.T) {
	oldCLI, oldExit, oldArgs := cliMain, exit, os.Args
	t.Cleanup(func() { cliMain, exit, os.Args = oldCLI, oldExit, oldArgs })
	var got []string
	cliMain = func(_ string, a []string) int { got = a; return 5 }
	code := -1
	exit = func(c int) { code = c }
	os.Args = []string{"kanareika", "history", "--org", "acme"}
	main()
	if code != 5 || !slices.Equal(got, []string{"history", "--org", "acme"}) {
		t.Fatal(code, got)
	}
}
