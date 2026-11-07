package main

import (
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
