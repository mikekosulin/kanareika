package engine

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestMain_(t *testing.T) {
	oldArgs, oldRun, oldFatal := os.Args, run, fatal
	t.Cleanup(func() { os.Args, run, fatal = oldArgs, oldRun, oldFatal })
	var fatals []string
	fatal = func(msg string, _ ...any) { fatals = append(fatals, msg) }

	for _, c := range []struct {
		err   error
		code  int
		fatal string
	}{
		{nil, 0, ""},
		{&types.ExitError{Code: 5}, 5, ""},
		{&types.UserError{Message: "bad flag"}, 1, "Error"},
		{errors.New("boom"), 1, "Fatal error"},
	} {
		fatals = nil
		var seen []string
		run = func(ctx context.Context) error {
			if ctx == nil {
				t.Fatal("no context")
			}
			seen = slices.Clone(os.Args)
			return c.err
		}
		if code := Main([]string{"sbom", "--format", "json", "x"}); code != c.code {
			t.Errorf("%v: code %d, want %d", c.err, code, c.code)
		}
		if !slices.Equal(seen, []string{"trivy", "sbom", "--format", "json", "x"}) {
			t.Errorf("args seen by trivy: %v", seen)
		}
		if (c.fatal == "") != (len(fatals) == 0) || c.fatal != "" && fatals[0] != c.fatal {
			t.Errorf("%v: fatal %v, want %q", c.err, fatals, c.fatal)
		}
	}
}

// TestRealVersion: the linked trivy answers --version (no network, no DB needed).
func TestRealVersion(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	if code := Main([]string{"--version", "--format", "json", "--cache-dir", t.TempDir()}); code != 0 {
		t.Fatal(code)
	}
}
