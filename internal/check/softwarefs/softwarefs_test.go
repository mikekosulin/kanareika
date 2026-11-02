package softwarefs

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/check/checktest"
	"github.com/mikekosulin/kanareika/internal/finding"
)

// testdata/python.json: the Python module's results. Inputs: a real archive streamed from centos6 (CentOS 6)
// by the module's own find | tar with the default profile, its recorded trivy report, and synthetic archives
// (links, absolute and escaping names, device files, gzip) with a synthetic trivy report covering relative,
// absolute (staging dir) and PkgPath targets.
// Frozen fixture: recorded with the Python reference implementation (no longer in the repo) from the anonymized
// inputs in testdata; the Go module must reproduce it exactly.
func TestMatchesPython(t *testing.T) {
	cases := checktest.LoadReplays(t)
	set := func(f checktest.TrivyFunc) func() { old := trivyRun; trivyRun = f; return func() { trivyRun = old } }
	for i := range cases {
		c := &cases[i]
		t.Run(c.Name, func(t *testing.T) {
			checktest.RunReplay(t, c, nil, set, func(ctx *check.Ctx, r checktest.ReplayRun, out string) ([]finding.Finding, error) {
				return Run(ctx, checktest.HostOf(r.Host), r.Cfg, out, r.Facts)
			})
		})
	}
}

func TestRemoteCommandMatchesPython(t *testing.T) {
	b, err := os.ReadFile("testdata/python.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Commands [][2]json.RawMessage `json:"commands"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	for _, c := range g.Commands {
		var cfg map[string]any
		var want string
		_ = json.Unmarshal(c[0], &cfg)
		_ = json.Unmarshal(c[1], &want)
		if got := RemoteCommand(cfg); got != want {
			t.Errorf("%v:\n got %s\nwant %s", cfg, got, want)
		}
	}
}

// Port of tests/test_core.py::test_software_fs_command_quotes_paths.
func TestCommandQuotesPaths(t *testing.T) {
	cmd := RemoteCommand(map[string]any{"paths": []any{"/opt/my app"}, "exclude": []any{"/var/lib/docker"},
		"patterns": []any{"*.jar"}, "max_file_mb": 1})
	for _, s := range []string{"'/opt/my app'", "-prune", "'*.jar'", "-size -1024k"} {
		if !strings.Contains(cmd, s) {
			t.Errorf("%q not in %s", s, cmd)
		}
	}
}
