package ospkg

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/check/checktest"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/sbom"
)

// testdata/python.json: the Python module's results over raw outputs recorded on real hosts (stream9
// CentOS Stream 9, centos6 CentOS 6 — EOL, ubuntu24 Ubuntu 24.04: packages.txt, changelog-cves.txt, upgrades.txt
// as the scans wrote them; trivy-os.json.gz trimmed to a few hundred vulnerabilities incl. every kernel build, only
// the fields kanareika reads) plus synthetic variants (booted an older kernel, failing queries, unsupported OS),
// and its helper results under "units".
// Frozen fixture: recorded with the Python reference implementation (no longer in the repo) from the anonymized
// inputs in testdata; the Go module must reproduce it exactly.
func TestMatchesPython(t *testing.T) {
	cases := checktest.LoadReplays(t)
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
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

func TestUnitsMatchPython(t *testing.T) {
	b, err := os.ReadFile("testdata/python.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Units struct {
			IsKernel      map[string]bool   `json:"is_kernel"`
			KernelMatches [][4]any          `json:"kernel_matches"`
			EVR           map[string]string `json:"evr"`
			Newer         [][2]*string      `json:"newer_kernel"`
			NewerSynth    [][2]*string      `json:"newer_kernel_synth"`
			Synth         []sbom.Package    `json:"synth"`
		} `json:"units"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	u := g.Units
	for n, want := range u.IsKernel {
		if IsKernel(n) != want {
			t.Errorf("IsKernel(%q) = %v", n, !want)
		}
	}
	for _, c := range u.KernelMatches {
		if got := KernelMatches(c[0].(string), c[1].(string), c[2].(string)); got != c[3].(bool) {
			t.Errorf("KernelMatches%v = %v", c[:3], got)
		}
	}
	for in, want := range u.EVR {
		if got := EVR(in); got != want {
			t.Errorf("EVR(%q) = %q, want %q", in, got, want)
		}
	}
	data, err := os.ReadFile("testdata/centos9/packages.txt")
	if err != nil {
		t.Fatal(err)
	}
	pk := sbom.ParsePackages("rpm", string(data))
	for name, c := range map[string]struct {
		pkgs  []sbom.Package
		cases [][2]*string
	}{"centos9": {pk, u.Newer}, "synth": {u.Synth, u.NewerSynth}} {
		for _, x := range c.cases {
			want := ""
			if x[1] != nil {
				want = *x[1]
			}
			if got := NewerKernel(c.pkgs, *x[0]); got != want {
				t.Errorf("%s: NewerKernel(%q) = %q, want %q", name, *x[0], got, want)
			}
		}
	}
}

func TestMarkKernelsNoRunning(t *testing.T) {
	fs := []finding.Finding{{Pkg: "kernel-core", Installed: "1-1"}}
	MarkKernels(fs, "", true)
	if !reflect.DeepEqual(fs, []finding.Finding{{Pkg: "kernel-core", Installed: "1-1"}}) {
		t.Error(fs)
	}
}
