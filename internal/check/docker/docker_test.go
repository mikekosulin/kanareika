package docker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/check/checktest"
	"github.com/mikekosulin/kanareika/internal/finding"
)

// testdata/python.json: the Python module's results over raw outputs recorded read-only on ubuntu24
// (Ubuntu, root: docker version/ps/inspect, `docker cp` of the package DBs of its two running alpine containers,
// the trivy rootfs reports of the scan that used them) and stream9 (CentOS Stream 9, sudo, swarm manager:
// 16 containers whose untagged images `docker image ls` does not list — so nothing to scan); image inspect output
// without Config/RootFS. Cases cover every scan_images mode, images running|all, a shared image cache across two
// hosts (results and failures reused), helper/sudo/none command forms, size limits and failing steps. The synthetic
// `docker save` streams save-*.bin were written alongside.
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

// Two hosts scanning the same images at the same time, each with parallel workers: every image is fetched and
// scanned once, both hosts get all its findings.
func TestSharedCacheConcurrent(t *testing.T) {
	var c *checktest.Replay
	cases := checktest.LoadReplays(t)
	for i := range cases {
		if cases[i].Name == "ubuntu24-packages" {
			c = &cases[i]
		}
	}
	here, _ := filepath.Abs("testdata")
	tmp := t.TempDir()
	n := &checktest.Norm{Roots: [][2]string{{tmp, "$OUT"}}}
	var tcalls []any
	var mu sync.Mutex
	fake := checktest.FakeTrivy(here, c, n, &tcalls)
	old := trivyRun
	trivyRun = func(ctx context.Context, args []string, output string, timeout time.Duration) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		return fake(ctx, args, output, timeout)
	}
	defer func() { trivyRun = old }()
	ctx := &check.Ctx{Context: context.Background(), SSH: &checktest.FakeSSH{Here: here, Case: c}, RunDir: tmp,
		Log: func(string, ...any) {}}
	want := len(c.Results[0].Findings)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := checktest.HostOf(map[string]any{"name": fmt.Sprintf("h%d", i)})
			out := filepath.Join(tmp, h.Name)
			_ = os.MkdirAll(out, 0o755)
			fs, err := Run(ctx, h, map[string]any{"scan_images": "packages", "image_parallel": 2}, out, check.Facts{})
			if err != nil || len(fs) != want {
				t.Errorf("%s: %d findings (%v), want %d", h.Name, len(fs), err, want)
			}
			for _, f := range fs {
				if f.Host != h.Name || (f.Kind == finding.Vuln && (f.ImageInUse == nil || !*f.ImageInUse)) {
					t.Errorf("%s: %+v", h.Name, f)
					break
				}
			}
		}()
	}
	wg.Wait()
	if len(tcalls) != 2 {
		t.Errorf("%d trivy runs, want 2", len(tcalls))
	}
}
