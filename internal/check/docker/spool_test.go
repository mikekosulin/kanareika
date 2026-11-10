package docker

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// one vulnerability in app:1; the other images fail to pull
func trivyOneVuln(_ context.Context, args []string, _ string, _ time.Duration) (io.ReadCloser, error) {
	if args[len(args)-1] == "app:1" {
		return trivy.Bytes([]byte(`{"Results": [{"Target": "app:1 (debian 12)", "Class": "os-pkgs", "Type": "debian",
 "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0001", "PkgName": "libc6", "InstalledVersion": "2.36-9",
 "FixedVersion": "2.36-10", "Severity": "HIGH"}]}]}`)), nil
	}
	return nil, &trivy.Error{Msg: "trivy image: unauthorized"}
}

// With a spool, an image's findings go to Spool/docker/<id>.findings.json.gz and reach the host's sink from there,
// each stamped with the host and whether a running container uses the image.
func TestRunSpoolToSink(t *testing.T) {
	withTrivy(t, trivyOneVuln)
	ctx, logs := newCtx(healthy())
	ctx.Spool = t.TempDir()
	var mu sync.Mutex
	var sunk []finding.Finding
	ctx.Sinks = map[string]func(f *finding.Finding){"web-01": func(f *finding.Finding) {
		mu.Lock()
		defer mu.Unlock()
		sunk = append(sunk, *f)
	}}
	fs, err := Run(ctx, host(), map[string]any{"scan_images": "registry"}, t.TempDir(), check.Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ctx.Spool, "docker", short(idA)+".findings.json.gz")); err != nil {
		t.Errorf("spool file: %v", err)
	}
	// returned: the engine inventory and the failed image; the vulnerability went to the sink
	if len(fs) != 2 || fs[0].ID != "docker-engine" || fs[1].ID != "image-scan-failed" {
		t.Fatalf("returned %+v", fs)
	}
	if len(sunk) != 1 {
		t.Fatalf("sunk %+v", sunk)
	}
	f := sunk[0]
	if f.ID != "CVE-2024-0001" || f.Pkg != "libc6" || f.Host != "web-01" || f.Module != "docker" ||
		f.ImageInUse == nil || !*f.ImageInUse {
		t.Errorf("sunk finding %+v", f)
	}
	if !slices.ContainsFunc(*logs, func(l string) bool { return strings.Contains(l, "app:1: 1 vulns (") }) {
		t.Errorf("logs %q", *logs)
	}
}

// A spool that can't take the file fails that image, not the host.
func TestRunSpoolWriteFails(t *testing.T) {
	withTrivy(t, trivyOneVuln)
	ctx, logs := newCtx(healthy())
	ctx.Spool = filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(ctx.Spool, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := Run(ctx, host(), map[string]any{"scan_images": "registry"}, t.TempDir(), check.Facts{})
	if err != nil {
		t.Fatal(err)
	}
	var failed []string
	for _, f := range fs {
		if f.ID == "image-scan-failed" {
			failed = append(failed, f.Args["name"].(string)+": "+f.Target)
		}
		if f.Kind == finding.Vuln {
			t.Errorf("vulnerability returned: %+v", f)
		}
	}
	slices.Sort(failed)
	if len(failed) != 2 || !strings.HasPrefix(failed[0], "app:1: ") || !strings.Contains(failed[0], "not a directory") ||
		failed[1] != "b: trivy image: unauthorized" {
		t.Errorf("failed %q", failed)
	}
	if !slices.ContainsFunc(*logs, func(l string) bool {
		return strings.HasPrefix(l, "web-01: docker: [") && strings.Contains(l, "app:1: FAILED") && strings.Contains(l, "not a directory")
	}) {
		t.Errorf("logs %q", *logs)
	}
}

// An image another host spooled whose file is gone by the time this host reads it ends the module with that error.
func TestRunSpoolReadFails(t *testing.T) {
	withTrivy(t, trivyOneVuln)
	ctx, _ := newCtx(healthy())
	ctx.Spool = t.TempDir()
	s := &scan{done: make(chan struct{}), host: "web-02", path: filepath.Join(ctx.Spool, "docker", "gone.findings.json.gz")}
	close(s.done)
	ctx.Cache.Store(CacheKey(idA), s)
	got, err := Run(ctx, host(), map[string]any{"scan_images": "registry"}, t.TempDir(), check.Facts{})
	if !errors.Is(err, fs.ErrNotExist) || got != nil {
		t.Errorf("got %+v, %v", got, err)
	}
}
