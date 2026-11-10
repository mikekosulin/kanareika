package ospkg

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/sbom"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// splitEnv: the rpm host matched in parts (bash; the kernel build alone), with trivy answering each run.
func splitEnv(t *testing.T, run func(n int, bom string) (io.ReadCloser, error)) *check.Ctx {
	t.Helper()
	ctx, _ := env(t, rpmSSH(), `{}`)
	oldRun, oldSize := trivyRun, partSize
	t.Cleanup(func() { trivyRun, partSize = oldRun, oldSize })
	partSize = 1
	n := 0
	trivyRun = func(_ context.Context, args []string, _ string, _ time.Duration) (io.ReadCloser, error) {
		n++
		return run(n, args[len(args)-1])
	}
	return ctx
}

var splitFacts = check.Facts{OSRelease: centos, Uname: "Linux 5.14.0-500.el9.x86_64 x86_64"}

// A part's BOM that can't be built, marshalled or written fails the module; the host's whole BOM is in place.
func TestPartBOMErrors(t *testing.T) {
	h := config.Host{Name: "web-01"}
	t.Run("build", func(t *testing.T) {
		ctx := splitEnv(t, func(int, string) (io.ReadCloser, error) { return trivy.Bytes([]byte(`{}`)), nil })
		old := buildBOM
		t.Cleanup(func() { buildBOM = old })
		calls := 0
		buildBOM = func(name string, osr map[string]string, pkgs []sbom.Package) (*sbom.BOM, error) {
			if calls++; calls > 1 { // the first builds the whole host's sbom.cdx.json
				return nil, errors.New("part bom failed")
			}
			return old(name, osr, pkgs)
		}
		out := t.TempDir()
		if _, err := Run(ctx, h, nil, out, splitFacts); err == nil || err.Error() != "part bom failed" {
			t.Errorf("err %v", err)
		}
		if _, err := os.Stat(filepath.Join(out, "sbom.cdx.json")); err != nil {
			t.Errorf("whole bom: %v", err)
		}
	})
	t.Run("marshal", func(t *testing.T) {
		ctx := splitEnv(t, func(int, string) (io.ReadCloser, error) { return trivy.Bytes([]byte(`{}`)), nil })
		old := marshalBOM
		t.Cleanup(func() { marshalBOM = old })
		calls := 0
		marshalBOM = func(v any, indent bool) ([]byte, error) {
			if calls++; calls > 1 {
				return nil, errors.New("part marshal failed")
			}
			return old(v, indent)
		}
		out := t.TempDir()
		if _, err := Run(ctx, h, nil, out, splitFacts); err == nil || err.Error() != "part marshal failed" {
			t.Errorf("err %v", err)
		}
		if _, err := os.Stat(filepath.Join(out, "sbom-01.cdx.json")); !os.IsNotExist(err) {
			t.Errorf("part bom written: %v", err)
		}
	})
	t.Run("write", func(t *testing.T) {
		ran := false
		ctx := splitEnv(t, func(int, string) (io.ReadCloser, error) { ran = true; return trivy.Bytes([]byte(`{}`)), nil })
		out := t.TempDir()
		if err := os.Mkdir(filepath.Join(out, "sbom-01.cdx.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Run(ctx, h, nil, out, splitFacts); err == nil || !strings.Contains(err.Error(), "sbom-01.cdx.json") {
			t.Errorf("err %v", err)
		}
		if ran {
			t.Error("trivy ran without its BOM")
		}
	})
}

// A later part's trivy run that fails ends the module with its error, after the first part was read; each part's
// BOM is removed after its run.
func TestLaterPartTrivyFails(t *testing.T) {
	var boms []string
	ctx := splitEnv(t, func(n int, bom string) (io.ReadCloser, error) {
		boms = append(boms, filepath.Base(bom))
		if n > 1 {
			return nil, &trivy.Error{Msg: "trivy sbom: db locked"}
		}
		return trivy.Bytes([]byte(`{"Results":[]}`)), nil
	})
	out := t.TempDir()
	fs, err := Run(ctx, config.Host{Name: "web-01"}, nil, out, splitFacts)
	if err == nil || err.Error() != "trivy sbom: db locked" || fs != nil {
		t.Fatalf("got %+v, %v", fs, err)
	}
	if !slices.Equal(boms, []string{"sbom-01.cdx.json", "sbom-02.cdx.json"}) {
		t.Errorf("runs on %q", boms)
	}
	for _, b := range boms {
		if _, err := os.Stat(filepath.Join(out, b)); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", b, err)
		}
	}
}
