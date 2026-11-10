package k8s

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
	"github.com/mikekosulin/kanareika/internal/trivy"
)

func TestFieldNonString(t *testing.T) {
	r := resource{"Name": []byte(`42`), "Kind": []byte(`"Pod"`), "Namespace": []byte(`null`)}
	if got := r.field("Name", "x"); got != "42" {
		t.Errorf("number: %q", got)
	}
	if got := r.field("Kind", "x"); got != "Pod" {
		t.Errorf("string: %q", got)
	}
	if got := r.field("Namespace", "x"); got != "None" {
		t.Errorf("null: %q", got)
	}
	if got := r.field("Absent", "def"); got != "def" {
		t.Errorf("absent: %q", got)
	}
}

func TestExposureTypes(t *testing.T) {
	for _, c := range []struct {
		v    any
		want int
	}{{1, 1}, {int64(3), 3}, {float64(0), 0}, {"1", 2}, {nil, 2}} {
		if got := exposure(map[string]any{"exposure": c.v}); got != c.want {
			t.Errorf("exposure(%#v) = %d, want %d", c.v, got, c.want)
		}
	}
}

func TestArgsNamespacesAsStrings(t *testing.T) {
	got := Args(map[string]any{"namespaces": []string{"shop", "payments"}}, "/k")
	want := []string{"k8s", "--kubeconfig", "/k", "--scanners", "vuln", "--report", "all", "--disable-node-collector",
		"--include-namespaces", "shop,payments"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRunNoOutputDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := &check.Ctx{Context: context.Background(), RunDir: file, Log: func(string, ...any) {}}
	if f, err := Run(ctx, nil, "production"); err == nil || f != nil {
		t.Errorf("got %v, %v; want an error", f, err)
	}
}

// Failures that are not trivy's own (I/O, broken reports) end the module with an error.
func TestRunFailures(t *testing.T) {
	cluster := []map[string]any{{"name": "prod", "env": "production", "kubeconfig": "acme/kubeconfig-prod"}}
	for _, c := range []struct {
		name string
		data string
		err  error
		want string
	}{
		{"io", "", errors.New("disk full"), "disk full"},
		{"bad-json", "{", nil, "trivy k8s report: unexpected end of JSON input"},
		{"bad-results", `{"Resources":[{"Kind":"Pod","Results":"x"}]}`, nil, "trivy k8s report: json: cannot unmarshal"},
	} {
		t.Run(c.name, func(t *testing.T) {
			org, _ := loadOrg(t, cluster, map[string]string{"acme/kubeconfig-prod": "apiVersion: v1\n"})
			old := trivyRun
			defer func() { trivyRun = old }()
			trivyRun = func(context.Context, []string, string, time.Duration) (io.ReadCloser, error) {
				return trivy.Bytes([]byte(c.data)), c.err
			}
			ctx := &check.Ctx{Context: context.Background(), Org: org, RunDir: t.TempDir(), Log: func(string, ...any) {}}
			f, err := Run(ctx, nil, "production")
			if err == nil || !strings.Contains(err.Error(), c.want) || f != nil {
				t.Errorf("got %v, %v; want error %q", f, err, c.want)
			}
		})
	}
}
