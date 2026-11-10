package ospkg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/sbom"
	"github.com/mikekosulin/kanareika/internal/trivy"
	"github.com/mikekosulin/kanareika/internal/vendor"
)

// fakeSSH answers commands from a table (missing = error) and records them.
type fakeSSH struct {
	out   map[string]string
	calls []string
}

func (f *fakeSSH) Run(_ context.Context, _ config.Host, command string, _ time.Duration, _ bool) (string, error) {
	f.calls = append(f.calls, command)
	if s, ok := f.out[command]; ok {
		return s, nil
	}
	return "", fmt.Errorf("no answer for %q", command)
}

func (f *fakeSSH) Stream(context.Context, config.Host, string, io.Writer, int64, time.Duration, func(int64)) (int64, error) {
	return 0, errors.New("not used")
}

// rpmPackages: two packages in the rpm query format (name, epoch, version, release, arch, source rpm).
const rpmPackages = "bash\t(none)\t5.1.8\t9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm\n" +
	"kernel-core\t(none)\t5.14.0\t500.el9\tx86_64\tkernel-5.14.0-500.el9.src.rpm\n"

var centos = map[string]string{"ID": "centos", "VERSION_ID": "9", "PRETTY_NAME": "CentOS Stream 9"}

func env(t *testing.T, ssh *fakeSSH, report string) (*check.Ctx, *[]string) {
	t.Helper()
	old := trivyRun
	trivyRun = func(_ context.Context, _ []string, _ string, _ time.Duration) (io.ReadCloser, error) {
		return trivy.Bytes([]byte(report)), nil
	}
	t.Cleanup(func() { trivyRun = old })
	var logs []string
	return &check.Ctx{Context: context.Background(), SSH: ssh,
		Log: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}, &logs
}

func rpmSSH() *fakeSSH {
	return &fakeSSH{out: map[string]string{
		sbom.PkgQuery["rpm"]:         rpmPackages,
		vendor.ChangelogQuery["rpm"]: "@bash\nCVE-2022-3715\n",
		vendor.UpgradesQuery["rpm"]:  "@@rc 0\n",
		sbom.PkgQuery["apk"]:         "P:musl\nV:1.2.4-r2\nA:x86_64\n\nP:busybox\nV:1.36.1-r5\nA:x86_64\no:busybox\n",
	}}
}

// An EOL report without PRETTY_NAME and without OS family / name: the finding names it "None None" as Python's
// f-string of None did; apk has no changelog and no upgrades query, so neither is run.
func TestEOLWithoutNamesOnAlpine(t *testing.T) {
	ssh := rpmSSH()
	ctx, logs := env(t, ssh, `{"Metadata":{"OS":{"EOSL":true}},"Results":[]}`)
	out := t.TempDir()
	fs, err := Run(ctx, config.Host{Name: "web-01"}, nil, out,
		check.Facts{OSRelease: map[string]string{"ID": "alpine", "VERSION_ID": "3.19.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].ID != "os-eol" || fs[0].Pkg != "None None" || fs[0].Installed != "" || fs[0].Severity != "HIGH" {
		t.Fatalf("findings: %+v", fs)
	}
	if len(ssh.calls) != 1 || ssh.calls[0] != sbom.PkgQuery["apk"] {
		t.Errorf("calls: %q", ssh.calls)
	}
	for _, f := range []string{"changelog-cves.txt", "upgrades.txt"} {
		if _, err := os.Stat(filepath.Join(out, f)); !os.IsNotExist(err) {
			t.Errorf("%s written: %v", f, err)
		}
	}
	if len(*logs) != 2 || !strings.Contains((*logs)[0], "2 packages") {
		t.Errorf("logs: %q", *logs)
	}
}

// Files that cannot be written: packages.txt and sbom.cdx.json fail the module; the changelog and upgrades files
// only cost their refinement (logged, the module goes on).
func TestWriteFailures(t *testing.T) {
	facts := check.Facts{OSRelease: centos, Uname: "Linux 5.14.0-500.el9.x86_64 x86_64"}
	h := config.Host{Name: "web-01"}

	ctx, _ := env(t, rpmSSH(), `{}`)
	if _, err := Run(ctx, h, nil, filepath.Join(t.TempDir(), "missing"), facts); err == nil ||
		!strings.Contains(err.Error(), "packages.txt") {
		t.Errorf("packages.txt: %v", err)
	}

	out := t.TempDir()
	if err := os.Mkdir(filepath.Join(out, "sbom.cdx.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, h, nil, out, facts); err == nil || !strings.Contains(err.Error(), "sbom.cdx.json") {
		t.Errorf("sbom: %v", err)
	}

	out = t.TempDir()
	for _, d := range []string{"changelog-cves.txt", "upgrades.txt"} {
		if err := os.Mkdir(filepath.Join(out, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ctx, logs := env(t, rpmSSH(), `{"Results":[]}`)
	fs, err := Run(ctx, h, nil, out, facts)
	if err != nil || len(fs) != 0 {
		t.Fatalf("%v %+v", err, fs)
	}
	got := strings.Join(*logs, "\n")
	for _, want := range []string{"web-01: os_packages: changelog not read: ", "web-01: os_packages: repositories not queried: "} {
		if !strings.Contains(got, want) {
			t.Errorf("log %q missing in\n%s", want, got)
		}
	}
}

func TestBadTrivyReport(t *testing.T) {
	ctx, _ := env(t, rpmSSH(), `not json`)
	_, err := Run(ctx, config.Host{Name: "web-01"}, nil, t.TempDir(), check.Facts{OSRelease: centos})
	if err == nil || !strings.HasPrefix(err.Error(), "trivy report: ") {
		t.Errorf("err = %v", err)
	}
}

// BOM building and marshalling errors are passed on (seams: the real functions do not fail for a supported OS).
func TestBOMErrors(t *testing.T) {
	ctx, _ := env(t, rpmSSH(), `{}`)
	facts := check.Facts{OSRelease: centos}
	oldB, oldM := buildBOM, marshalBOM
	t.Cleanup(func() { buildBOM, marshalBOM = oldB, oldM })

	buildBOM = func(string, map[string]string, []sbom.Package) (*sbom.BOM, error) {
		return nil, errors.New("bom failed")
	}
	if _, err := Run(ctx, config.Host{Name: "web-01"}, nil, t.TempDir(), facts); err == nil || err.Error() != "bom failed" {
		t.Errorf("build: %v", err)
	}
	buildBOM = oldB
	marshalBOM = func(any, bool) ([]byte, error) { return nil, errors.New("marshal failed") }
	out := t.TempDir()
	if _, err := Run(ctx, config.Host{Name: "web-01"}, nil, out, facts); err == nil || err.Error() != "marshal failed" {
		t.Errorf("marshal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "sbom.cdx.json")); !os.IsNotExist(err) {
		t.Errorf("sbom written: %v", err)
	}
}
