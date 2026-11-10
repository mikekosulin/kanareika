package docker

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/check/checktest"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/priv"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// answer: a scripted reply to commands containing a marker.
type answer struct {
	out string
	err error
}

// fakeSSH answers Run by the first marker the command contains (in a fixed order) and Stream with stream.
type fakeSSH struct {
	mu      sync.Mutex
	order   []string
	answers map[string]answer
	stream  func(command string, w io.Writer, progress func(int64)) (int64, error)
	runs    []string
}

func (f *fakeSSH) Run(_ context.Context, _ config.Host, command string, _ time.Duration, _ bool) (string, error) {
	f.mu.Lock()
	f.runs = append(f.runs, command)
	f.mu.Unlock()
	for _, m := range f.order {
		if strings.Contains(command, m) {
			a := f.answers[m]
			return a.out, a.err
		}
	}
	return "", errors.New("unexpected command: " + command)
}

func (f *fakeSSH) Stream(_ context.Context, _ config.Host, command string, w io.Writer, _ int64, _ time.Duration,
	progress func(int64)) (int64, error) {
	if f.stream == nil {
		return 0, errors.New("no stream")
	}
	return f.stream(command, w, progress)
}

var (
	idA = "sha256:" + strings.Repeat("a", 64)
	idB = "sha256:" + strings.Repeat("b", 64)
	idC = "sha256:" + strings.Repeat("c", 64)
)

// host answers: docker installed, a version with a server, one container, three running images: A only tagged,
// B only by digest, C with neither.
func healthy() *fakeSSH {
	return &fakeSSH{
		order: []string{"command -v docker", "docker version", "docker ps -a", "docker ps -q", "docker image ls"},
		answers: map[string]answer{
			"command -v docker": {out: "/usr/bin/docker\n"},
			"docker version":    {out: `{"Server": {"Version": "27.0.1"}}`},
			"docker ps -a":      {out: `{"ID": "c1", "Image": "app:1"}` + "\n"},
			"docker ps -q": {out: idA + " " + strings.Repeat("1", 64) + "\n" + idB + " " + strings.Repeat("2", 64) +
				"\n" + idC + " " + strings.Repeat("3", 64) + "\n"},
			"docker image ls": {out: `[{"Id": "` + idA + `", "RepoTags": ["app:1"], "RepoDigests": [], "Size": 1048576},
 {"Id": "` + idB + `", "RepoTags": [], "RepoDigests": ["registry.example.com/team/b@sha256:` + strings.Repeat("d", 64) + `"]},
 {"Id": "` + idC + `"}]`},
		},
	}
}

func newCtx(ssh check.Runner) (*check.Ctx, *[]string) {
	var mu sync.Mutex
	logs := &[]string{}
	return &check.Ctx{Context: context.Background(), SSH: ssh, Log: func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		*logs = append(*logs, fmt.Sprintf(format, args...))
	}}, logs
}

func host() config.Host {
	return checktest.HostOf(map[string]any{"name": "web-01"})
}

// withoutOp hides a privileged op for one test (priv.Cmd then fails as for an unknown op).
func withoutOp(t *testing.T, op string) {
	t.Helper()
	old := priv.Ops
	m := maps.Clone(old)
	delete(m, op)
	priv.Ops = m
	t.Cleanup(func() { priv.Ops = old })
}

func withTrivy(t *testing.T, f TrivyFunc) {
	t.Helper()
	old := trivyRun
	trivyRun = f
	t.Cleanup(func() { trivyRun = old })
}

// TrivyFunc mirrors trivyRun's type.
type TrivyFunc = func(ctx context.Context, args []string, output string, timeout time.Duration) (io.ReadCloser, error)

func TestMode(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
	}{{nil, ""}, {false, ""}, {true, "true"}, {"packages", "packages"}, {1, "1"}} {
		cfg := map[string]any{}
		if c.v != nil {
			cfg["scan_images"] = c.v
		}
		if got := Mode(cfg); got != c.want {
			t.Errorf("Mode(%#v) = %q, want %q", c.v, got, c.want)
		}
	}
}

// Every inventory step that fails ends the module with an error and writes nothing.
func TestRunInventoryErrors(t *testing.T) {
	boom := errors.New("boom")
	for _, c := range []struct {
		name   string
		marker string
		ans    answer
		op     string // privileged op to hide
		want   string
	}{
		{"which", "command -v docker", answer{err: boom}, "", "boom"},
		{"version-not-object", "docker version", answer{out: "[]"}, "", "Docker not checked: it needs root or membership in the docker group; audit is not root and kanareika does not use sudo on this host (privilege: none) (docker version: not a JSON object)"},
		{"version-op", "", answer{}, "docker-version", `Docker not checked: it needs root or membership in the docker group; audit is not root and kanareika does not use sudo on this host (privilege: none) (unknown privileged op "docker-version")`},
		{"ps-json", "docker ps -a", answer{out: "{broken\n"}, "", ""},
		{"running", "docker ps -q", answer{err: boom}, "", "boom"},
		{"images", "docker image ls", answer{err: boom}, "", "boom"},
		{"images-json", "docker image ls", answer{out: "[broken"}, "", ""},
		{"images-not-list", "docker image ls", answer{out: "{}"}, "", "docker image inspect: not a JSON list"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ssh := healthy()
			if c.marker != "" {
				ssh.answers[c.marker] = c.ans
			}
			if c.op != "" {
				withoutOp(t, c.op)
			}
			ctx, _ := newCtx(ssh)
			out := t.TempDir()
			f, err := Run(ctx, host(), map[string]any{}, out, check.Facts{})
			if err == nil || f != nil || (c.want != "" && err.Error() != c.want) {
				t.Fatalf("got %v, %v; want error %q", f, err, c.want)
			}
			if _, err := os.Stat(filepath.Join(out, "docker.json")); err == nil {
				t.Error("docker.json written")
			}
		})
	}
	t.Run("write", func(t *testing.T) {
		ctx, _ := newCtx(healthy())
		_, err := Run(ctx, host(), map[string]any{}, filepath.Join(t.TempDir(), "missing"), check.Facts{})
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("err %v, want not exist", err)
		}
	})
}

// registry mode: an image known only by tag is pulled by the tag, one by digest is named by its repository in the
// failure finding, one with neither can't be pulled and is left out.
func TestRunRegistry(t *testing.T) {
	var mu sync.Mutex
	var pulled []string
	withTrivy(t, func(_ context.Context, args []string, _ string, _ time.Duration) (io.ReadCloser, error) {
		mu.Lock()
		pulled = append(pulled, args[len(args)-1])
		mu.Unlock()
		if args[len(args)-1] == "app:1" {
			return trivy.Bytes([]byte(`{"Results": []}`)), nil
		}
		return nil, &trivy.Error{Msg: "trivy image: unauthorized"}
	})
	ctx, _ := newCtx(healthy())
	out := t.TempDir()
	fs, err := Run(ctx, host(), map[string]any{"scan_images": "registry"}, out, check.Facts{})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(pulled)
	if want := []string{"app:1", "registry.example.com/team/b@sha256:" + strings.Repeat("d", 64)}; !slices.Equal(pulled, want) {
		t.Errorf("pulled %q, want %q", pulled, want)
	}
	if len(fs) != 2 || fs[0].ID != "docker-engine" || fs[0].Installed != "27.0.1" {
		t.Fatalf("findings %+v", fs)
	}
	if f := fs[1]; f.ID != "image-scan-failed" || f.Target != "trivy image: unauthorized" || f.Args["name"] != "b" {
		t.Errorf("failure finding %+v", f)
	}
	b, _ := os.ReadFile(filepath.Join(out, "docker.json"))
	if !bytes.Contains(b, []byte(`"container": "`+strings.Repeat("3", 64)+`"`)) {
		t.Errorf("docker.json: %s", b)
	}
}

// A report trivy wrote but that isn't JSON fails the image.
func TestRunBrokenReport(t *testing.T) {
	withTrivy(t, func(context.Context, []string, string, time.Duration) (io.ReadCloser, error) {
		return trivy.Bytes([]byte("<html>")), nil
	})
	ctx, _ := newCtx(healthy())
	fs, err := Run(ctx, host(), map[string]any{"scan_images": "registry"}, t.TempDir(), check.Facts{})
	if err != nil || len(fs) != 3 || !strings.Contains(fs[1].Target, "invalid character") || !strings.HasPrefix(fs[1].Target, "trivy report: ") {
		t.Errorf("got %+v, %v", fs, err)
	}
}

// save mode: the stream reports progress; a failing stream or `docker save` op fails the image, not the host.
func TestRunSaveFailures(t *testing.T) {
	withTrivy(t, func(context.Context, []string, string, time.Duration) (io.ReadCloser, error) {
		t.Error("trivy ran")
		return nil, nil
	})
	t.Run("stream", func(t *testing.T) {
		ssh := healthy()
		ssh.stream = func(command string, w io.Writer, progress func(int64)) (int64, error) {
			progress(7)
			return 0, errors.New("connection reset")
		}
		ctx, logs := newCtx(ssh)
		fs, err := Run(ctx, host(), map[string]any{"scan_images": "save", "image_parallel": 1}, t.TempDir(), check.Facts{})
		if err != nil {
			t.Fatal(err)
		}
		failed := 0
		for _, f := range fs {
			if f.ID == "image-scan-failed" && f.Target == "connection reset" {
				failed++
			}
		}
		if failed != 3 {
			t.Errorf("%d failed images, want 3: %+v", failed, fs)
		}
		if !slices.Contains(*logs, "web-01: docker: app:1: 7 MB received") {
			t.Errorf("no progress in logs %q", *logs)
		}
	})
	t.Run("gzip", func(t *testing.T) {
		ssh := healthy()
		ssh.stream = func(_ string, w io.Writer, _ func(int64)) (int64, error) {
			n, err := w.Write([]byte{0x1f, 0x8b, 0})
			return int64(n), err
		}
		ctx, _ := newCtx(ssh)
		dir := t.TempDir()
		fs, err := Run(ctx, host(), map[string]any{"scan_images": "save"}, dir, check.Facts{})
		if err != nil || len(fs) != 4 || fs[1].ID != "image-scan-failed" || fs[1].Target != "unexpected EOF" {
			t.Errorf("got %+v, %v", fs, err)
		}
		if left, _ := os.ReadDir(filepath.Join(dir, "images")); len(left) != 0 {
			t.Errorf("left behind: %v", left)
		}
	})
	t.Run("op", func(t *testing.T) {
		withoutOp(t, "docker-save")
		ctx, _ := newCtx(healthy())
		fs, err := Run(ctx, host(), map[string]any{"scan_images": "save"}, t.TempDir(), check.Facts{})
		if err != nil || len(fs) != 4 || fs[3].Target != `unknown privileged op "docker-save"` {
			t.Errorf("got %+v, %v", fs, err)
		}
	})
}

// A host waiting for another host's scan of the same image gives up when the run is cancelled.
func TestRunCancelledWhileWaiting(t *testing.T) {
	ssh := healthy()
	ctx, logs := newCtx(ssh)
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx.Context = cctx
	ctx.Cache.Store(CacheKey(idA), &scan{done: make(chan struct{}), host: "web-02"})
	fs, err := Run(ctx, host(), map[string]any{"scan_images": "registry", "images": "all"}, t.TempDir(), check.Facts{})
	if !errors.Is(err, context.Canceled) || fs != nil {
		t.Errorf("got %v, %v", fs, err)
	}
	if !slices.Contains(*logs, "web-01: docker: waiting for app:1 (scanned by web-02)") {
		t.Errorf("logs %q", *logs)
	}
}

func TestRunImagesDirError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits: Unix, not root")
	}
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "docker.json"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(out, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(out, 0o755) })
	ctx, _ := newCtx(healthy())
	fs, err := Run(ctx, host(), map[string]any{"scan_images": "registry"}, out, check.Facts{})
	if !errors.Is(err, os.ErrPermission) || fs != nil {
		t.Errorf("got %v, %v", fs, err)
	}
}

func TestScanPackageDBsErrors(t *testing.T) {
	img := &image{id: idA, container: strings.Repeat("1", 64), label: "app:1"}
	noReport := func([]string) ([]finding.Finding, error) { t.Error("report called"); return nil, nil } //nolint:unparam // trivyReport's signature
	t.Run("op", func(t *testing.T) {
		withoutOp(t, "docker-cp")
		ctx, _ := newCtx(healthy())
		if _, err := scanPackageDBs(ctx, host(), img, t.TempDir(), noReport); err == nil ||
			err.Error() != `unknown privileged op "docker-cp"` {
			t.Errorf("err %v", err)
		}
	})
	t.Run("stage", func(t *testing.T) {
		ssh := healthy()
		ssh.stream = func(_ string, w io.Writer, _ func(int64)) (int64, error) {
			n, err := w.Write([]byte("x"))
			return int64(n), err
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, short(idA)+".rootfs"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		ctx, _ := newCtx(ssh)
		if _, err := scanPackageDBs(ctx, host(), img, dir, noReport); err == nil {
			t.Error("no error with the staging dir blocked")
		}
	})
	t.Run("tar", func(t *testing.T) {
		ssh := healthy()
		ssh.stream = func(_ string, w io.Writer, _ func(int64)) (int64, error) {
			n, err := w.Write(bytes.Repeat([]byte("x"), 1024))
			return int64(n), err
		}
		ctx, _ := newCtx(ssh)
		if _, err := scanPackageDBs(ctx, host(), img, t.TempDir(), noReport); err == nil ||
			!strings.HasPrefix(err.Error(), "tar: ") {
			t.Errorf("err %v, want a tar error", err)
		}
	})
}

func gz(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(data)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestGunzipOrRename(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := gunzipOrRename(filepath.Join(dir, "missing"), filepath.Join(dir, "x")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing source: %v", err)
	}
	if err := gunzipOrRename(write("hdr", []byte{0x1f, 0x8b, 0}), filepath.Join(dir, "x")); err == nil {
		t.Error("bad gzip header accepted")
	}
	good := gz(t, []byte("tar data"))
	if err := gunzipOrRename(write("nodst", good), filepath.Join(dir, "no", "x")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unwritable destination: %v", err)
	}
	src := write("trunc", good[:len(good)-6])
	if err := gunzipOrRename(src, filepath.Join(dir, "t")); err == nil {
		t.Error("truncated gzip accepted")
	}
	if _, err := os.Stat(src); err != nil {
		t.Error("source removed after a failure")
	}
	src = write("ok", good)
	if err := gunzipOrRename(src, filepath.Join(dir, "ok.tar")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "ok.tar")); string(b) != "tar data" {
		t.Errorf("got %q", b)
	}
	if _, err := os.Stat(src); !errors.Is(err, os.ErrNotExist) {
		t.Error("source kept")
	}
}

func TestStreamCreateError(t *testing.T) {
	ctx, _ := newCtx(healthy())
	n, err := stream(ctx, host(), "true", filepath.Join(t.TempDir(), "no", "f"), 1, time.Second, nil)
	if n != 0 || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("got %d, %v", n, err)
	}
}
