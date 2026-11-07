package softwarefs

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
)

// member of a test archive; Typeflag 0 = regular file.
type member struct {
	name     string
	typ      byte
	link     string
	body     string
	paxGlobl map[string]string
}

func tarOf(t *testing.T, ms ...member) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, m := range ms {
		h := &tar.Header{Name: m.name, Typeflag: m.typ, Linkname: m.link, Mode: 0o644, PAXRecords: m.paxGlobl}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(m.body))
		}
		if h.Typeflag == tar.TypeDir {
			h.Mode = 0o755
		}
		if h.Typeflag == tar.TypeXGlobalHeader { // archive/tar takes nothing but the records here
			h = &tar.Header{Typeflag: h.Typeflag, PAXRecords: h.PAXRecords}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(m.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// extract writes data as an archive file and extracts it into a fresh directory.
func extract(t *testing.T, data []byte) (string, error) {
	t.Helper()
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar")
	if err := os.WriteFile(archive, data, 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "dest")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	return dest, Extract(archive, dest)
}

func TestExtractUnreadableArchives(t *testing.T) {
	if err := Extract(filepath.Join(t.TempDir(), "missing.tar"), t.TempDir()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing archive: %v", err)
	}
	if _, err := extract(t, []byte{0x1f, 0x8b}); err == nil {
		t.Error("truncated gzip header: no error")
	}
	if _, err := extract(t, bytes.Repeat([]byte("x"), 1024)); err == nil || !strings.HasPrefix(err.Error(), "tar: ") {
		t.Errorf("garbage tar: %v", err)
	}
}

func TestPyRepr(t *testing.T) {
	for in, want := range map[string]string{`it's`: `"it's"`, `a'b"c`: `'a\'b"c'`, `a\b`: `'a\\b'`, `x`: `'x'`} {
		if got := pyRepr(in); got != want {
			t.Errorf("pyRepr(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestExtractOutsideQuoted(t *testing.T) {
	dest, err := extract(t, tarOf(t, member{name: "../it's"}))
	want := `"../it's" would be extracted to "` + filepath.Join(filepath.Dir(mustReal(t, dest)), "it's") +
		`", which is outside the destination`
	if err == nil || err.Error() != want {
		t.Errorf("err = %v\nwant %s", err, want)
	}
}

func mustReal(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Meta headers are skipped; links replace what is already there; hard links share the file.
func TestExtractLinksAndMeta(t *testing.T) {
	dest, err := extract(t, tarOf(t,
		member{name: "global", typ: tar.TypeXGlobalHeader, paxGlobl: map[string]string{"comment": "x"}},
		member{name: "a", body: "old"},
		member{name: "a", typ: tar.TypeSymlink, link: "b"},
		member{name: "b", body: "data"},
		member{name: "h", body: "stale"},
		member{name: "h", typ: tar.TypeLink, link: "b"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if l, err := os.Readlink(filepath.Join(dest, "a")); err != nil || l != "b" {
		t.Errorf("a -> %q (%v)", l, err)
	}
	if got := read(t, filepath.Join(dest, "h")); got != "data" {
		t.Errorf("h = %q", got)
	}
	bi, _ := os.Stat(filepath.Join(dest, "b"))
	hi, _ := os.Stat(filepath.Join(dest, "h"))
	if !os.SameFile(bi, hi) {
		t.Error("h is not a hard link of b")
	}
	if _, err := os.Lstat(filepath.Join(dest, "global")); !os.IsNotExist(err) {
		t.Errorf("meta header extracted: %v", err)
	}
}

func TestExtractFailures(t *testing.T) {
	for name, c := range map[string]struct {
		ms   []member
		want error
	}{
		"parent is a file":     {[]member{{name: "f"}, {name: "f/x"}}, syscall.ENOTDIR},
		"dir over a file":      {[]member{{name: "f"}, {name: "f/", typ: tar.TypeDir}}, syscall.ENOTDIR},
		"file over a dir":      {[]member{{name: "d/", typ: tar.TypeDir}, {name: "d"}}, syscall.EISDIR},
		"hard link to nothing": {[]member{{name: "h", typ: tar.TypeLink, link: "nope"}}, fs.ErrNotExist},
		"hard link to a dir":   {[]member{{name: "d/", typ: tar.TypeDir}, {name: "h", typ: tar.TypeLink, link: "d"}}, syscall.EISDIR},
	} {
		t.Run(name, func(t *testing.T) {
			if errors.Is(c.want, syscall.EISDIR) && runtime.GOOS == "windows" {
				t.Skip("EISDIR is Unix's")
			}
			if _, err := extract(t, tarOf(t, c.ms...)); !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// swap sets *p to v for the test.
func swap[T any](t *testing.T, p *T, v T) {
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

var errAbs = errors.New("getwd: no such file or directory")

// A path that cannot be made absolute (lost working directory) fails the extraction wherever it comes up.
func TestExtractAbsFailures(t *testing.T) {
	failOn := func(suffix string) func(string) (string, error) {
		return func(p string) (string, error) {
			if strings.HasSuffix(p, suffix) {
				return "", errAbs
			}
			return filepath.Abs(p)
		}
	}
	for name, c := range map[string]struct {
		suffix string
		ms     []member
	}{
		"destination": {"dest", []member{{name: "x"}}},
		"member":      {"boom", []member{{name: "boom"}}},
		"link target": {"boom", []member{{name: "boom2"}, {name: "h", typ: tar.TypeLink, link: "boom"}}},
	} {
		t.Run(name, func(t *testing.T) {
			swap(t, &absPath, failOn(c.suffix))
			if _, err := extract(t, tarOf(t, c.ms...)); !errors.Is(err, errAbs) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

// Nothing resolves (not even the root): the path comes back as it is.
func TestRealpathNothingResolves(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("remote paths are Unix paths; filepath here is the local one")
	}
	swap(t, &evalSymlinks, func(string) (string, error) { return "", fs.ErrNotExist })
	if p, err := realpath("/srv/app/../lib"); err != nil || p != "/srv/lib" {
		t.Errorf("realpath = %q, %v", p, err)
	}
}

func TestStringsAndInt(t *testing.T) {
	if got := Strings([]string{"/opt", "/srv"}); !reflect.DeepEqual(got, []string{"/opt", "/srv"}) {
		t.Errorf("Strings = %q", got)
	}
	if got := Strings("not a list"); got != nil {
		t.Errorf("Strings(string) = %q", got)
	}
	if got := Int(map[string]any{"n": int64(7)}, "n", 1); got != 7 {
		t.Errorf("Int(int64) = %d", got)
	}
}

// streamer streams data for any command.
type streamer struct{ data []byte }

func (s streamer) Run(context.Context, config.Host, string, time.Duration, bool) (string, error) {
	return "", errors.New("not used")
}

func (s streamer) Stream(_ context.Context, _ config.Host, _ string, w io.Writer, _ int64, _ time.Duration, _ func(int64)) (int64, error) {
	n, err := w.Write(s.data)
	return int64(n), err
}

var cfg = map[string]any{"paths": []any{"/opt"}, "patterns": []any{"*.jar"}}

func runWith(t *testing.T, out, report string) error {
	t.Helper()
	swap(t, &trivyRun, func(context.Context, []string, string, time.Duration) ([]byte, error) { return []byte(report), nil })
	ctx := &check.Ctx{Context: context.Background(), SSH: streamer{tarOf(t, member{name: "opt/app/lib.jar", body: "jar"})},
		Log: func(string, ...any) {}}
	_, err := Run(ctx, config.Host{Name: "web-01"}, cfg, out, check.Facts{})
	return err
}

// Every failing step fails the module, and the archive and staging dir are removed either way.
func TestRunFailures(t *testing.T) {
	for name, c := range map[string]struct {
		prepare func(t *testing.T, out string)
		report  string
		want    string
	}{
		"archive not created": {func(t *testing.T, out string) { mkdir(t, filepath.Join(out, "software_fs.tar")) }, `{}`,
			"software_fs.tar"},
		"stage not created": {func(t *testing.T, out string) { write(t, filepath.Join(out, "software_fs")) }, `{}`,
			"software_fs"},
		"files list not written": {func(t *testing.T, out string) { mkdir(t, filepath.Join(out, "software_fs.files.txt")) },
			`{}`, "software_fs.files.txt"},
		"bad report": {func(*testing.T, string) {}, `not json`, "trivy report: "},
		"files not read": {func(t *testing.T, _ string) {
			swap(t, &listFiles, func(string) ([]string, error) { return nil, errors.New("walk failed") })
		}, `{}`, "walk failed"},
	} {
		t.Run(name, func(t *testing.T) {
			out := t.TempDir()
			c.prepare(t, out)
			if err := runWith(t, out, c.report); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
			for _, p := range []string{"software_fs.tar", "software_fs"} {
				if _, err := os.Lstat(filepath.Join(out, p)); !os.IsNotExist(err) {
					t.Errorf("%s left behind: %v", p, err)
				}
			}
		})
	}
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestAbsLink: links to absolute paths are refused whatever OS unpacks: the host's /etc/passwd (which Windows'
// filepath takes for relative), and Windows' own forms.
func TestAbsLink(t *testing.T) {
	win := runtime.GOOS == "windows" // a drive letter is only a drive there (a:b is a fine name on Linux)
	for l, want := range map[string]bool{"/etc/passwd": true, `\Windows\x`: true, `C:\x`: win, "c:/x": win, "a:b": win,
		"lib/x.jar": false, "../x": false, "x": false, "": false} {
		if absLink(l) != want {
			t.Errorf("absLink(%q) = %v", l, !want)
		}
	}
}
