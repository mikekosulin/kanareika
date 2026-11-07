package dbbundle

import (
	"archive/tar"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func setSeam[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// noBundle: Export failed and left neither the bundle nor its temp file behind.
func noBundle(t *testing.T, out string) {
	t.Helper()
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("partial bundle left")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(out), ".kanareika-db-*")); len(left) != 0 {
		t.Fatal("temp file left:", left)
	}
}

// A file that yields fewer bytes than its header promised breaks the tar stream: at the next header, or at the
// end of the archive when it was the last file.
func TestExportShortFile(t *testing.T) {
	setSeam(t, &copyFile, func(io.Writer, io.Reader) (int64, error) { return 0, nil })
	for name, files := range map[string][]string{"next header": {"a", "b"}, "last file": {"a"}} {
		src := t.TempDir()
		for _, f := range files {
			write(t, filepath.Join(src, "db", f), "data")
		}
		out := filepath.Join(t.TempDir(), "b.tgz")
		if _, err := Export(out, []Part{{"trivy-db", filepath.Join(src, "db")}}); err == nil ||
			!strings.Contains(err.Error(), "missed writing") {
			t.Errorf("%s: %v", name, err)
		}
		noBundle(t, out)
	}
}

type failAfter struct{ ok int }

func (w *failAfter) Write(p []byte) (int, error) {
	if w.ok == 0 {
		return 0, errors.New("disk full")
	}
	w.ok--
	return len(p), nil
}

func TestExportWriteErrors(t *testing.T) {
	src := t.TempDir()
	write(t, filepath.Join(src, "db", "x"), "data")
	parts := []Part{{"trivy-db", filepath.Join(src, "db")}}

	// the gzip header goes through, the compressed data (written on close) does not
	setSeam(t, &exportTo, func(*os.File) io.Writer { return &failAfter{ok: 1} })
	out := filepath.Join(t.TempDir(), "b.tgz")
	if _, err := Export(out, parts); err == nil || err.Error() != "disk full" {
		t.Errorf("gzip close: %v", err)
	}
	noBundle(t, out)

	// the temp file fails on close
	exportTo = func(f *os.File) io.Writer { f.Close(); return io.Discard }
	out = filepath.Join(t.TempDir(), "b.tgz")
	if _, err := Export(out, parts); !errors.Is(err, os.ErrClosed) {
		t.Errorf("temp close: %v", err)
	}
	noBundle(t, out)
}

// A directory that can be listed but not searched: its entries are named, their info cannot be read.
func TestExportUnstatableEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits: Unix")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores permissions")
	}
	src := t.TempDir()
	inner := filepath.Join(src, "db", "inner")
	write(t, filepath.Join(inner, "x"), "x")
	must(t, os.Chmod(inner, 0o444))
	t.Cleanup(func() { _ = os.Chmod(inner, 0o755) })
	out := filepath.Join(t.TempDir(), "b.tgz")
	if _, err := Export(out, []Part{{"trivy-db", filepath.Join(src, "db")}}); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("err = %v", err)
	}
	noBundle(t, out)
}

// An entry that needs a directory where the bundle already put a file.
func TestImportFileInTheWay(t *testing.T) {
	for name, second := range map[string]entry{
		"dir":  {name: "trivy-db/a/b/", typ: tar.TypeDir},
		"file": {name: "trivy-db/a/b", body: "y", typ: tar.TypeReg},
	} {
		dst := t.TempDir()
		b := bundle(t, entry{name: "trivy-db/a", body: "x", typ: tar.TypeReg}, second)
		if _, err := Import(b, []Part{{"trivy-db", filepath.Join(dst, "db")}}); err == nil ||
			!strings.Contains(err.Error(), "not a directory") {
			t.Errorf("%s: %v", name, err)
		}
		if left, _ := filepath.Glob(filepath.Join(dst, "*")); len(left) != 0 {
			t.Errorf("%s: left behind: %v", name, left)
		}
		if left, _ := filepath.Glob(filepath.Join(dst, ".*")); len(left) != 0 {
			t.Errorf("%s: staging left: %v", name, left)
		}
	}
}

// When a directory cannot be swapped in, the one in place stays as it was.
func TestImportSwapFails(t *testing.T) {
	b := bundle(t, entry{name: "trivy-db/x", body: "new", typ: tar.TypeReg})
	for _, failAt := range []int{1, 2} {
		dst := t.TempDir()
		db := filepath.Join(dst, "db")
		write(t, filepath.Join(db, "x"), "old")
		calls := 0
		setSeam(t, &rename, func(from, to string) error {
			calls++
			if calls == failAt {
				return &os.LinkError{Op: "rename", Old: from, New: to, Err: errors.New("device busy")}
			}
			return os.Rename(from, to)
		})
		done, err := Import(b, []Part{{"trivy-db", db}})
		if err == nil || !strings.Contains(err.Error(), "device busy") || len(done) != 0 {
			t.Errorf("rename %d: %v %v", failAt, done, err)
		}
		if got := read(t, filepath.Join(db, "x")); got != "old" {
			t.Errorf("rename %d: db/x = %q", failAt, got)
		}
		if left, _ := filepath.Glob(filepath.Join(dst, ".*")); len(left) != 0 {
			t.Errorf("rename %d: staging left: %v", failAt, left)
		}
	}
}
