package dbbundle

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, p, s string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(p), 0o755))
	must(t, os.WriteFile(p, []byte(s), 0o644))
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	must(t, err)
	return string(b)
}

func TestRoundTrip(t *testing.T) {
	src := t.TempDir()
	write(t, filepath.Join(src, "db", "trivy.db"), "vulns")
	write(t, filepath.Join(src, "db", "metadata.json"), `{"UpdatedAt":"2026-11-05T00:00:00Z"}`)
	write(t, filepath.Join(src, "feeds", "kev.json"), "kev")
	write(t, filepath.Join(src, "feeds", "sub", "x.csv"), "epss")
	must(t, os.Symlink("kev.json", filepath.Join(src, "feeds", "link"))) // not data: skipped
	parts := []Part{{"trivy-db", filepath.Join(src, "db")}, {"trivy-java-db", filepath.Join(src, "java-db")},
		{"feeds", filepath.Join(src, "feeds")}}
	bundle := filepath.Join(t.TempDir(), "b.tar.gz")
	done, err := Export(bundle, parts)
	must(t, err)
	if !slices.Equal(done, []string{"trivy-db", "feeds"}) { // java-db was never downloaded
		t.Fatal(done)
	}

	dst := t.TempDir()
	write(t, filepath.Join(dst, "db", "stale.db"), "old") // replaced whole
	write(t, filepath.Join(dst, "java-db", "keep"), "j")  // not in the bundle: untouched
	in := []Part{{"trivy-db", filepath.Join(dst, "db")}, {"trivy-java-db", filepath.Join(dst, "java-db")},
		{"feeds", filepath.Join(dst, "new", "feeds")}}
	done, err = Import(bundle, in)
	must(t, err)
	if !slices.Equal(done, []string{"feeds", "trivy-db"}) {
		t.Fatal(done)
	}
	if read(t, filepath.Join(dst, "db", "trivy.db")) != "vulns" || read(t, filepath.Join(dst, "new", "feeds", "sub", "x.csv")) != "epss" ||
		read(t, filepath.Join(dst, "java-db", "keep")) != "j" {
		t.Fatal("content")
	}
	if _, err := os.Stat(filepath.Join(dst, "db", "stale.db")); !os.IsNotExist(err) {
		t.Fatal("stale file kept")
	}
	if _, err := os.Lstat(filepath.Join(dst, "new", "feeds", "link")); !os.IsNotExist(err) {
		t.Fatal("link exported")
	}
	left, _ := filepath.Glob(filepath.Join(dst, ".*"))
	if len(left) != 0 {
		t.Fatal("staging left:", left)
	}
}

func TestExportErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Export(filepath.Join(dir, "b.tgz"), []Part{{"x", filepath.Join(dir, "none")}}); err == nil ||
		!strings.Contains(err.Error(), "nothing to export") {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "file"), "x")
	if _, err := Export(filepath.Join(dir, "b.tgz"), []Part{{"x", filepath.Join(dir, "file")}}); err == nil ||
		!strings.Contains(err.Error(), "not a directory") {
		t.Fatal(err)
	}
	if _, err := Export(filepath.Join(dir, "no", "such", "b.tgz"), []Part{{"x", dir}}); err == nil {
		t.Fatal("missing target dir")
	}
	if _, err := os.Stat(filepath.Join(dir, "b.tgz")); !os.IsNotExist(err) {
		t.Fatal("partial bundle left")
	}
}

type entry struct {
	name, body string
	typ        byte
}

func bundle(t *testing.T, entries ...entry) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "b.tar.gz")
	f, err := os.Create(p)
	must(t, err)
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if e.typ == tar.TypeSymlink {
			h.Linkname = "/etc/passwd"
		}
		must(t, tw.WriteHeader(h))
		if e.typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	must(t, tw.Close())
	must(t, zw.Close())
	must(t, f.Close())
	return p
}

func TestImportRefuses(t *testing.T) {
	old := maxFile
	maxFile = 64
	t.Cleanup(func() { maxFile = old })
	dst := t.TempDir()
	parts := []Part{{"trivy-db", filepath.Join(dst, "db")}, {"feeds", filepath.Join(dst, "feeds")}}
	for name, c := range map[string]struct {
		entries []entry
		want    string
	}{
		"dotdot":        {[]entry{{name: "trivy-db/../../evil", body: "x", typ: tar.TypeReg}}, "unsafe path"},
		"leading":       {[]entry{{name: "../evil", body: "x", typ: tar.TypeReg}}, "unsafe path"},
		"absolute":      {[]entry{{name: "/etc/evil", body: "x", typ: tar.TypeReg}}, "unsafe path"},
		"unclean":       {[]entry{{name: "trivy-db/./x", body: "x", typ: tar.TypeReg}}, "unsafe path"},
		"backslash":     {[]entry{{name: `trivy-db\..\x`, body: "x", typ: tar.TypeReg}}, "unsafe path"},
		"empty name":    {[]entry{{name: "/", typ: tar.TypeDir}}, "unsafe path"},
		"unknown":       {[]entry{{name: "orgs/acme.yml", body: "x", typ: tar.TypeReg}}, "unexpected entry"},
		"symlink":       {[]entry{{name: "trivy-db/x", typ: tar.TypeSymlink}}, "only files and directories"},
		"too big":       {[]entry{{name: "trivy-db/x", body: strings.Repeat("x", 100), typ: tar.TypeReg}}, "too large"},
		"empty":         {nil, "empty"},
		"file over dir": {[]entry{{name: "trivy-db", body: "x", typ: tar.TypeReg}}, ""},
	} {
		_, err := Import(bundle(t, c.entries...), parts)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, p := range parts {
		if _, err := os.Stat(p.Dir); !os.IsNotExist(err) {
			t.Fatal("a refused bundle changed", p.Dir)
		}
	}
	left, _ := filepath.Glob(filepath.Join(dst, ".*"))
	if len(left) != 0 {
		t.Fatal("staging left:", left)
	}

	notGz := filepath.Join(dst, "x.tgz")
	write(t, notGz, "plain text")
	if _, err := Import(notGz, parts); err == nil || !strings.Contains(err.Error(), "not a kanareika DB bundle") {
		t.Fatal(err)
	}
	if _, err := Import(filepath.Join(dst, "missing"), parts); err == nil {
		t.Fatal("missing file")
	}
	// truncated archive: gzip header fine, tar broken
	f, _ := os.Create(notGz)
	zw := gzip.NewWriter(f)
	_, _ = zw.Write([]byte("not a tar archive, just some bytes that are long enough to be read as a header....."))
	zw.Close()
	f.Close()
	if _, err := Import(notGz, parts); err == nil {
		t.Fatal("broken tar")
	}
}

// TestPermissionErrors: unreadable sources and unwritable targets fail cleanly, leaving nothing behind.
func TestPermissionErrors(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("permission bits: Unix")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores permissions")
	}
	src := t.TempDir()
	write(t, filepath.Join(src, "db", "secret"), "x")
	must(t, os.Chmod(filepath.Join(src, "db", "secret"), 0))
	out := filepath.Join(t.TempDir(), "b.tgz")
	if _, err := Export(out, []Part{{"trivy-db", filepath.Join(src, "db")}}); err == nil {
		t.Fatal("unreadable file exported")
	}
	locked := filepath.Join(src, "locked")
	write(t, filepath.Join(locked, "db", "x"), "x")
	must(t, os.Chmod(locked, 0))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if _, err := Export(out, []Part{{"trivy-db", filepath.Join(locked, "db")}}); err == nil {
		t.Fatal("unreadable dir exported")
	}
	sub := filepath.Join(src, "sub")
	write(t, filepath.Join(sub, "db", "inner", "x"), "x")
	must(t, os.Chmod(filepath.Join(sub, "db", "inner"), 0))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(sub, "db", "inner"), 0o755) })
	if _, err := Export(out, []Part{{"trivy-db", filepath.Join(sub, "db")}}); err == nil {
		t.Fatal("unreadable subdir exported")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("partial bundle left")
	}

	b := bundle(t, entry{name: "trivy-db/", typ: tar.TypeDir}, entry{name: "trivy-db/x", body: "x", typ: tar.TypeReg})
	ro := t.TempDir()
	must(t, os.Chmod(ro, 0o555))
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	if _, err := Import(b, []Part{{"trivy-db", filepath.Join(ro, "db")}}); err == nil {
		t.Fatal("imported into a read-only dir")
	}
	if _, err := Import(b, []Part{{"trivy-db", filepath.Join(ro, "deeper", "db")}}); err == nil {
		t.Fatal("created a dir in a read-only dir")
	}
}
