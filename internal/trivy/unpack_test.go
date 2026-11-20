package trivy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/dbget"
	"github.com/mikekosulin/kanareika/internal/trivy/ocitest"
)

// entry: one member of a test archive.
type entry struct {
	h    tar.Header
	body []byte
}

// file: a regular file of body.
func file(name string, body []byte) entry {
	return entry{tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)), ModTime: ocitest.ModTime}, body}
}

// archive: a tar.gz of the entries, in order.
func archive(t *testing.T, es ...entry) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, e := range es {
		must(t, tw.WriteHeader(&e.h))
		_, err := tw.Write(e.body)
		must(t, err)
	}
	must(t, tw.Close())
	must(t, gz.Close())
	return b.Bytes()
}

// dbFiles: what a trivy-db layer holds.
func dbFiles(t *testing.T) []entry {
	return []entry{file("metadata.json", ocitest.Metadata(2, testNext, testUpd)), file("trivy.db", boltDB(t))}
}

// fetchLayer: the layer served as the DB's only repository, downloaded.
func fetchLayer(t *testing.T, layer []byte) dbget.Item {
	t.Helper()
	reg := ocitest.New(t)
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", reg.Push("a/trivy-db", "2", dbKinds[0].mediaType, layer))
	it, _ := runJob(t, "db")
	return it
}

// TestLayerExtras: what a layer may carry besides plain files is passed over: a pax global header (as `git archive`
// writes one) is not a file, a symlink is not created (it could point anywhere on the machine).
func TestLayerExtras(t *testing.T) {
	cache := fetchEnv(t)
	pax := entry{h: tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": "trivy-db"}}}
	link := entry{h: tar.Header{Name: "passwd", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", ModTime: ocitest.ModTime}}
	if it := fetchLayer(t, archive(t, append([]entry{pax, link}, dbFiles(t)...)...)); it.State != dbget.Done {
		t.Fatalf("%+v", it)
	}
	ents, _ := os.ReadDir(filepath.Join(cache, "db"))
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"metadata.json", "trivy.db"}) {
		t.Fatal(names)
	}
}

// TestBrokenArchives: an archive that is not a tar inside its gzip, is cut short inside a file, has entries that
// collide (a directory through a file, a file over a directory), or a metadata.json that is not JSON fails the
// download with the reason, and leaves the cache as it was.
func TestBrokenArchives(t *testing.T) {
	cache := fetchEnv(t)
	var notTar bytes.Buffer
	gz := gzip.NewWriter(&notTar)
	_, _ = gz.Write(bytes.Repeat([]byte("x"), 1024))
	must(t, gz.Close())
	var cut bytes.Buffer // a file of 1000 bytes of which 10 came
	gz = gzip.NewWriter(&cut)
	tw := tar.NewWriter(gz)
	must(t, tw.WriteHeader(&tar.Header{Name: "trivy.db", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1000}))
	_, _ = tw.Write(make([]byte, 10))
	must(t, gz.Close())
	dir := func(name string) entry {
		return entry{h: tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755, ModTime: ocitest.ModTime}}
	}
	cases := []struct {
		name  string
		layer []byte
		want  string // in the note; "" for the system's own words
	}{
		{"not a tar", notTar.Bytes(), "unpacking: archive/tar: invalid tar header"},
		{"cut short", cut.Bytes(), "unpacking: unexpected EOF"},
		{"directory through a file", archive(t, file("a", nil), dir("a/b")), ""},
		{"file through a file", archive(t, file("a", nil), file("a/b", nil)), ""},
		{"file over a directory", archive(t, dir("x"), file("x", nil)), ""},
		{"metadata not JSON", archive(t, file("metadata.json", []byte("not json")), file("trivy.db", []byte("x"))), "the layer's metadata.json: "},
	}
	for _, c := range cases {
		it := fetchLayer(t, c.layer)
		if it.State != dbget.Failed || !strings.Contains(it.Note, c.want) {
			t.Errorf("%s: %+v", c.name, it)
		}
		if ents, _ := os.ReadDir(cache); len(ents) != 0 {
			t.Fatalf("%s: leftovers %v", c.name, ents)
		}
	}
}

// TestLayerTimes: the files get the archive's times, access time included (go-getter, which trivy downloads with,
// keeps both; checked on Unix).
func TestLayerTimes(t *testing.T) {
	cache := fetchEnv(t)
	atimeWant := time.Date(2026, 11, 8, 7, 30, 0, 0, time.UTC)
	es := dbFiles(t)
	es[1].h.AccessTime, es[1].h.Format = atimeWant, tar.FormatPAX // the format that carries it
	if it := fetchLayer(t, archive(t, es...)); it.State != dbget.Done {
		t.Fatalf("%+v", it)
	}
	p := filepath.Join(cache, "db", "trivy.db") // only looked at, never read: reading may move the access time
	fi, err := os.Stat(p)
	must(t, err)
	at, checked := atime(t, p)
	if !fi.ModTime().Equal(ocitest.ModTime) || checked && !at.Equal(atimeWant) {
		t.Fatal(fi.ModTime(), at)
	}
}

// TestCleanLeftovers: the temp files and directories of a download that died over a day ago are removed when the
// next one starts; a younger one (another process downloading right now) and the other DB's are left alone.
func TestCleanLeftovers(t *testing.T) {
	cache := fetchEnv(t)
	must(t, os.MkdirAll(cache, 0o755))
	old, young := testNow.Add(-48*time.Hour), testNow.Add(-time.Hour)
	for name, at := range map[string]time.Time{".db-1.tar.gz": old, ".db-new-1": old, ".db-2.tar.gz": young, ".java-db-1.tar.gz": old} {
		p := filepath.Join(cache, name)
		if strings.Contains(name, "-new-") {
			must(t, os.MkdirAll(filepath.Join(p, "sub"), 0o755))
		} else {
			must(t, os.WriteFile(p, []byte("partial"), 0o644))
		}
		must(t, os.Chtimes(p, at, at))
	}
	if it := fetchLayer(t, dbLayer(t)); it.State != dbget.Done {
		t.Fatalf("%+v", it)
	}
	ents, _ := os.ReadDir(cache)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{".db-2.tar.gz", ".java-db-1.tar.gz", "db"}) {
		t.Fatal(names)
	}
}

// TestUnwritableCache: a cache directory that can't be written to fails the download with the system's reason.
func TestUnwritableCache(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permissions that apply (not root)")
	}
	cache := fetchEnv(t)
	must(t, os.MkdirAll(cache, 0o555))
	t.Cleanup(func() { _ = os.Chmod(cache, 0o755) })
	if it := fetchLayer(t, dbLayer(t)); it.State != dbget.Failed || !strings.Contains(it.Note, "permission denied") {
		t.Fatalf("%+v", it)
	}
}

// TestNotFresh: a cached DB trivy would not use as it is is downloaded again: no download time (as published, e.g.
// copied in by hand), or another schema; without a cache directory nothing is fresh.
func TestNotFresh(t *testing.T) {
	cache := fetchEnv(t)
	for _, meta := range []string{
		`{"Version":2,"NextUpdate":"2026-11-09T12:00:00Z","UpdatedAt":"2026-11-09T06:00:00Z"}`,
		`{"Version":1,"NextUpdate":"2026-11-09T12:00:00Z","UpdatedAt":"2026-11-09T06:00:00Z","DownloadedAt":"2026-11-09T09:00:00Z"}`,
	} {
		must(t, os.MkdirAll(filepath.Join(cache, "db"), 0o755))
		must(t, os.WriteFile(filepath.Join(cache, "db", "trivy.db"), []byte("x"), 0o644))
		must(t, os.WriteFile(filepath.Join(cache, "db", "metadata.json"), []byte(meta), 0o644))
		if it := fetchLayer(t, dbLayer(t)); it.State != dbget.Done {
			t.Fatalf("%s: %+v", meta, it)
		}
	}
	t.Setenv("TRIVY_CACHE_DIR", "")
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("LocalAppData", "")
	if trivyCacheDir() == "" && kind("db").fresh(testNow) {
		t.Fatal("fresh without a cache directory")
	}
}

// TestInstallMissing: an archive or a cache directory that is gone is an error, and no half-made copy stays.
func TestInstallMissing(t *testing.T) {
	cache := t.TempDir()
	k := kind("db")
	if err := k.install(cache, filepath.Join(cache, "gone.tar.gz"), 1<<20, testNow); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(cache); len(ents) != 0 {
		t.Fatalf("leftovers: %v", ents)
	}
	arc := filepath.Join(t.TempDir(), "db.tar.gz")
	must(t, os.WriteFile(arc, dbLayer(t), 0o644))
	if err := k.install(filepath.Join(cache, "gone"), arc, 1<<20, testNow); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
}
