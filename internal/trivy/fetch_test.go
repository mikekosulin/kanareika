package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tdb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	javadb "github.com/aquasecurity/trivy-java-db/pkg/db"
	trivydb "github.com/aquasecurity/trivy/pkg/db"
	_ "modernc.org/sqlite" // the Java DB's driver, as trivy links it

	"github.com/mikekosulin/kanareika/internal/dbget"
	"github.com/mikekosulin/kanareika/internal/trivy/ocitest"
)

var (
	testNow  = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	testNext = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	testUpd  = time.Date(2026, 11, 9, 6, 0, 0, 0, time.UTC)
)

// fetchEnv: an empty trivy cache, the clock at testNow, no external trivy, every attempt made.
func fetchEnv(t *testing.T) string {
	t.Helper()
	cache := filepath.Join(t.TempDir(), "trivy")
	t.Setenv("TRIVY_CACHE_DIR", cache)
	t.Setenv("KANAREIKA_TRIVY", "")
	t.Setenv("TRIVY_DB_REPOSITORY", "")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "")
	oldNow, oldRetry := clockNow, retryAfter
	clockNow, retryAfter = func() time.Time { return testNow }, 0
	t.Cleanup(func() { clockNow, retryAfter = oldNow, oldRetry })
	failMu.Lock()
	failed = map[string]failure{}
	failMu.Unlock()
	return cache
}

// boltDB: an empty trivy-db file, as trivy-db creates it.
func boltDB(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	must(t, tdb.Init(dir))
	must(t, tdb.Close())
	b, err := os.ReadFile(tdb.Path(dir))
	must(t, err)
	return b
}

// javaDB: an empty trivy-java-db file with its tables.
func javaDB(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	d, err := javadb.New(dir)
	must(t, err)
	must(t, d.Init())
	must(t, d.Close())
	b, err := os.ReadFile(filepath.Join(dir, "trivy-java.db"))
	must(t, err)
	return b
}

func dbLayer(t *testing.T) []byte {
	return ocitest.Layer(map[string][]byte{"trivy.db": boltDB(t), "metadata.json": ocitest.Metadata(2, testNext, testUpd)})
}

func runJob(t *testing.T, name string) (dbget.Item, error) {
	t.Helper()
	tr := dbget.NewTracker()
	errs := tr.Run(context.Background(), []dbget.Job{Job(name, nil)})
	return tr.Snapshot().Items[0], errs[name]
}

// TestFetchAsTrivy: the layer is downloaded, checked and unpacked as trivy does it; trivy's own code accepts the
// result for --skip-db-update; the next update finds it fresh and downloads nothing.
func TestFetchAsTrivy(t *testing.T) {
	cache := fetchEnv(t)
	reg := ocitest.New(t)
	layer := dbLayer(t)
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", reg.Push("aquasecurity/trivy-db", "2", dbKinds[0].mediaType, layer))

	it, err := runJob(t, "db")
	if err != nil || it.State != dbget.Done || it.Bytes != int64(len(layer)) || it.Total != int64(len(layer)) {
		t.Fatalf("%+v %v", it, err)
	}
	dir := filepath.Join(cache, "db")
	// the layout trivy writes: the two files, nothing else (no temp files left in the cache either)
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"metadata.json", "trivy.db"}) {
		t.Fatal(names)
	}
	if ents, _ := os.ReadDir(cache); len(ents) != 1 {
		t.Fatalf("leftovers in the cache: %v", ents)
	}
	fi, err := os.Stat(filepath.Join(dir, "trivy.db"))
	must(t, err)
	if fi.Mode().Perm() != 0o644 || !fi.ModTime().Equal(ocitest.ModTime) {
		t.Fatal(fi.Mode(), fi.ModTime())
	}
	// metadata.json: byte for byte what trivy's metadata client writes after its download
	var want bytes.Buffer
	must(t, json.NewEncoder(&want).Encode(&metadata.Metadata{Version: 2, NextUpdate: testNext, UpdatedAt: testUpd, DownloadedAt: testNow}))
	got, _ := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("metadata.json:\n%s\nwant:\n%s", got, want.Bytes())
	}
	// trivy itself: no update needed with --skip-db-update, and the DB opens
	need, err := trivydb.NewClient(dir, true).NeedsUpdate(context.Background(), "test", true)
	if err != nil || need {
		t.Fatal(need, err)
	}
	must(t, trivydb.Init(dir))
	must(t, trivydb.Close())
	if at := DBStatus()[0].Updated; !at.Equal(testUpd) {
		t.Fatal(at)
	}

	// fresh: the next update asks nothing
	n := len(reg.Paths())
	it, err = runJob(t, "db")
	if err != nil || it.State != dbget.Cached || it.Note != "already up to date (cached)" || len(reg.Paths()) != n {
		t.Fatalf("%+v %v %v", it, err, reg.Paths()[n:])
	}
	// nothing but the request: no identifiers, no telemetry
	for _, q := range reg.Requests {
		for _, h := range q.Headers {
			if !slices.Contains([]string{"Accept", "Accept-Encoding", "Authorization", "User-Agent"}, h) {
				t.Fatalf("%s sent %s", q.Path, h)
			}
		}
		if q.UA != dbget.UserAgent {
			t.Fatal(q.UA)
		}
	}
}

// TestFetchJavaDB: the Java DB the same way; trivy-java-db reads what was written.
func TestFetchJavaDB(t *testing.T) {
	cache := fetchEnv(t)
	reg := ocitest.New(t)
	layer := ocitest.Layer(map[string][]byte{"trivy-java.db": javaDB(t), "metadata.json": ocitest.Metadata(1, testNext, testUpd)})
	t.Setenv("KANAREIKA_TRIVY_JAVA_DB_REPOS", reg.Push("aquasecurity/trivy-java-db", "1", dbKinds[1].mediaType, layer))
	if it, err := runJob(t, "java-db"); err != nil || it.State != dbget.Done {
		t.Fatalf("%+v %v", it, err)
	}
	dir := filepath.Join(cache, "java-db")
	mc := javadb.NewMetadata(dir)
	m, err := mc.Get()
	if err != nil || m.Version != 1 || !m.DownloadedAt.Equal(testNow) || !m.NextUpdate.Equal(testNext) {
		t.Fatal(m, err)
	}
	d, err := javadb.New(dir)
	must(t, err)
	defer d.Close()
	if idx, err := d.SelectIndexBySha1("0000"); err != nil || idx.ArtifactID != "" {
		t.Fatal(idx, err)
	}
	// the day after DownloadedAt, past NextUpdate: trivy would download again, so does kanareika
	clockNow = func() time.Time { return testNow.Add(25 * time.Hour) }
	if it, _ := runJob(t, "java-db"); it.State != dbget.Done {
		t.Fatal(it)
	}
}

// TestMirrorFallback: a mirror that fails is reported and the next one tried; the reason says which and why.
func TestMirrorFallback(t *testing.T) {
	cache := fetchEnv(t)
	busy, good := ocitest.New(t), ocitest.New(t)
	busy.Fail = 429
	layer := dbLayer(t)
	refs := []string{busy.Push("a/trivy-db", "2", dbKinds[0].mediaType, layer), good.Push("a/trivy-db", "2", dbKinds[0].mediaType, layer)}
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", strings.Join(refs, ","))
	var notes []string
	tr := dbget.NewTracker()
	var mu sync.Mutex // OnEvent runs in the jobs' goroutines
	tr.OnEvent = func(it dbget.Item) { mu.Lock(); notes = append(notes, it.Note); mu.Unlock() }
	if errs := tr.Run(context.Background(), []dbget.Job{Job("db", nil)}); errs != nil {
		t.Fatal(errs)
	}
	want := busy.Host() + ": too many requests (429), trying " + good.Host()
	if !slices.Contains(notes, want) || tr.Snapshot().Items[0].Note != "from "+good.Host() {
		t.Fatalf("%q", notes)
	}
	if _, err := os.Stat(filepath.Join(cache, "db", "trivy.db")); err != nil {
		t.Fatal(err)
	}
}

// TestFetchFailures: every mirror failing is one error naming each and why; a cached copy stays in place, whole.
func TestFetchFailures(t *testing.T) {
	cache := fetchEnv(t)
	a, b, c := ocitest.New(t), ocitest.New(t), ocitest.New(t)
	layer := dbLayer(t)
	var refs []string
	for _, r := range []*ocitest.Registry{a, b, c} {
		refs = append(refs, r.Push("a/trivy-db", "2", dbKinds[0].mediaType, layer))
	}
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", strings.Join(refs, ","))
	a.Fail = 503
	b.Corrupt = true
	c.NoChallenge = true
	it, err := runJob(t, "db")
	var me *MirrorError
	if !errors.As(err, &me) || it.State != dbget.Failed {
		t.Fatal(it, err)
	}
	want := "no mirror worked: " + a.Host() + ": server error (503); " + b.Host() + ": sha256 mismatch: got "
	if !strings.HasPrefix(it.Note, want) || !strings.HasSuffix(it.Note, c.Host()+": unauthorized (401)") {
		t.Fatal(it.Note)
	}
	if ents, _ := os.ReadDir(cache); len(ents) != 0 {
		t.Fatalf("leftovers: %v", ents)
	}

	// with a copy in the cache: it stays (Kept), untouched
	a.Fail, b.Corrupt, c.NoChallenge = 0, false, false
	if _, err := runJob(t, "db"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(cache, "db", "metadata.json"))
	clockNow = func() time.Time { return testNow.Add(3 * time.Hour) } // past NextUpdate and the hour
	b.Corrupt, c.Fail, a.Fail = true, 404, 500
	it, err = runJob(t, "db")
	var kept *dbget.KeptError
	if !errors.As(err, &kept) || !strings.Contains(it.Note, "; the copy from 2026-11-09 06:00Z (7h0m0s old) stays in use") {
		t.Fatal(it.Note, err)
	}
	after, _ := os.ReadFile(filepath.Join(cache, "db", "metadata.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("the cached copy changed")
	}
	// Prepare goes on with it, saying so
	var logs []string
	must(t, Prepare(context.Background(), func(f string, a ...any) { logs = append(logs, f) }))
	if !strings.HasPrefix(logs[len(logs)-1], "WARNING: trivy %s not updated") {
		t.Fatal(logs)
	}
}

// TestFailureMemo: a failed download is not retried at once when a cached copy exists (a scan right after a failed
// db update does not wait for the same mirrors again); without a copy it is.
func TestFailureMemo(t *testing.T) {
	cache := fetchEnv(t)
	retryAfter = time.Minute
	reg := ocitest.New(t)
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", reg.Push("a/trivy-db", "2", dbKinds[0].mediaType, dbLayer(t)))
	reg.Fail = 500
	if _, err := runJob(t, "db"); err == nil {
		t.Fatal("no error")
	}
	n := len(reg.Paths())
	if _, err := runJob(t, "db"); err == nil || len(reg.Paths()) == n {
		t.Fatal("no copy: must retry")
	}
	must(t, os.MkdirAll(filepath.Join(cache, "db"), 0o755))
	must(t, os.WriteFile(filepath.Join(cache, "db", "metadata.json"), []byte(`{"UpdatedAt":"2026-11-08T00:00:00Z"}`), 0o644))
	n = len(reg.Paths())
	if _, err := runJob(t, "db"); err == nil || len(reg.Paths()) != n {
		t.Fatal("retried within a minute")
	}
}

// TestBadLayers: what the registry serves must be a trivy DB of this trivy's schema, inside its directory.
func TestBadLayers(t *testing.T) {
	fetchEnv(t)
	reg := ocitest.New(t)
	cases := []struct {
		media string
		layer []byte
		want  string
	}{
		{"application/x-other", dbLayer(t), "unexpected layer type"},
		{dbKinds[0].mediaType, ocitest.Layer(map[string][]byte{"metadata.json": ocitest.Metadata(2, testNext, testUpd)}), "the layer has no trivy.db"},
		{dbKinds[0].mediaType, ocitest.Layer(map[string][]byte{"trivy.db": []byte("x"), "metadata.json": ocitest.Metadata(3, testNext, testUpd)}), "DB schema 3, this trivy reads 2"},
		{dbKinds[0].mediaType, ocitest.Layer(map[string][]byte{"../evil": []byte("x")}), "outside the DB directory"},
		{dbKinds[0].mediaType, ocitest.Layer(nil), "empty archive"},
		{dbKinds[0].mediaType, []byte("not gzip"), "unpacking"},
	}
	for i, c := range cases {
		t.Setenv("KANAREIKA_TRIVY_DB_REPOS", reg.Push("a/trivy-db", string(rune('a'+i)), c.media, c.layer))
		if it, _ := runJob(t, "db"); !strings.Contains(it.Note, c.want) {
			t.Errorf("%d: %q, want %q", i, it.Note, c.want)
		}
	}
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", reg.Host()+"/missing/x:2")
	if it, _ := runJob(t, "db"); !strings.HasSuffix(it.Note, ": not found (404)") {
		t.Fatal(it.Note)
	}
}

// TestNoSpace: a full disk is said with how much is needed, and no other mirror is tried for it.
func TestNoSpace(t *testing.T) {
	err := &dbget.NoSpaceError{Need: 2_100_000_000}
	if dbget.Reason(err) != "no space left on device: 2.1 GB free needed" {
		t.Fatal(dbget.Reason(err))
	}
	cache := fetchEnv(t)
	// the cache dir is a file: unwritable, as a full disk would be (not ENOSPC, so it is reported as it is)
	must(t, os.WriteFile(cache, nil, 0o644))
	reg := ocitest.New(t)
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", reg.Push("a/trivy-db", "2", dbKinds[0].mediaType, dbLayer(t)))
	if it, _ := runJob(t, "db"); it.State != dbget.Failed {
		t.Fatal(it)
	}
}

// TestViaTrivy: with trivy's own repository setting or an external trivy, trivy downloads.
func TestViaTrivy(t *testing.T) {
	fetchEnv(t)
	fake(t, `exit 0`)
	tr := dbget.NewTracker()
	var notes []string
	var mu sync.Mutex // OnEvent runs in the jobs' goroutines
	tr.OnEvent = func(it dbget.Item) { mu.Lock(); notes = append(notes, it.Note); mu.Unlock() }
	if errs := tr.Run(context.Background(), []dbget.Job{Job("db", nil), Job("nope", nil)}); errs["db"] != nil || errs["nope"] == nil {
		t.Fatal(errs)
	}
	if !slices.Contains(notes, "trivy downloads it (external trivy)") {
		t.Fatal(notes)
	}
	k := kind("db")
	t.Setenv("KANAREIKA_TRIVY", "")
	t.Setenv("TRIVY_DB_REPOSITORY", "x/y:2")
	if k.viaTrivy() != "TRIVY_DB_REPOSITORY is set" {
		t.Fatal(k.viaTrivy())
	}
	t.Setenv("TRIVY_CACHE_DIR", "")
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	if trivyCacheDir() == "" {
		if err := k.fetch(context.Background(), nil, nil); err == nil || !strings.Contains(err.Error(), "no cache directory") {
			t.Fatal(err)
		}
	}
}

// TestSchemas: the schema versions kanareika expects are the ones the embedded trivy reads.
func TestSchemas(t *testing.T) {
	if dbKinds[0].schema != tdb.SchemaVersion || dbKinds[1].schema != javadb.SchemaVersion {
		t.Fatal(tdb.SchemaVersion, javadb.SchemaVersion)
	}
	for _, k := range dbKinds {
		if !strings.HasSuffix(k.repos[0], ":"+string(rune('0'+k.schema))) {
			t.Fatal(k.repos[0])
		}
	}
}
