package trivy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/metadata"

	"github.com/mikekosulin/kanareika/internal/dbget"
)

// How kanareika downloads trivy's DBs: the OCI layer straight from the registry (the manifest names its digest and
// size, so the bytes can be counted and checked), unpacked into trivy's cache exactly as trivy does it (pkg/oci:
// the tar.gz into <cache>/<db>, then metadata.json's DownloadedAt set), so `trivy --skip-db-update` uses it as its
// own. The new copy is unpacked next to the old one and swapped in, so a failed download leaves the old copy whole.
// With TRIVY_DB_REPOSITORY / TRIVY_JAVA_DB_REPOSITORY or an external trivy (KANAREIKA_TRIVY), trivy downloads.

// clockNow: tests freeze it.
var clockNow = time.Now

// fetchMu: one download of each DB at a time in this process (Prepare, the Java DB on demand, db update).
var fetchMu = map[string]*sync.Mutex{"db": {}, "java-db": {}}

// retryAfter: a DB whose download failed is not tried again within this time when a cached copy exists (a scan
// right after a failed db update does not wait for the same mirrors again).
var retryAfter = 5 * time.Minute

var (
	failMu sync.Mutex
	failed = map[string]failure{}
)

type failure struct {
	at  time.Time
	err error
}

func kind(name string) dbKind {
	for _, k := range dbKinds {
		if k.name == name {
			return k
		}
	}
	return dbKind{}
}

func (k dbKind) meta() (metadata.Metadata, error) {
	return metadata.NewClient(filepath.Join(trivyCacheDir(), k.name)).Get()
}

// fresh: trivy itself would not download it now (pkg/db NeedsUpdate, pkg/javadb isNewDB): the DB file and its
// metadata are there, the schema matches, and either the next build is not out yet or it was downloaded within
// the window (1 h for the DB, a day for the Java DB).
func (k dbKind) fresh(now time.Time) bool {
	dir := trivyCacheDir()
	if dir == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, k.name, k.file)); err != nil {
		return false
	}
	m, err := k.meta()
	if err != nil || m.Version != k.schema || m.DownloadedAt.IsZero() {
		return false
	}
	return now.Before(m.NextUpdate) || now.Before(m.DownloadedAt.Add(k.window))
}

// viaTrivy: why trivy downloads this DB itself ("": kanareika does).
func (k dbKind) viaTrivy() string {
	if os.Getenv(k.trivyEnv) != "" {
		return k.trivyEnv + " is set"
	}
	if os.Getenv("KANAREIKA_TRIVY") != "" {
		return "external trivy"
	}
	return ""
}

func hostOf(ref string) string {
	h, _, _ := strings.Cut(ref, "/")
	return h
}

// MirrorError: no repository worked; Fails: "<host>: <reason>" for each, in the order tried.
type MirrorError struct {
	DB    string
	Fails []string
}

func (e *MirrorError) Error() string  { return "trivy " + e.DB + ": " + e.Reason() }
func (e *MirrorError) Reason() string { return "no mirror worked: " + strings.Join(e.Fails, "; ") }

// fetch: the DB into trivy's cache unless it is fresh; the mirrors in order. p (may be nil) gets the progress,
// logf (may be nil) the same as lines.
func (k dbKind) fetch(ctx context.Context, p *dbget.Progress, logf func(string, ...any)) error {
	say := func(f string, a ...any) {
		if logf != nil {
			logf(f, a...)
		}
	}
	mu := fetchMu[k.name]
	mu.Lock()
	defer mu.Unlock()
	if trivyCacheDir() == "" {
		return errors.New("trivy " + k.name + ": no cache directory (set TRIVY_CACHE_DIR)")
	}
	if k.fresh(clockNow()) {
		p.Cached("already up to date (cached)")
		return nil
	}
	failMu.Lock()
	f := failed[k.name]
	failMu.Unlock()
	if f.err != nil && clockNow().Sub(f.at) < retryAfter && !k.cachedAt().IsZero() {
		return f.err
	}
	err := k.fetchNow(ctx, p, say)
	failMu.Lock()
	if err != nil && ctx.Err() == nil {
		failed[k.name] = failure{clockNow(), err}
	} else {
		delete(failed, k.name)
	}
	failMu.Unlock()
	return err
}

func (k dbKind) fetchNow(ctx context.Context, p *dbget.Progress, say func(string, ...any)) error {
	if why := k.viaTrivy(); why != "" {
		p.Start(0)
		p.Note("trivy downloads it (" + why + ")")
		return k.download(ctx, say)
	}
	repos := k.repositories()
	var fails []string
	for i, ref := range repos {
		err := k.pull(ctx, ref, p, say)
		if err == nil {
			if i > 0 {
				p.Note("from " + hostOf(ref))
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var full *dbget.NoSpaceError
		if errors.As(err, &full) {
			return err // the same on every mirror
		}
		reason := hostOf(ref) + ": " + dbget.Reason(err)
		fails = append(fails, reason)
		if i+1 < len(repos) {
			reason += ", trying " + hostOf(repos[i+1])
			p.Note(reason)
		}
		say("trivy %s: %s", k.name, reason)
	}
	return &MirrorError{DB: k.name, Fails: fails}
}

// pull: the single layer of ref, checked against its digest, installed into the cache.
func (k dbKind) pull(ctx context.Context, ref string, p *dbget.Progress, say func(string, ...any)) error {
	r, err := parseRef(ref)
	if err != nil {
		return err
	}
	m, err := r.manifest(ctx)
	if err != nil {
		return err
	}
	if len(m.Layers) != 1 {
		return fmt.Errorf("%d layers, expected one", len(m.Layers))
	}
	l := m.Layers[0]
	if l.MediaType != k.mediaType {
		return fmt.Errorf("unexpected layer type %q", l.MediaType)
	}
	if !strings.HasPrefix(l.Digest, "sha256:") {
		return fmt.Errorf("unexpected layer digest %q", l.Digest)
	}
	cache := trivyCacheDir()
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}
	cleanLeftovers(cache, k.name)
	say("trivy %s: downloading %s from %s", k.name, dbget.Size(l.Size), r.host)
	p.Start(l.Size)
	resp, err := r.get(ctx, "blobs/"+l.Digest, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(cache, "."+k.name+"-*.tar.gz")
	if err != nil {
		return dbget.NoSpace(err, l.Size)
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), p.Reader(resp.Body))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return dbget.NoSpace(err, l.Size)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != l.Digest || n != l.Size {
		return &dbget.ChecksumError{Want: l.Digest, Got: got}
	}
	p.Note("unpacking")
	return k.install(cache, tmp.Name(), clockNow())
}

// cleanLeftovers: temp files and directories of downloads that died more than a day ago (one running in another
// process right now is younger).
func cleanLeftovers(cache, name string) {
	old, _ := filepath.Glob(filepath.Join(cache, "."+name+"-*"))
	for _, f := range old {
		if fi, err := os.Lstat(f); err == nil && clockNow().Sub(fi.ModTime()) > 24*time.Hour {
			_ = os.RemoveAll(f)
		}
	}
}

// install: the downloaded tar.gz as <cache>/<name>, with DownloadedAt set as trivy sets it (metadata.Client.Update:
// the same JSON encoder, the same fields).
func (k dbKind) install(cache, archive string, at time.Time) error {
	tmp := filepath.Join(cache, fmt.Sprintf(".%s-new-%d", k.name, time.Now().UnixNano()))
	if err := os.Mkdir(tmp, 0o755); err != nil {
		return dbget.NoSpace(err, 0)
	}
	defer os.RemoveAll(tmp)
	if err := untar(archive, tmp); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(tmp, k.file)); err != nil {
		return fmt.Errorf("the layer has no %s", k.file)
	}
	mc := metadata.NewClient(tmp)
	meta, err := mc.Get()
	if err != nil {
		return fmt.Errorf("the layer's metadata.json: %w", err)
	}
	if meta.Version != k.schema {
		return fmt.Errorf("DB schema %d, this trivy reads %d", meta.Version, k.schema)
	}
	meta.DownloadedAt = at.UTC()
	if err := mc.Update(meta); err != nil {
		return dbget.NoSpace(err, 0)
	}
	dst := filepath.Join(cache, k.name)
	old := filepath.Join(cache, fmt.Sprintf(".%s-old-%d", k.name, time.Now().UnixNano()))
	hadOld := false
	if _, err := os.Lstat(dst); err == nil {
		if err := os.Rename(dst, old); err != nil {
			return err
		}
		hadOld = true
	}
	if err := os.Rename(tmp, dst); err != nil {
		if hadOld {
			_ = os.Rename(old, dst)
		}
		return err
	}
	if hadOld {
		_ = os.RemoveAll(old)
	}
	return nil
}

// unpackError: the archive is broken (not "the connection closed": its bytes matched the digest).
type unpackError struct{ err error }

func (e *unpackError) Error() string  { return "unpacking: " + e.err.Error() }
func (e *unpackError) Unwrap() error  { return e.err }
func (e *unpackError) Reason() string { return e.Error() }

// untar: a tar.gz into dst as go-getter (which trivy's downloader uses) unpacks it: regular files with the
// archive's permission bits and times, directories 0755 then their own mode; no paths outside dst.
func untar(archive, dst string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return &unpackError{err}
	}
	tr := tar.NewReader(gz)
	now := time.Now()
	stamp := func(path string, h *tar.Header) error {
		a, m := now, now
		if h.AccessTime.Unix() > 0 {
			a = h.AccessTime
		}
		if h.ModTime.Unix() > 0 {
			m = h.ModTime
		}
		return os.Chtimes(path, a, m)
	}
	var dirs []*tar.Header
	var need int64
	files := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return &unpackError{err}
		}
		if h.Typeflag == tar.TypeXGlobalHeader || h.Typeflag == tar.TypeXHeader {
			continue
		}
		if !filepath.IsLocal(h.Name) {
			return fmt.Errorf("unpacking: entry %q outside the DB directory", h.Name)
		}
		path := filepath.Join(dst, h.Name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return dbget.NoSpace(err, need)
			}
			dirs = append(dirs, h)
			continue
		case tar.TypeReg:
		default:
			continue // trivy's layers hold plain files only
		}
		need += h.Size
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return dbget.NoSpace(err, need)
		}
		mode := h.FileInfo().Mode() & 0o777
		w, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			return dbget.NoSpace(err, need)
		}
		_, err = io.Copy(w, tr)
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return dbget.NoSpace(&unpackError{err}, need)
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		if err := stamp(path, h); err != nil {
			return err
		}
		files++
	}
	if files == 0 {
		return errors.New("unpacking: empty archive")
	}
	for _, h := range dirs {
		path := filepath.Join(dst, h.Name)
		if err := os.Chmod(path, h.FileInfo().Mode()&os.ModePerm); err != nil {
			return err
		}
		if err := stamp(path, h); err != nil {
			return err
		}
	}
	return nil
}

// Job: one DB ("db", "java-db") for dbget.Run: "cached" when fresh, else downloaded from the mirrors in order; a
// failed download with a cached copy is Kept (scans go on with it).
func Job(name string, logf func(string, ...any)) dbget.Job {
	k := kind(name)
	return dbget.Job{Name: name, Label: dbget.Labels[name], Run: func(ctx context.Context, p *dbget.Progress) error {
		if k.name == "" {
			return errors.New("unknown trivy DB " + name)
		}
		err := k.fetch(ctx, p, logf)
		if err != nil && ctx.Err() == nil {
			if at := k.cachedAt(); !at.IsZero() {
				return dbget.Kept(err, fmt.Sprintf("the copy from %s (%s old) stays in use",
					at.UTC().Format("2006-01-02 15:04Z"), clockNow().Sub(at).Round(time.Hour)))
			}
		}
		return err
	}}
}
