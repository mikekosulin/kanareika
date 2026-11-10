// Package trivy wraps the trivy binary: vulnerability matching for SBOMs, filesystems, images and clusters.
//
// trivy is linked into kanareika (package engine) and runs as a child process of kanareika itself, so there is
// nothing else to install; only its vulnerability DBs are downloaded (see Prepare, Offline and package-level db
// helpers). KANAREIKA_TRIVY names an external trivy binary instead. Trivy's own settings (TRIVY_CACHE_DIR for the
// vulnerability DBs, ...) pass through the environment untouched.
package trivy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/jsonx"
)

// Error: trivy ran and failed (bad target, broken DB, ...). Timeouts and a missing binary are plain errors.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

var prepared atomic.Bool

// tail: the last n characters (not bytes) of s.
func tail(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[len(r)-n:])
}

// quiet: no call home from trivy, in every subcommand. --skip-version-check alone still sends Aqua anonymous usage
// data (trivy pkg/notification: the version check request carries telemetry unless it is disabled too).
// slots bounds the trivy processes running at once across all hosts and scans of this process: each holds its
// report in memory, so this is the memory bound; a host waits here while the others go on collecting. nil = none.
var (
	slotsMu sync.Mutex
	slots   chan struct{}
)

// SetParallel bounds the trivy matches running at once (n <= 0: no bound). Matches already waiting keep the bound
// they started under.
func SetParallel(n int) {
	slotsMu.Lock()
	defer slotsMu.Unlock()
	switch {
	case n <= 0:
		slots = nil
	case slots == nil || cap(slots) != n:
		slots = make(chan struct{}, n)
	}
}

func acquire(ctx context.Context) (release func(), err error) {
	slotsMu.Lock()
	c := slots
	slotsMu.Unlock()
	if c == nil {
		return func() {}, nil
	}
	select {
	case c <- struct{}{}:
		return func() { <-c }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var quiet = []string{"TRIVY_DISABLE_TELEMETRY=true", "TRIVY_SKIP_VERSION_CHECK=true"}

func command(ctx context.Context, timeout time.Duration, args ...string) (stdout, stderr string, err error) {
	bin, prefix, err := Binary()
	if err != nil {
		return "", "", err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append(prefix, args...)...)
	cmd.Env = append(os.Environ(), quiet...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("trivy %s: timed out after %s", strings.Join(args[:min(1, len(args))], " "), timeout)
	}
	return o.String(), e.String(), err
}

// dbKind: one of trivy's vulnerability DBs and where it can be downloaded from.
type dbKind struct {
	name     string   // "db", "java-db": the directory under trivy's cache dir
	flag     string   // trivy flag that downloads it and exits
	repoFlag string   // trivy flag naming the OCI repositories
	trivyEnv string   // trivy's own setting for the repositories: when set, kanareika leaves the choice to trivy
	ourEnv   string   // kanareika's override: comma-separated repositories, tried in order
	repos    []string // default: GitHub Container Registry (published there by Aqua), then its mirrors
	// lazy: downloaded only when a scan needs it (java-db, ~1 GB: only for .jar files); refreshed once present
	lazy bool
	// as trivy keeps it (pkg/db, pkg/javadb): the DB file, the schema of the tag, the layer's media type, and how
	// long a download counts as fresh after DownloadedAt once NextUpdate has passed
	file      string
	schema    int
	mediaType string
	window    time.Duration
}

var dbKinds = []dbKind{
	{name: "db", flag: "--download-db-only", repoFlag: "--db-repository", trivyEnv: "TRIVY_DB_REPOSITORY",
		ourEnv: "KANAREIKA_TRIVY_DB_REPOS",
		repos: []string{"ghcr.io/aquasecurity/trivy-db:2", "mirror.gcr.io/aquasec/trivy-db:2",
			"public.ecr.aws/aquasecurity/trivy-db:2"},
		file: "trivy.db", schema: 2, mediaType: "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip", window: time.Hour},
	{name: "java-db", flag: "--download-java-db-only", repoFlag: "--java-db-repository", trivyEnv: "TRIVY_JAVA_DB_REPOSITORY",
		ourEnv: "KANAREIKA_TRIVY_JAVA_DB_REPOS",
		repos: []string{"ghcr.io/aquasecurity/trivy-java-db:1", "mirror.gcr.io/aquasec/trivy-java-db:1",
			"public.ecr.aws/aquasecurity/trivy-java-db:1"},
		lazy: true, file: "trivy-java.db", schema: 1, mediaType: "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip",
		window: 24 * time.Hour},
}

// dbTimeout: per download attempt. Passed to trivy as well: its own default (5m) is too short for a slow link.
var dbTimeout = 30 * time.Minute

// repositories to try for k, in order; nil = let trivy decide (its own TRIVY_*_REPOSITORY is set).
func (k dbKind) repositories() []string {
	if os.Getenv(k.trivyEnv) != "" {
		return nil
	}
	if v := os.Getenv(k.ourEnv); v != "" {
		var out []string
		for _, r := range strings.Split(v, ",") {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return k.repos
}

// CacheDir: trivy's cache dir, where its vulnerability DBs live ("" when there is no user cache dir).
func CacheDir() string { return trivyCacheDir() }

// trivyCacheDir: trivy's cache dir (TRIVY_CACHE_DIR, else <user cache dir>/trivy, as trivy itself picks it).
func trivyCacheDir() string {
	if d := os.Getenv("TRIVY_CACHE_DIR"); d != "" {
		return d
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "trivy")
}

// cachedAt: when the cached copy of k was downloaded; zero if there is none.
// nextUpdate: when trivy publishes the next build (metadata.json NextUpdate); zero when unknown.
func (k dbKind) nextUpdate() time.Time {
	dir := trivyCacheDir()
	if dir == "" {
		return time.Time{}
	}
	data, err := os.ReadFile(filepath.Join(dir, k.name, "metadata.json"))
	if err != nil {
		return time.Time{}
	}
	var m struct{ NextUpdate time.Time }
	_ = json.Unmarshal(data, &m)
	return m.NextUpdate
}

func (k dbKind) cachedAt() time.Time {
	dir := trivyCacheDir()
	if dir == "" {
		return time.Time{}
	}
	data, err := os.ReadFile(filepath.Join(dir, k.name, "metadata.json"))
	if err != nil {
		return time.Time{}
	}
	var m struct{ DownloadedAt, UpdatedAt time.Time }
	if json.Unmarshal(data, &m) != nil {
		return time.Time{}
	}
	if !m.UpdatedAt.IsZero() {
		return m.UpdatedAt
	}
	return m.DownloadedAt
}

// download k, trying each repository in turn; the errors of all attempts if none worked.
func (k dbKind) download(ctx context.Context, logf func(string, ...any)) error {
	args := []string{"image", k.flag, "--skip-version-check", "--no-progress", "--timeout", dbTimeout.String()}
	repos := k.repositories()
	if repos == nil {
		repos = []string{""} // trivy's own setting
	}
	var errs []string
	for _, repo := range repos {
		a := args
		where := k.trivyEnv
		if repo != "" {
			a = append(slices.Clone(args), k.repoFlag, repo)
			where = repo
		}
		_, stderr, err := command(ctx, dbTimeout+time.Minute, a...)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			err = errors.New(tail(strings.TrimSpace(stderr), 400))
		}
		errs = append(errs, fmt.Sprintf("%s: %v", where, err))
		if logf != nil {
			logf("trivy %s: %s failed, %d more to try", k.name, where, len(repos)-len(errs))
		}
	}
	return &Error{fmt.Sprintf("trivy %s: no repository worked:\n    %s", k.flag, strings.Join(errs, "\n    "))}
}

// Prepare downloads the vulnerability DBs once, before parallel scans start: concurrent first-time downloads from
// several trivy processes break each other. Later runs then skip the DB update. When no repository can be reached
// but a DB is already cached, the scan goes on with it and logf says how old it is; with nothing cached it fails.
func Prepare(ctx context.Context, logf func(string, ...any)) error {
	prepLog.Store(&logf)
	for _, k := range dbKinds {
		if k.lazy && k.cachedAt().IsZero() {
			continue // downloaded by the first run that needs it (Run)
		}
		err := k.fetch(ctx, nil, logf)
		if err == nil {
			continue
		}
		at := k.cachedAt()
		if at.IsZero() || ctx.Err() != nil {
			return err
		}
		if logf != nil {
			logf("WARNING: trivy %s not updated, using the cached copy from %s (%s old): %v",
				k.name, at.UTC().Format("2006-01-02 15:04Z"), time.Since(at).Round(time.Hour), err)
		}
	}
	prepared.Store(true)
	return nil
}

// ErrNoDB: offline and a vulnerability DB was never downloaded or imported.
var ErrNoDB = errors.New("no trivy vulnerability DB: run `kanareika db update` with network access, " +
	"or `kanareika db import <bundle>` with a bundle made by `kanareika db export`")

// OfflineMaxAge: an offline scan says out loud when a DB is older than this (trivy-db is rebuilt every 6 hours).
const OfflineMaxAge = 7 * 24 * time.Hour

// PrepareOffline: use the cached DBs as they are, without touching the network; ErrNoDB when one is missing.
func PrepareOffline(logf func(string, ...any)) error {
	for _, k := range dbKinds {
		at := k.cachedAt()
		if at.IsZero() && k.lazy {
			continue // offline: hosts with .jar files report the missing Java DB
		}
		if at.IsZero() {
			return fmt.Errorf("trivy %s: %w", k.name, ErrNoDB)
		}
		if logf != nil {
			age := time.Since(at)
			warn := ""
			if age > OfflineMaxAge {
				warn = "WARNING: "
			}
			logf("%strivy %s: offline, using the copy from %s (%s old)", warn, k.name, at.UTC().Format("2006-01-02 15:04Z"),
				age.Round(time.Hour))
			if warn != "" {
				logf("WARNING: vulnerabilities published since then are not found; bring a fresh bundle " +
					"(`kanareika db export` on a connected machine, `db import` here)")
			}
		}
	}
	prepared.Store(true)
	return nil
}

// DBInfo: one vulnerability DB in the cache.
type DBInfo struct {
	Name    string    `json:"name"`    // "db", "java-db"
	Dir     string    `json:"dir"`     // where it is (or would be)
	Updated time.Time `json:"updated"` // zero: not downloaded
	// Next: when the next build of this DB is published (trivy's metadata); after it, a newer one is out
	Next time.Time `json:"next_update"`
	// OnDemand: downloaded the first time a scan finds what needs it (the Java DB: .jar files), not before
	OnDemand bool `json:"on_demand,omitempty"`
}

// Outdated: a newer build has been published since this one (or there is none yet).
func (d DBInfo) Outdated(now time.Time) bool {
	if d.Updated.IsZero() {
		return !d.OnDemand // an on-demand DB not downloaded yet is fine: nothing has needed it
	}
	return !d.Next.IsZero() && now.After(d.Next)
}

// DBStatus: the cached DBs, in a fixed order.
func DBStatus() []DBInfo {
	out := make([]DBInfo, 0, len(dbKinds))
	for _, k := range dbKinds {
		dir := ""
		if c := trivyCacheDir(); c != "" {
			dir = filepath.Join(c, k.name)
		}
		out = append(out, DBInfo{Name: k.name, Dir: dir, Updated: k.cachedAt(), Next: k.nextUpdate(), OnDemand: k.lazy})
	}
	return out
}

// Run trivy with JSON output into output; the raw report is kept next to it as output.gz (raw trivy output
// carries full CVE descriptions — hundreds of MB per host) and returned to be read once (ReadReport): closing it
// removes the raw file. Nothing holds the report in memory.
func Run(ctx context.Context, args []string, output string, timeout time.Duration) (io.ReadCloser, error) {
	release, err := acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	cmd := append(slices.Clone(args), "--format", "json", "--output", output, "--skip-version-check")
	if prepared.Load() {
		cmd = append(cmd, "--skip-db-update", "--skip-java-db-update")
	}
	_, stderr, err := command(ctx, timeout, cmd...)
	if err != nil && prepared.Load() && strings.Contains(stderr, javaDBMissing) && fetchLazy(ctx) {
		_, stderr, err = command(ctx, timeout, cmd...) // the Java DB is there now
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		var lines []string
		for _, ln := range strings.Split(stderr, "\n") {
			if strings.Contains(ln, "FATAL") || strings.Contains(ln, "ERROR") {
				lines = append(lines, ln)
			}
		}
		msg := strings.Join(lines, "\n")
		if msg == "" {
			msg = stderr
		}
		if msg = tail(strings.TrimSpace(msg), 800); msg == "" {
			msg = fmt.Sprintf("exit %d", exit.ExitCode())
		}
		return nil, &Error{fmt.Sprintf("trivy %s: %s", strings.Join(args[:min(1, len(args))], " "), msg)}
	} else if err != nil {
		return nil, err
	}
	f, err := os.Open(output)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err == nil && st.Size() == 0 {
		f.Close()
		if err := gzipFile(output, strings.NewReader("{}")); err != nil {
			return nil, err
		}
		return Bytes([]byte("{}")), os.Remove(output)
	}
	if err == nil {
		err = gzipFile(output, f)
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return &rawReport{f}, nil
}

// rawReport: trivy's output file, removed when closed (output.gz stays).
type rawReport struct{ *os.File }

func (r *rawReport) Close() error {
	err := r.File.Close()
	if rerr := os.Remove(r.Name()); err == nil {
		err = rerr
	}
	return err
}

// Bytes: a report in memory, as Run returns one (tests, recorded reports).
func Bytes(b []byte) io.ReadCloser { return io.NopCloser(bytes.NewReader(b)) }

func gzipFile(path string, src io.Reader) error {
	f, err := os.Create(path + ".gz")
	if err != nil {
		return err
	}
	zw, _ := gzip.NewWriterLevel(f, 6)
	_, err = io.Copy(zw, src)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Version of the trivy kanareika runs, "?" when it can't be asked.
func Version(ctx context.Context) string {
	if os.Getenv("KANAREIKA_TRIVY") == "" {
		if v := Embedded(); v != "" {
			return v
		}
	}
	out, _, err := command(ctx, 30*time.Second, "--version", "--format", "json")
	if err != nil {
		return "?"
	}
	var v struct{ Version *string }
	if json.Unmarshal([]byte(out), &v) != nil {
		return "?"
	}
	if v.Version == nil {
		return "?"
	}
	return *v.Version
}

// --- reports ----------------------------------------------------------------------------------------------------------

// Report: the part of trivy JSON (fs/image/rootfs/sbom) kanareika reads.
type Report struct {
	Results []Result `json:"Results"`
}

type Result struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	PkgPath          string   `json:"PkgPath"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Status           string   `json:"Status"`
	Severity         *string  `json:"Severity"` // absent = UNKNOWN
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	PrimaryURL       string   `json:"PrimaryURL"`
	CweIDs           []string `json:"CweIDs"`
	CVSS             CVSS     `json:"CVSS"`
	PublishedDate    string   `json:"PublishedDate,omitempty"`
}

// CVSS: source -> vectors, in the report's order (the fallback source is the first one listed).
type CVSS struct {
	Sources []string
	Vectors map[string]Vectors
}

type Vectors struct {
	V3Vector  string  `json:"V3Vector"`
	V40Vector string  `json:"V40Vector"`
	V3Score   float64 `json:"V3Score,omitempty"`
	V40Score  float64 `json:"V40Score,omitempty"`
}

func (c *CVSS) UnmarshalJSON(b []byte) error {
	*c = CVSS{Vectors: map[string]Vectors{}}
	dec := json.NewDecoder(bytes.NewReader(b))
	t, err := dec.Token()
	if err != nil || t == nil {
		return err // null
	}
	if t != json.Delim('{') {
		return fmt.Errorf("CVSS: object expected")
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return err
		}
		var v Vectors
		if err := dec.Decode(&v); err != nil {
			return err
		}
		key := k.(string)
		if _, dup := c.Vectors[key]; !dup {
			c.Sources = append(c.Sources, key)
		}
		c.Vectors[key] = v
	}
	return nil
}

func (c CVSS) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range c.Sources {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(c.Vectors[k])
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func ParseReport(data []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("trivy report: %w", err)
	}
	return &r, nil
}

// ReadReport reads a trivy report (fs / image / rootfs / sbom JSON) one vulnerability at a time: fn gets each with
// its result's target (v is reused: fn copies what it keeps), its strings interned in strs (nil: a new set).
// meta, when not nil, gets the report's Metadata.
func ReadReport(r io.Reader, strs jsonx.Strings, meta any, fn func(target string, v *Vulnerability)) error {
	if strs == nil {
		strs = jsonx.Strings{}
	}
	opts := jsonv2.JoinOptions(json.DefaultOptionsV1(), strs.Unmarshalers())
	dec := jsontext.NewDecoder(r, opts)
	err := readReport(dec, opts, meta, fn)
	if err != nil {
		return fmt.Errorf("trivy report: %w", err)
	}
	return nil
}

func readReport(dec *jsontext.Decoder, opts jsonv2.Options, meta any, fn func(string, *Vulnerability)) error {
	return readObject(dec, func(key string) error {
		switch {
		case strings.EqualFold(key, "Results"):
			return readArray(dec, func() error { return readResult(dec, opts, fn) })
		case strings.EqualFold(key, "Metadata") && meta != nil:
			return jsonv2.UnmarshalDecode(dec, meta, opts)
		}
		return dec.SkipValue()
	})
}

// readResult: one of Results; its vulnerabilities are read before its target only when the report lists them
// first (trivy does not), and then kept as JSON until the target comes.
func readResult(dec *jsontext.Decoder, opts jsonv2.Options, fn func(string, *Vulnerability)) error {
	var target string
	var early jsontext.Value
	var v Vulnerability
	vulns := func(d *jsontext.Decoder) error {
		return readArray(d, func() error {
			v = Vulnerability{}
			if err := jsonv2.UnmarshalDecode(d, &v, opts); err != nil {
				return err
			}
			fn(target, &v)
			return nil
		})
	}
	seenTarget := false
	err := readObject(dec, func(key string) error {
		switch {
		case strings.EqualFold(key, "Target"):
			seenTarget = true
			return jsonv2.UnmarshalDecode(dec, &target, opts)
		case strings.EqualFold(key, "Vulnerabilities"):
			if seenTarget {
				return vulns(dec)
			}
			val, err := dec.ReadValue()
			early = slices.Clone(val)
			return err
		}
		return dec.SkipValue()
	})
	if err != nil || early == nil {
		return err
	}
	return vulns(jsontext.NewDecoder(bytes.NewReader(early), opts))
}

// readObject calls member for each member of the object (or null) next in dec, positioned at its value.
func readObject(dec *jsontext.Decoder, member func(key string) error) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	switch tok.Kind() {
	case 'n':
		return nil
	case '{':
	default:
		return fmt.Errorf("object expected, got %v", tok.Kind())
	}
	for dec.PeekKind() != '}' {
		k, err := dec.ReadToken()
		if err != nil {
			return err
		}
		if err := member(k.String()); err != nil {
			return err
		}
	}
	_, err = dec.ReadToken()
	return err
}

// readArray calls elem for each element of the array (or null) next in dec, positioned at it.
func readArray(dec *jsontext.Decoder, elem func() error) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	switch tok.Kind() {
	case 'n':
		return nil
	case '[':
	default:
		return fmt.Errorf("array expected, got %v", tok.Kind())
	}
	for dec.PeekKind() != ']' {
		if dec.PeekKind() == 0 {
			_, err := dec.ReadToken()
			return err
		}
		if err := elem(); err != nil {
			return err
		}
	}
	_, err = dec.ReadToken()
	return err
}

// rceCWEs: weakness types that typically end in code execution.
var rceCWEs = map[string]bool{"CWE-94": true, "CWE-77": true, "CWE-78": true, "CWE-95": true, "CWE-96": true,
	"CWE-502": true, "CWE-787": true, "CWE-788": true, "CWE-416": true, "CWE-415": true, "CWE-119": true,
	"CWE-120": true, "CWE-121": true, "CWE-122": true, "CWE-134": true, "CWE-190": true, "CWE-843": true,
	"CWE-434": true, "CWE-1321": true}

var rceText = []string{"remote code execution", "arbitrary code", "execute code", "code execution",
	"command injection", " rce"}

func vector(v Vulnerability) string {
	for _, src := range append([]string{"nvd", "redhat", "ghsa", "ubuntu"}, v.CVSS.Sources...) {
		s := v.CVSS.Vectors[src]
		if s.V3Vector != "" {
			return s.V3Vector
		}
		if s.V40Vector != "" {
			return s.V40Vector
		}
	}
	return ""
}

// score: the base score of the vector vector() picks (same sources, same order); nil when there is none.
func score(v Vulnerability) *float64 {
	for _, src := range append([]string{"nvd", "redhat", "ghsa", "ubuntu"}, v.CVSS.Sources...) {
		s := v.CVSS.Vectors[src]
		if s.V3Vector != "" {
			if s.V3Score > 0 {
				return &s.V3Score
			}
			return nil
		}
		if s.V40Vector != "" {
			if s.V40Score > 0 {
				return &s.V40Score
			}
			return nil
		}
	}
	return nil
}

// maxDescription: runes of an advisory's description kept in a finding (the rest is on the advisory page).
const maxDescription = 600

func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return strings.TrimSpace(string([]rune(s)[:n-1])) + "…"
}

type Class struct {
	Vector  string `json:"vector"`
	Preauth bool   `json:"preauth"`
	RCE     bool   `json:"rce"`
}

// Classify: pre-auth = network-reachable, no privileges, no user interaction (CVSS AV:N/PR:N/UI:N); rce = the
// weakness or the description says code execution.
func Classify(v Vulnerability) Class {
	vec := vector(v)
	parts := map[string]string{}
	for _, p := range strings.Split(vec, "/") {
		if k, val, ok := strings.Cut(p, ":"); ok {
			parts[k] = val
		}
	}
	preauth := parts["AV"] == "N" && parts["PR"] == "N" && parts["UI"] == "N" && vec != ""
	desc := v.Description
	if utf8.RuneCountInString(desc) > 600 {
		desc = string([]rune(desc)[:600])
	}
	text := strings.ToLower(" " + v.Title + " " + desc)
	// code execution = full confidentiality AND integrity impact, plus a code-exec weakness or wording;
	// "crafted file -> crash" style CVEs (only A:H) stay out
	full := parts["C"] == "H" && parts["I"] == "H"
	rce := full && (slices.ContainsFunc(v.CweIDs, func(c string) bool { return rceCWEs[c] }) ||
		slices.ContainsFunc(rceText, func(t string) bool { return strings.Contains(text, t) }))
	return Class{Vector: vec, Preauth: preauth, RCE: rce}
}

// VulnFindings flattens Results[].Vulnerabilities into findings on top of base (where + module; base.Target, when
// set, replaces the result's target, e.g. "os" or "image:<ref>").
func VulnFindings(r *Report, base finding.Finding) []finding.Finding {
	var out []finding.Finding
	d := newDeriver(nil)
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			out = append(out, d.finding(base, res.Target, &v))
		}
	}
	return out
}

// ReadFindings: VulnFindings of the report in r, read one vulnerability at a time (see ReadReport).
func ReadFindings(r io.Reader, base finding.Finding, meta any) ([]finding.Finding, error) {
	var out []finding.Finding
	err := EachFinding(r, base, meta, func(f *finding.Finding) { out = append(out, *f) })
	return slices.Clip(out), err
}

// EachFinding: the findings of ReadFindings, one at a time (f is reused: fn copies what it keeps).
func EachFinding(r io.Reader, base finding.Finding, meta any, fn func(f *finding.Finding)) error {
	strs := jsonx.Strings{}
	d := newDeriver(strs)
	var f finding.Finding
	return ReadReport(r, strs, meta, func(target string, v *Vulnerability) {
		f = d.finding(base, target, v)
		fn(&f)
	})
}

// deriver makes findings of vulnerabilities. What a finding derives from the advisory (class, shortened
// description, score) is the same for every package a CVE is listed on: worked out once per CVE (a kernel CVE
// comes once per kernel package), its strings shared.
type deriver struct {
	strs jsonx.Strings
	seen map[string]*derived
}

type derived struct {
	title, desc string // what it was derived from
	cwes        []string
	cvss        *CVSS
	class       Class
	short, pub  string
	score       *float64
}

func newDeriver(strs jsonx.Strings) *deriver {
	if strs == nil {
		strs = jsonx.Strings{}
	}
	return &deriver{strs: strs, seen: map[string]*derived{}}
}

func (d *deriver) derive(v *Vulnerability) *derived {
	if x := d.seen[v.VulnerabilityID]; x != nil && x.title == v.Title && x.desc == v.Description &&
		slices.Equal(x.cwes, v.CweIDs) && sameCVSS(x.cvss, &v.CVSS) {
		return x
	}
	c := Classify(*v)
	c.Vector = d.strs.Intern(c.Vector)
	x := &derived{title: v.Title, desc: v.Description, cwes: slices.Clone(v.CweIDs), cvss: &v.CVSS, class: c,
		short: d.strs.Intern(shorten(v.Description, maxDescription)), score: score(*v)}
	if len(v.PublishedDate) >= 10 {
		x.pub = d.strs.Intern(v.PublishedDate[:10])
	}
	cv := v.CVSS // v is reused by the reader: keep a copy of what is compared
	x.cvss = &cv
	d.seen[v.VulnerabilityID] = x
	return x
}

func sameCVSS(a, b *CVSS) bool {
	return slices.Equal(a.Sources, b.Sources) && maps.Equal(a.Vectors, b.Vectors)
}

// finding: one vulnerability as a finding.
func (d *deriver) finding(base finding.Finding, target string, v *Vulnerability) finding.Finding {
	f := base
	f.Kind, f.ID, f.Pkg, f.PkgPath = finding.Vuln, v.VulnerabilityID, v.PkgName, v.PkgPath
	f.Installed, f.Fixed, f.Status = v.InstalledVersion, v.FixedVersion, v.Status
	f.Severity = "UNKNOWN"
	if v.Severity != nil {
		f.Severity = *v.Severity
	}
	f.Title, f.URL = v.Title, v.PrimaryURL
	if f.Target == "" {
		f.Target = target
	}
	x := d.derive(v)
	f.Vector, f.Preauth, f.RCE = x.class.Vector, x.class.Preauth, x.class.RCE
	f.CVSSScore, f.Description, f.Published = x.score, x.short, x.pub
	return f
}

// javaDBMissing: trivy's words when it met .jar files and the Java DB is not downloaded (--skip-java-db-update).
const javaDBMissing = "Unable to initialize the Java DB"

var (
	lazyMu  sync.Mutex
	prepLog atomic.Pointer[func(string, ...any)]
)

// DownloadOnDemand: the on-demand DBs (the Java DB) now, for a bundle carried to an isolated network or a fleet
// known to run Java; a normal scan gets them by itself when it finds .jar files.
func DownloadOnDemand(ctx context.Context, logf func(string, ...any)) error {
	for _, k := range dbKinds {
		if k.lazy {
			if err := k.fetch(ctx, nil, logf); err != nil {
				return err
			}
		}
	}
	return nil
}

// fetchLazy downloads the on-demand DBs that are missing, once for all parallel runs; true when they are there.
func fetchLazy(ctx context.Context) bool {
	lazyMu.Lock()
	defer lazyMu.Unlock()
	var logf func(string, ...any)
	if p := prepLog.Load(); p != nil {
		logf = *p
	}
	ok := true
	for _, k := range dbKinds {
		if !k.lazy || !k.cachedAt().IsZero() {
			continue
		}
		if logf != nil {
			logf("trivy %s: found .jar files, downloading the Java DB once (about 1 GB)", k.name)
		}
		if err := k.fetch(ctx, nil, logf); err != nil {
			if logf != nil {
				logf("WARNING: trivy %s: %v", k.name, err)
			}
			ok = false
		}
	}
	return ok
}
