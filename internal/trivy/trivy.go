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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/mikekosulin/kanareika/internal/finding"
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

func command(ctx context.Context, timeout time.Duration, args ...string) (stdout, stderr string, err error) {
	bin, prefix, err := Binary()
	if err != nil {
		return "", "", err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append(prefix, args...)...)
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
}

var dbKinds = []dbKind{
	{"db", "--download-db-only", "--db-repository", "TRIVY_DB_REPOSITORY", "KANAREIKA_TRIVY_DB_REPOS",
		[]string{"ghcr.io/aquasecurity/trivy-db:2", "mirror.gcr.io/aquasec/trivy-db:2", "public.ecr.aws/aquasecurity/trivy-db:2"}},
	{"java-db", "--download-java-db-only", "--java-db-repository", "TRIVY_JAVA_DB_REPOSITORY", "KANAREIKA_TRIVY_JAVA_DB_REPOS",
		[]string{"ghcr.io/aquasecurity/trivy-java-db:1", "mirror.gcr.io/aquasec/trivy-java-db:1", "public.ecr.aws/aquasecurity/trivy-java-db:1"}},
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
	for _, k := range dbKinds {
		err := k.download(ctx, logf)
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

// PrepareOffline: use the cached DBs as they are, without touching the network; ErrNoDB when one is missing.
func PrepareOffline(logf func(string, ...any)) error {
	for _, k := range dbKinds {
		at := k.cachedAt()
		if at.IsZero() {
			return fmt.Errorf("trivy %s: %w", k.name, ErrNoDB)
		}
		if logf != nil {
			logf("trivy %s: offline, using the copy from %s (%s old)", k.name, at.UTC().Format("2006-01-02 15:04Z"),
				time.Since(at).Round(time.Hour))
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
}

// DBStatus: the cached DBs, in a fixed order.
func DBStatus() []DBInfo {
	out := make([]DBInfo, 0, len(dbKinds))
	for _, k := range dbKinds {
		dir := ""
		if c := trivyCacheDir(); c != "" {
			dir = filepath.Join(c, k.name)
		}
		out = append(out, DBInfo{Name: k.name, Dir: dir, Updated: k.cachedAt()})
	}
	return out
}

// Run trivy with JSON output into output; the raw report is kept next to it as output.gz (raw trivy output
// carries full CVE descriptions — hundreds of MB per host) and returned.
func Run(ctx context.Context, args []string, output string, timeout time.Duration) ([]byte, error) {
	cmd := append(slices.Clone(args), "--format", "json", "--output", output, "--skip-version-check")
	if prepared.Load() {
		cmd = append(cmd, "--skip-db-update", "--skip-java-db-update")
	}
	_, stderr, err := command(ctx, timeout, cmd...)
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
	data, err := os.ReadFile(output)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		data = []byte("{}")
	}
	if err := gzipFile(output, data); err != nil {
		return nil, err
	}
	return data, os.Remove(output)
}

func gzipFile(path string, data []byte) error {
	f, err := os.Create(path + ".gz")
	if err != nil {
		return err
	}
	zw, _ := gzip.NewWriterLevel(f, 6)
	_, err = zw.Write(data)
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
}

// CVSS: source -> vectors, in the report's order (the fallback source is the first one listed).
type CVSS struct {
	Sources []string
	Vectors map[string]Vectors
}

type Vectors struct {
	V3Vector  string `json:"V3Vector"`
	V40Vector string `json:"V40Vector"`
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
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			f := base
			f.Kind, f.ID, f.Pkg, f.PkgPath = finding.Vuln, v.VulnerabilityID, v.PkgName, v.PkgPath
			f.Installed, f.Fixed, f.Status = v.InstalledVersion, v.FixedVersion, v.Status
			f.Severity = "UNKNOWN"
			if v.Severity != nil {
				f.Severity = *v.Severity
			}
			f.Title, f.URL = v.Title, v.PrimaryURL
			if f.Target == "" {
				f.Target = res.Target
			}
			c := Classify(v)
			f.Vector, f.Preauth, f.RCE = c.Vector, c.Preauth, c.RCE
			out = append(out, f)
		}
	}
	return out
}
