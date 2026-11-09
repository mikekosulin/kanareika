// Package report stores runs (reports/<org>/<env>/<run>/), builds what the dashboard shows (view.json), the
// patch-plan summary (summary.md), history and diffs between runs, and the merged current state (current/).
//
// The files are shared with the Python implementation and with runs written by earlier versions: same keys, same
// nesting, same list order.
package report

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

// Current is reports/<org>/<env>/current: the merged latest state per host and module.
const Current = "current"

func EnvDir(p config.Paths, org, env string) string { return filepath.Join(p.Reports, org, env) }

// Busy: another process holds the environment's lock (a scan is running).
type Busy struct{ Env string }

func (e *Busy) Error() string { return "a scan is already running in " + e.Env }

// Lock is a flock on reports/<org>/<env>/.lock: one scan per environment, and the current-state merge never
// races a scan (the dashboard waits; a second scan refuses).
type Lock struct{ f *os.File }

// flock, rename and policy are seams for tests: failures that real files cannot produce.
var (
	flock  = lockFile
	rename = os.Rename
	policy = config.Policy
)

// EnvLock takes the lock; wait=false returns *Busy instead of blocking.
func EnvLock(env string, wait bool) (*Lock, error) {
	if err := os.MkdirAll(env, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(env, ".lock"), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	busy, err := flock(f, wait)
	if err != nil || busy {
		f.Close()
		if busy {
			return nil, &Busy{Env: env}
		}
		return nil, err
	}
	return &Lock{f: f}, nil
}

func (l *Lock) Unlock() error {
	_ = unlockFile(l.f)
	return l.f.Close()
}

// runDirs: finished runs (with run.json) in env, oldest first; current/ is not a run.
func runDirs(env string) []string {
	ents, err := os.ReadDir(env)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents { // ReadDir sorts by name, as Python's sorted(iterdir())
		if e.IsDir() && e.Name() != Current && exists(filepath.Join(env, e.Name(), "run.json")) {
			out = append(out, filepath.Join(env, e.Name()))
		}
	}
	return out
}

// Runs: run directories of an environment, oldest first.
func Runs(p config.Paths, org, env string) []string { return runDirs(EnvDir(p, org, env)) }

// LoadFindings reads findings.json.gz (or findings.json of older runs); none = empty.
func LoadFindings(dir string) ([]finding.Finding, error) {
	var r io.Reader
	if f, err := os.Open(filepath.Join(dir, "findings.json.gz")); err == nil {
		defer f.Close()
		gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
		if err != nil {
			return nil, err
		}
		r = gz
	} else if f, err := os.Open(filepath.Join(dir, "findings.json")); err == nil {
		defer f.Close()
		r = bufio.NewReaderSize(f, 1<<20)
	} else {
		return []finding.Finding{}, nil
	}
	out := []finding.Finding{}
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	for i := range out {
		upgradeDenied(&out[i])
	}
	return out, nil
}

// upgradeDenied: runs before 0.5 stored what a module could not read as raw keys in one text ("cannot read:
// denied.shadow, denied.keys (needs root or sudo)"); they read in plain words now, as new runs write them.
func upgradeDenied(f *finding.Finding) {
	what, ok := f.Args["what"].(string)
	if f.Msg != "health.limited" || !ok {
		return
	}
	var keys []string
	for _, k := range strings.Split(what, ", ") {
		if strings.HasPrefix(k, "denied.") {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return
	}
	t := i18n.Msg("denied.title", map[string]any{"what_keys": keys})
	f.Title, f.Msg, f.Args = t.Text, t.Key, t.Args
}

func LoadMeta(dir string) (*Meta, error) {
	b, err := os.ReadFile(filepath.Join(dir, "run.json"))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s/run.json: %w", dir, err)
	}
	return &m, nil
}

func LoadRun(dir string) (*Meta, []finding.Finding, error) {
	m, err := LoadMeta(dir)
	if err != nil {
		return nil, nil, err
	}
	fs, err := LoadFindings(dir)
	return m, fs, err
}

// IsPartial: a run limited to some hosts, groups or modules (statistics compare full runs only).
func IsPartial(m *Meta) bool {
	s := m.Selection
	return len(s.Hosts) > 0 || len(s.Groups) > 0 || len(s.Modules) > 0
}

func isPartialDir(dir string) (bool, error) {
	m, err := LoadMeta(dir)
	if err != nil {
		return false, err
	}
	return IsPartial(m), nil
}

// PreviousRun: the latest finished run before runDir (fullOnly: the latest full one); nil when there is none.
func PreviousRun(runDir string, fullOnly bool) (*Prev, error) {
	var done []string
	for _, d := range runDirs(filepath.Dir(runDir)) {
		if filepath.Base(d) < filepath.Base(runDir) {
			done = append(done, d)
		}
	}
	if fullOnly {
		var full []string
		for _, d := range done {
			p, err := isPartialDir(d)
			if err != nil {
				return nil, err
			}
			if !p {
				full = append(full, d)
			}
		}
		done = full
	}
	if len(done) == 0 {
		return nil, nil
	}
	return loadPrev(done[len(done)-1])
}

func loadPrev(dir string) (*Prev, error) {
	m, fs, err := LoadRun(dir)
	if err != nil {
		return nil, err
	}
	return &Prev{ID: filepath.Base(dir), Meta: m, Findings: fs}, nil
}

// SaveRun writes a finished run: findings, run.json (with counts), view.json and summary.md.
func SaveRun(runDir string, meta *Meta, findings []finding.Finding) error {
	if err := writeFindings(runDir, findings); err != nil {
		return err
	}
	c := CountsOf(findings)
	meta.Counts = c.Map()
	var prev *Prev
	if !IsPartial(meta) { // statistics compare FULL runs only; a partial run has nothing comparable
		var err error
		if prev, err = PreviousRun(runDir, true); err != nil {
			return err
		}
	}
	view := BuildView(runDir, meta, findings, prev)
	meta.PlanCounts = &view.PlanCounts
	meta.Totals = &view.Totals
	if err := writeMeta(runDir, meta); err != nil {
		return err
	}
	if err := WriteView(runDir, view); err != nil {
		return err
	}
	if err := WriteSummary(runDir, meta, findings); err != nil {
		return err
	}
	return nil
}

func writeFindings(dir string, findings []finding.Finding) error {
	if findings == nil {
		findings = []finding.Finding{}
	}
	return writeAtomic(filepath.Join(dir, "findings.json.gz"), func(w io.Writer) error {
		gz, _ := gzip.NewWriterLevel(w, 6)
		e := json.NewEncoder(gz)
		e.SetEscapeHTML(false)
		if err := e.Encode(findings); err != nil {
			return err
		}
		return gz.Close()
	})
}

// writeMeta: run.json indented by one space, like Python's json.dumps(indent=1).
func writeMeta(dir string, m *Meta) error {
	b, err := pyfmt.MarshalIndent(m)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "run.json"), func(w io.Writer) error { _, err := w.Write(b); return err })
}

// WriteView writes view.json (also used by the dashboard when it rebuilds the view of an old run).
func WriteView(dir string, v *View) error {
	b, err := pyfmt.Marshal(v)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "view.json"), func(w io.Writer) error { _, err := w.Write(b); return err })
}

// WriteMeta writes run.json (the dashboard adds plan_counts to old runs).
func WriteMeta(dir string, m *Meta) error { return writeMeta(dir, m) }

// writeAtomic: readers (the dashboard) never see a half-written file.
func writeAtomic(path string, write func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(tmp, 1<<20)
	if err = write(w); err == nil {
		err = w.Flush()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err == nil {
		err = rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// HistoryTable: the runs of an environment, one line each (CLI `history`).
func HistoryTable(p config.Paths, org, env string) (string, error) {
	rows := []string{"run                   hosts  fail   P1    P2    P3    P4  accepted  scope", strings.Repeat("-", 90)}
	for _, r := range Runs(p, org, env) {
		m, err := LoadMeta(r)
		if err != nil {
			return "", err
		}
		c := m.Counts
		scope := strings.Join(m.Selection.Hosts, ",")
		if scope == "" {
			scope = "all"
		}
		row := fmt.Sprintf("%-20s %6d %5d ", m.RunID, m.HostsOK, m.HostsFailed.Len())
		var ps []string
		for _, pr := range Prios {
			ps = append(ps, fmt.Sprintf("%5d", c[pr]))
		}
		rows = append(rows, row+strings.Join(ps, " ")+fmt.Sprintf(" %9d  %s", c["accepted"], pyfmt.Head(scope, 30)))
	}
	return strings.Join(rows, "\n"), nil
}

// --- retention ---------------------------------------------------------------------------------------------------

// KeepDefault: take the number from policy/settings.yml (retention), or the built-in default.
const KeepDefault = -1

func retention(p config.Paths) (keepFull, keepPartial int) {
	keepFull, keepPartial = 12, 30
	b, err := policy(p, "settings.yml")
	if err != nil {
		return
	}
	v, err := config.YAML(b)
	if err != nil {
		return
	}
	root, _ := v.(map[string]any)
	r, _ := root["retention"].(map[string]any)
	if n, ok := r["keep_full"].(float64); ok {
		keepFull = int(n)
	}
	if n, ok := r["keep_partial"].(float64); ok {
		keepPartial = int(n)
	}
	return
}

// Prune drops old runs: keeps the last keepFull full and keepPartial partial runs (current/ holds the merged
// state anyway), plus leftovers of interrupted runs (no run.json) older than a day. Returns the dropped names.
func Prune(p config.Paths, env string, keepFull, keepPartial int, dryRun bool) ([]string, error) {
	defFull, defPartial := retention(p)
	if keepFull < 0 {
		keepFull = defFull
	}
	if keepPartial < 0 {
		keepPartial = defPartial
	}
	ents, err := os.ReadDir(env)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	var full, part, broken []string
	now := time.Now()
	for _, e := range ents {
		name := e.Name()
		if !e.IsDir() || name == Current || strings.HasPrefix(name, ".") {
			continue
		}
		d := filepath.Join(env, name)
		if !exists(filepath.Join(d, "run.json")) {
			running := false
			if st, err := os.Stat(filepath.Join(d, "status.json")); err == nil {
				running = now.Sub(st.ModTime()) < 120*time.Second
			}
			if st, err := os.Stat(d); err == nil && !running && now.Sub(st.ModTime()) > 24*time.Hour {
				broken = append(broken, d)
			}
			continue
		}
		partial, err := isPartialDir(d)
		if err != nil {
			return nil, err
		}
		if partial {
			part = append(part, d)
		} else {
			full = append(full, d)
		}
	}
	drop := slices.Concat(broken, full[:max(0, len(full)-keepFull)], part[:max(0, len(part)-keepPartial)])
	names := []string{}
	for _, d := range drop {
		if !dryRun {
			_ = os.RemoveAll(d)
		}
		names = append(names, filepath.Base(d))
	}
	return names, nil
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

// PrevIndex: the env's current state (reports/<org>/<env>/current) by finding key, for the due date's clock
// (priority.Prev). Findings saved before 0.5 have no first_seen: they get the date of the oldest kept run that
// has them (and fix_since of the oldest that had an installable fix), so upgrading does not restart every clock.
func PrevIndex(env string) (func(*finding.Finding) *finding.Finding, error) {
	cur := filepath.Join(env, Current)
	idx := map[Key]*finding.Finding{}
	if exists(filepath.Join(cur, "findings.json.gz")) {
		fs, err := LoadFindings(cur)
		if err != nil {
			return nil, err
		}
		for i := range fs {
			idx[KeyOf(&fs[i])] = &fs[i]
		}
	}
	missing := 0
	for _, f := range idx {
		if f.FirstSeen == "" {
			missing++
		}
	}
	if missing > 0 {
		for _, run := range runDirs(env) { // oldest first
			day := filepath.Base(run)
			if len(day) < 10 {
				continue
			}
			day = day[:10]
			fs, err := LoadFindings(run)
			if err != nil {
				continue // a damaged old run: the clock starts later, nothing else depends on it
			}
			for i := range fs {
				f := idx[KeyOf(&fs[i])]
				if f == nil {
					continue
				}
				if f.FirstSeen == "" || day < f.FirstSeen {
					f.FirstSeen = day
				}
				installable := fs[i].FixState == finding.FixAvailable || fs[i].FixState == finding.FixReboot ||
					(fs[i].FixState == "" && fs[i].Fixed != "")
				if installable && (f.FixSince == "" || day < f.FixSince) {
					f.FixSince = day
				}
			}
		}
	}
	return func(f *finding.Finding) *finding.Finding { return idx[KeyOf(f)] }, nil
}
