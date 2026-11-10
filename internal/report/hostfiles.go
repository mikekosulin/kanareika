package report

import (
	"bufio"
	"compress/gzip"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// Findings are stored per host: <dir>/hosts/<host>/findings.json.gz, one JSON array each (the format of the
// former single file), the org-level findings (external:<target>, k8s:<cluster>) in hosts/@org. Nothing ever needs
// a whole environment's findings at once: a scan writes each host's file when the host is done, current/ takes a
// host's file from the run that scanned it, and every aggregate is built one host at a time.
//
// Runs written before 0.6 hold one findings.json.gz (or findings.json) for the whole environment. They stay
// readable as they are; MigrateEnv splits them (a scan does it under the environment's lock).

// OrgHost: the file of the org-level findings; never a host name (config names have no "@").
const OrgHost = "@org"

const hostFindings = "findings.json.gz"

// HostFile: one findings file of a run or of current/.
type HostFile struct {
	Host string // "" for the single file of a run written before 0.6
	Path string
}

// FileHost: the host file a finding is stored in.
func FileHost(f *finding.Finding) string {
	if strings.Contains(f.Host, ":") {
		return OrgHost
	}
	return f.Host
}

// hostFindingsPath: where dir keeps host's findings.
func hostFindingsPath(dir, host string) string {
	return filepath.Join(dir, "hosts", host, hostFindings)
}

// legacyFile: the single findings file of a run written before 0.6; "" when there is none. While it is there it
// is what dir holds: host files beside it are left over from an interrupted split.
func legacyFile(dir string) string {
	for _, name := range []string{"findings.json.gz", "findings.json"} {
		if p := filepath.Join(dir, name); isFile(p) {
			return p
		}
	}
	return ""
}

// HostFiles: the findings files of dir (a run or current/), sorted by host. A dir written before 0.6 and not split
// yet (see MigrateEnv) gives its single file as one entry with Host ""; none: nil.
func HostFiles(dir string) ([]HostFile, error) {
	if p := legacyFile(dir); p != "" {
		return []HostFile{{Path: p}}, nil
	}
	ents, err := os.ReadDir(filepath.Join(dir, "hosts"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []HostFile
	for _, e := range ents { // sorted by name
		if p := hostFindingsPath(dir, e.Name()); e.IsDir() && exists(p) {
			out = append(out, HostFile{Host: e.Name(), Path: p})
		}
	}
	return out, nil
}

// EachFindingIn calls fn with every finding of one findings file (a host's, or the single file of an older run);
// f is reused, so fn copies what it keeps.
func EachFindingIn(path string, fn func(f *finding.Finding)) error {
	r, closeFn, err := openPath(path)
	if err != nil {
		return err
	}
	defer closeFn()
	if err := eachFinding(r, fn); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// eachHostFinding: the findings of one host of dir, from its file, or filtered out of the single file of an older
// run (read whole for each host: slow, never large).
func eachHostFinding(dir, host string, fn func(f *finding.Finding)) error {
	if p := legacyFile(dir); p != "" {
		return EachFindingIn(p, func(f *finding.Finding) {
			if FileHost(f) == host {
				fn(f)
			}
		})
	}
	p := hostFindingsPath(dir, host)
	if !exists(p) {
		return nil
	}
	return EachFindingIn(p, fn)
}

// openPath opens a findings file, gunzipping a .gz one.
func openPath(path string) (io.Reader, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	br := bufio.NewReaderSize(f, 256<<10)
	if !strings.HasSuffix(path, ".gz") {
		return br, func() { f.Close() }, nil
	}
	gz, err := gzip.NewReader(br)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return gz, func() { f.Close() }, nil
}

// findingsWriter writes one findings file a finding at a time; Commit puts it in place atomically, Abort drops it.
type findingsWriter struct {
	path string
	tmp  *os.File
	bw   *bufio.Writer
	gz   *gzip.Writer
	enc  *jsontext.Encoder
	n    int
}

func newFindingsWriter(path string) (*findingsWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return nil, err
	}
	w := &findingsWriter{path: path, tmp: tmp, bw: bufio.NewWriterSize(tmp, 256<<10)}
	w.gz, _ = gzip.NewWriterLevel(w.bw, 6)
	w.enc = jsontext.NewEncoder(w.gz, jsonv1.DefaultOptionsV1(), jsontext.EscapeForHTML(false))
	if err := w.enc.WriteToken(jsontext.BeginArray); err != nil {
		w.Abort()
		return nil, err
	}
	return w, nil
}

func (w *findingsWriter) Add(f *finding.Finding) error {
	w.n++
	return json.MarshalEncode(w.enc, f)
}

func (w *findingsWriter) Commit() error {
	err := w.enc.WriteToken(jsontext.EndArray)
	if err == nil {
		err = w.gz.Close()
	}
	if err == nil {
		err = w.bw.Flush()
	}
	if cerr := w.tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(w.tmp.Name(), 0o644)
	}
	if err == nil {
		err = rename(w.tmp.Name(), w.path)
	}
	if err != nil {
		os.Remove(w.tmp.Name())
	}
	return err
}

func (w *findingsWriter) Abort() {
	w.tmp.Close()
	os.Remove(w.tmp.Name())
}

// WriteHostFindings writes the findings of one host of dir (a run or current/).
func WriteHostFindings(dir, host string, findings []finding.Finding) error {
	w, err := newFindingsWriter(hostFindingsPath(dir, host))
	if err != nil {
		return err
	}
	for i := range findings {
		if err := w.Add(&findings[i]); err != nil {
			w.Abort()
			return err
		}
	}
	if err := w.Commit(); err != nil {
		return err
	}
	return nil
}

// WriteFindingsFile writes findings as one findings file at path (read back with EachFindingIn): what a scan keeps
// on disk instead of in memory, such as an image's findings shared by the hosts that run it.
func WriteFindingsFile(path string, findings []finding.Finding) error {
	w, err := newFindingsWriter(path)
	if err != nil {
		return err
	}
	for i := range findings {
		if err := w.Add(&findings[i]); err != nil {
			w.Abort()
			return err
		}
	}
	return w.Commit()
}

// HostWriter writes one host's findings file a finding at a time (a scan streams each host's findings into it).
type HostWriter struct {
	dir, host string
	w         *findingsWriter
}

// NewHostWriter starts dir's findings file of host; nothing is in place before Commit.
func NewHostWriter(dir, host string) (*HostWriter, error) {
	w, err := newFindingsWriter(hostFindingsPath(dir, host))
	if err != nil {
		return nil, err
	}
	return &HostWriter{dir: dir, host: host, w: w}, nil
}

func (h *HostWriter) Add(f *finding.Finding) error { return h.w.Add(f) }

// Len: the findings added so far.
func (h *HostWriter) Len() int { return h.w.n }

// Commit puts the file in place.
func (h *HostWriter) Commit() error {
	if err := h.w.Commit(); err != nil {
		return err
	}
	return nil
}

func (h *HostWriter) Abort() { h.w.Abort() }

// writeFindings stores findings of any hosts in dir, one file per host (in the order they come).
func writeFindings(dir string, findings []finding.Finding) error {
	by := map[string][]finding.Finding{}
	var order []string
	for i := range findings {
		h := FileHost(&findings[i])
		if _, ok := by[h]; !ok {
			order = append(order, h)
		}
		by[h] = append(by[h], findings[i])
	}
	for _, h := range order {
		if err := WriteHostFindings(dir, h, by[h]); err != nil {
			return err
		}
	}
	return nil
}

// splitLegacy rewrites the single findings file of a run written before 0.6 as host files, then removes it. The
// host files are in place before the single file goes, and HostFiles reads the single file while it is there: an
// interruption loses nothing. Call it holding the environment's lock.
func splitLegacy(dir string) error {
	src := legacyFile(dir)
	if src == "" {
		return nil
	}
	ws := map[string]*findingsWriter{}
	abort := func() {
		for _, w := range ws {
			w.Abort()
		}
	}
	var werr error
	err := EachFindingIn(src, func(f *finding.Finding) {
		if werr != nil {
			return
		}
		h := FileHost(f)
		w := ws[h]
		if w == nil {
			if w, werr = newFindingsWriter(hostFindingsPath(dir, h)); werr != nil {
				return
			}
			ws[h] = w
		}
		werr = w.Add(f)
	})
	if err = errors.Join(err, werr); err != nil {
		abort()
		return err
	}
	// hosts the single file had nothing for: no stale file of an earlier split may stay
	if hfs, _ := os.ReadDir(filepath.Join(dir, "hosts")); hfs != nil {
		for _, e := range hfs {
			if ws[e.Name()] == nil {
				if err := os.Remove(hostFindingsPath(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
					abort()
					return err
				}
			}
		}
	}
	for h, w := range ws {
		delete(ws, h)
		if err := w.Commit(); err != nil {
			abort()
			return err
		}
	}
	return os.Remove(src)
}

// MigrateEnv splits the single findings file of current/ and of every run written before 0.6 into host files (one
// way: versions before 0.6 do not read the result). Call it holding the environment's lock.
func MigrateEnv(env string) error {
	dirs := append(runDirs(env), filepath.Join(env, Current))
	for _, d := range dirs {
		if err := splitLegacy(d); err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
	}
	return nil
}

// linkOrCopy puts src at dst (replacing it atomically): a hard link when the file system allows, a copy otherwise.
// Findings files are never changed in place, so a link is as good as a copy.
func linkOrCopy(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".link")
	os.Remove(tmp)
	if err := os.Link(src, tmp); err == nil {
		if err := rename(tmp, dst); err != nil {
			os.Remove(tmp)
			return err
		}
		return nil
	}
	return copyFile(src, dst)
}

func isFile(path string) bool { st, err := os.Stat(path); return err == nil && st.Mode().IsRegular() }
