// Package dbbundle moves everything kanareika downloads (trivy's vulnerability DBs, KEV/EPSS feeds, the IP DB) to a
// machine without Internet access: Export packs it into one tar.gz on a connected machine, Import unpacks it on the
// isolated one.
//
// The bundle holds public data only: the DBs as their publishers ship them. Nothing from orgs/, reports/ or
// secrets/ is ever read here. Import accepts regular files and directories under the known top-level names only
// (no links, no absolute paths, no "..") and replaces each part whole, so a broken bundle never leaves a half
// updated DB behind.
package dbbundle

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Part: one directory of the bundle: Name inside the archive, Dir on this machine.
type Part struct {
	Name string
	Dir  string
}

// maxFile: a single file larger than this is refused on import (trivy's DB is ~1 GB uncompressed today).
var maxFile int64 = 16 << 30

// Export writes the parts that exist into a gzip'd tar at dst (atomically: a temp file, then rename) and returns
// the names of the parts written. A part whose directory is missing is skipped; none at all is an error.
func Export(dst string, parts []Part) ([]string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".kanareika-db-*.tar.gz")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	zw := gzip.NewWriter(tmp)
	tw := tar.NewWriter(zw)
	var written []string
	for _, p := range parts {
		st, err := os.Stat(p.Dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			return nil, fmt.Errorf("%s: not a directory", p.Dir)
		}
		if err := addDir(tw, p); err != nil {
			return nil, err
		}
		written = append(written, p.Name)
	}
	if len(written) == 0 {
		return nil, errors.New("nothing to export: no DB downloaded yet (run `kanareika db update`)")
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	return written, os.Rename(tmp.Name(), dst)
}

func addDir(tw *tar.Writer, p Part) error {
	return filepath.WalkDir(p.Dir, func(fp string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(p.Dir, fp)
		if err != nil {
			return err
		}
		name := path.Join(p.Name, filepath.ToSlash(rel))
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: info.ModTime()})
		case !info.Mode().IsRegular():
			return nil // locks, sockets, links: not part of a DB
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: info.Size(),
			ModTime: info.ModTime()}); err != nil {
			return err
		}
		f, err := os.Open(fp)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}

// Import unpacks a bundle made by Export: every part found in it replaces the part's directory. Parts absent from
// the bundle are left as they are. Returns the names of the parts imported.
func Import(src string, parts []Part) ([]string, error) {
	byName := map[string]Part{}
	for _, p := range parts {
		byName[p.Name] = p
	}
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%s: not a kanareika DB bundle: %w", src, err)
	}
	tr := tar.NewReader(zr)
	staged := map[string]string{} // part name -> staging dir
	defer func() {
		for _, d := range staged {
			os.RemoveAll(d)
		}
	}()
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("%s: %w", src, err)
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		if name == "" || path.IsAbs(name) || path.Clean(name) != name || name == ".." ||
			strings.HasPrefix(name, "../") || strings.ContainsRune(name, '\\') {
			return nil, fmt.Errorf("%s: unsafe path %q", src, hdr.Name)
		}
		top, rest, _ := strings.Cut(name, "/")
		p, known := byName[top]
		if !known {
			return nil, fmt.Errorf("%s: unexpected entry %q (known: %s)", src, hdr.Name, names(parts))
		}
		dir, ok := staged[top]
		if !ok {
			if err := os.MkdirAll(filepath.Dir(p.Dir), 0o755); err != nil {
				return nil, err
			}
			if dir, err = os.MkdirTemp(filepath.Dir(p.Dir), "."+filepath.Base(p.Dir)+"-import-*"); err != nil {
				return nil, err
			}
			staged[top] = dir
		}
		target := filepath.Join(dir, filepath.FromSlash(rest))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			if hdr.Size > maxFile {
				return nil, fmt.Errorf("%s: %q is too large (%d bytes)", src, hdr.Name, hdr.Size)
			}
			if err := writeFile(target, tr, hdr.Size); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%s: %q: only files and directories are allowed", src, hdr.Name)
		}
	}
	if len(staged) == 0 {
		return nil, fmt.Errorf("%s: the bundle is empty", src)
	}
	var done []string
	for top, dir := range staged {
		dst := byName[top].Dir
		old := dst + ".old"
		_ = os.RemoveAll(old)
		if err := os.Rename(dst, old); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return done, err
		}
		if err := os.Rename(dir, dst); err != nil {
			_ = os.Rename(old, dst)
			return done, err
		}
		delete(staged, top)
		_ = os.RemoveAll(old)
		done = append(done, top)
	}
	sort.Strings(done)
	return done, nil
}

func names(parts []Part) string {
	n := make([]string, 0, len(parts))
	for _, p := range parts {
		n = append(n, p.Name)
	}
	return strings.Join(n, ", ")
}

func writeFile(target string, r io.Reader, size int64) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = io.CopyN(f, r, size)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
