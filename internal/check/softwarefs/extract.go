package softwarefs

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Extract unpacks a tar (plain or gzip) into dest the way Python's tarfile.extractall(dest, filter="data") does:
// archives come from remote hosts, so leading "/" is stripped, nothing may land or link outside dest, device files
// and FIFOs are refused, ownership and special mode bits are dropped. A refused member fails the whole extraction
// with Python's message.
func Extract(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var r io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		r = zr
	}
	dest, err = realpath(dest)
	if err != nil {
		return err
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if err := extractOne(tr, hdr, dest); err != nil {
			return err
		}
	}
}

// pyRepr: repr() of a str, enough for the paths in tarfile's messages.
func pyRepr(s string) string {
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
}

func inside(p, dest string) bool {
	return p == dest || strings.HasPrefix(p, dest+string(filepath.Separator))
}

// absPath and evalSymlinks are filepath.Abs and filepath.EvalSymlinks; tests swap them to reach the error paths (a
// lost working directory, an unresolvable root).
var (
	absPath      = filepath.Abs
	evalSymlinks = filepath.EvalSymlinks
)

// realpath: os.path.realpath — symlinks resolved as far as the path exists, the rest cleaned lexically.
func realpath(p string) (string, error) {
	p, err := absPath(p)
	if err != nil {
		return "", err
	}
	rest := ""
	for cur := p; ; {
		if r, err := evalSymlinks(cur); err == nil {
			return filepath.Join(r, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

func extractOne(tr *tar.Reader, hdr *tar.Header, dest string) error {
	orig := hdr.Name
	name := strings.TrimLeft(orig, "/")
	target, err := realpath(filepath.Join(dest, name))
	if err != nil {
		return err
	}
	if !inside(target, dest) {
		return fmt.Errorf("%s would be extracted to %s, which is outside the destination", pyRepr(orig), pyRepr(target))
	}
	switch hdr.Typeflag {
	case tar.TypeReg, '\x00' /* TypeRegA: regular file in old archives */, tar.TypeLink, tar.TypeDir, tar.TypeSymlink, tar.TypeGNUSparse:
	default:
		if hdr.Typeflag == tar.TypeChar || hdr.Typeflag == tar.TypeBlock || hdr.Typeflag == tar.TypeFifo {
			return fmt.Errorf("%s is a special file", pyRepr(orig))
		}
		return nil // pax / GNU meta headers are consumed by archive/tar; anything else is skipped
	}
	path := filepath.Join(dest, name)
	if hdr.Typeflag == tar.TypeLink || hdr.Typeflag == tar.TypeSymlink {
		if filepath.IsAbs(hdr.Linkname) {
			return fmt.Errorf("%s is a link to an absolute path", pyRepr(orig))
		}
		var lt string
		if hdr.Typeflag == tar.TypeSymlink {
			lt = filepath.Join(dest, filepath.Dir(name), hdr.Linkname)
		} else {
			lt = filepath.Join(dest, hdr.Linkname)
		}
		if lt, err = realpath(lt); err != nil {
			return err
		}
		if !inside(lt, dest) {
			return fmt.Errorf("%s would link to %s, which is outside the destination", pyRepr(orig), pyRepr(lt))
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
	case tar.TypeSymlink:
		if _, err := os.Lstat(path); err == nil {
			_ = os.Remove(path)
		}
		return os.Symlink(filepath.Clean(hdr.Linkname), path)
	case tar.TypeLink:
		if _, err := os.Lstat(path); err == nil {
			_ = os.Remove(path)
		}
		src := filepath.Join(dest, filepath.Clean(hdr.Linkname))
		if os.Link(src, path) == nil {
			return nil
		}
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		return writeFile(path, in, 0o644)
	default:
		mode := os.FileMode(hdr.Mode) & 0o755
		if mode&0o100 == 0 {
			mode &^= 0o111
		}
		return writeFile(path, tr, mode|0o600)
	}
	return nil
}

func writeFile(path string, r io.Reader, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
