package trivy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Pinned trivy version: the one the Docker image ships (Dockerfile ARG TRIVY_IMAGE). Bumping it means updating
// checksums below from the release's trivy_<ver>_checksums.txt.
const Pinned = "0.75.0"

// checksums: SHA-256 of the release archives, from trivy_0.75.0_checksums.txt of the GitHub release. Pinned here
// rather than downloaded next to the archive, so a tampered release asset can't come with a matching checksum.
var checksums = map[string]string{
	"trivy_0.75.0_FreeBSD-64bit.tar.gz": "89c88a41cc259cb93951a4fc923fbeee145302c369cc098b2af56298569cfa06",
	"trivy_0.75.0_Linux-32bit.tar.gz":   "5dca0e5b0579a1c5fff1bf7dc541185020a3df892fe7c3345a1bf22988cc0e9c",
	"trivy_0.75.0_Linux-64bit.tar.gz":   "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f",
	"trivy_0.75.0_Linux-ARM.tar.gz":     "8cbe2286600ba56267fab0f10cf5696c252993b7b7935c5cef518abab3c84af4",
	"trivy_0.75.0_Linux-ARM64.tar.gz":   "a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3",
	"trivy_0.75.0_Linux-PPC64LE.tar.gz": "dbd7403d4191b14efd5ee4a808c93bc97b56fa9f62dd98a691a61bf6e556642e",
	"trivy_0.75.0_Linux-s390x.tar.gz":   "6acd3a3af4688567f5d3cdf3dd45e871ae060a88c07cea01401ae1487c4f19a3",
	"trivy_0.75.0_macOS-64bit.tar.gz":   "291edaa9778acbe4693d067b5ad60ee11570e5ac68296e85595417528ca641e4",
	"trivy_0.75.0_macOS-ARM64.tar.gz":   "4a77108cccf8e55c8d6823e1e759939a622277e66cd0daa3c1fc621ed69e4568",
}

const releaseURL = "https://github.com/aquasecurity/trivy/releases/download/v%s/%s"

// asset: the release archive for goos/goarch, as trivy names them.
func asset(goos, goarch string) (string, error) {
	osName := map[string]string{"linux": "Linux", "darwin": "macOS", "freebsd": "FreeBSD"}[goos]
	arch := map[string]string{"amd64": "64bit", "386": "32bit", "arm64": "ARM64", "arm": "ARM", "ppc64le": "PPC64LE",
		"s390x": "s390x"}[goarch]
	name := fmt.Sprintf("trivy_%s_%s-%s.tar.gz", Pinned, osName, arch)
	if _, ok := checksums[name]; !ok || osName == "" || arch == "" {
		return "", fmt.Errorf("no trivy %s release for %s/%s: install it and set KANAREIKA_TRIVY", Pinned, goos, goarch)
	}
	return name, nil
}

var (
	binMu  sync.Mutex
	binHit string
)

// Binary: path of the trivy to run. KANAREIKA_TRIVY if set; else the cached download of the pinned version; else
// a `trivy` on PATH if it is that version; else download it now.
func Binary(ctx context.Context) (string, error) {
	if p := os.Getenv("KANAREIKA_TRIVY"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("KANAREIKA_TRIVY: %w", err)
		}
		return p, nil
	}
	binMu.Lock()
	defer binMu.Unlock()
	if binHit != "" {
		return binHit, nil
	}
	cached := filepath.Join(cacheDir(), "bin", "trivy-"+Pinned)
	if _, err := os.Stat(cached); err == nil {
		binHit = cached
		return cached, nil
	}
	if p, err := exec.LookPath("trivy"); err == nil && versionOf(ctx, p) == Pinned {
		binHit = p
		return p, nil
	}
	if err := install(ctx, cached, runtime.GOOS, runtime.GOARCH); err != nil {
		return "", fmt.Errorf("trivy %s: %w", Pinned, err)
	}
	binHit = cached
	return cached, nil
}

func versionOf(ctx context.Context, bin string) string {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version", "--format", "json").Output()
	if err != nil {
		return ""
	}
	var v struct{ Version string }
	_ = json.Unmarshal(out, &v)
	return v.Version
}

// install downloads the release archive, checks it and puts the trivy binary at dest. Atomic (temp file + rename):
// concurrent kanareika processes may both download, neither sees half a binary.
func install(ctx context.Context, dest, goos, goarch string) error {
	name, err := asset(goos, goarch)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(releaseURL, Pinned, name), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %s", name, resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	archive, err := os.CreateTemp(filepath.Dir(dest), ".trivy-*.tar.gz")
	if err != nil {
		return err
	}
	defer os.Remove(archive.Name())
	defer archive.Close()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(archive, h), resp.Body); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != checksums[name] {
		return fmt.Errorf("%s: checksum mismatch (got %s)", name, got)
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return extract(archive, dest)
}

// extract the "trivy" entry of a tar.gz into dest (mode 0755).
func extract(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("no trivy binary in the archive")
		} else if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != "trivy" || filepath.Dir(hdr.Name) != "." {
			continue
		}
		tmp, err := os.CreateTemp(filepath.Dir(dest), ".trivy-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		_, err = io.Copy(tmp, tr)
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Chmod(tmp.Name(), 0o755)
		}
		if err != nil {
			return err
		}
		return os.Rename(tmp.Name(), dest)
	}
}
