// Package softwarefs is the software_fs module: software outside the package manager. Lockfiles and jars are
// streamed back as a tar over SSH (nothing is written on the host) and scanned with `trivy fs` on the scanner side.
package softwarefs

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/priv"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// trivyRun is trivy.Run; tests swap it for recorded reports.
var trivyRun = trivy.Run

// listFiles is Files; tests swap it to reach its error path (the staging dir Extract just wrote is always walkable).
var listFiles = Files

// Strings: a YAML list of strings (anything else counts as empty, as `cfg.get(k) or []` did for falsy values).
func Strings(v any) []string {
	var out []string
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
	}
	return out
}

// Int: an integer setting (YAML int, JSON float, numeric string) or def when absent / not a number.
func Int(cfg map[string]any, key string, def int) int {
	switch t := cfg[key].(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
	}
	return def
}

func join(items []string, prefix, sep string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = prefix + priv.Quote(s)
	}
	return strings.Join(parts, sep)
}

// RemoteCommand: find the files (existing dirs only, one filesystem, excluded trees pruned, size-capped); tar reads
// the list from stdin and writes the archive to stdout.
func RemoteCommand(cfg map[string]any) string {
	paths := join(Strings(cfg["paths"]), "", " ")
	prune := join(Strings(cfg["exclude"]), "-path ", " -o ")
	names := join(Strings(cfg["patterns"]), "-name ", " -o ")
	size := fmt.Sprintf("-size -%dk", Int(cfg, "max_file_mb", 100)*1024)
	pruneExpr := ""
	if prune != "" {
		pruneExpr = `\( ` + prune + ` \) -prune -o `
	}
	find := fmt.Sprintf(`find %s -xdev %s-type f \( %s \) %s -print 2>/dev/null`, paths, pruneExpr, names, size)
	return find + " | tar -cf - -T - 2>/dev/null"
}

// Run is the module. Files in out: software_fs.files.txt (what was found, relative to /) and trivy-fs.json.gz; the
// archive and the staging dir are removed afterwards.
func Run(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, facts check.Facts) ([]finding.Finding, error) {
	if len(Strings(cfg["paths"])) == 0 || len(Strings(cfg["patterns"])) == 0 {
		return nil, nil
	}
	archive := filepath.Join(out, "software_fs.tar")
	stage := filepath.Join(out, "software_fs")
	defer os.RemoveAll(stage)
	defer os.Remove(archive)
	size, err := streamToFile(ctx, h, RemoteCommand(cfg), archive, int64(Int(cfg, "max_total_mb", 1024))<<20,
		1800*time.Second)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return nil, err
	}
	if err := Extract(archive, stage); err != nil { // rejects absolute paths, .., device files, links outside
		return nil, err
	}
	files, err := listFiles(stage)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(out, "software_fs.files.txt"), []byte(strings.Join(files, "\n")+"\n"), 0o644); err != nil {
		return nil, err
	}
	data, err := trivyRun(ctx, []string{"fs", "--scanners", "vuln", stage}, filepath.Join(out, "trivy-fs.json"), time.Hour)
	if err != nil {
		return nil, err
	}
	report, err := trivy.ParseReport(data)
	if err != nil {
		return nil, err
	}
	ctx.Log("%s: software_fs: %d files", h.Name, len(files))
	findings := trivy.VulnFindings(report, check.Base(h, "software_fs"))
	for i := range findings { // trivy paths are relative to the staging dir == relative to the host root
		f := &findings[i]
		rel := f.PkgPath
		if rel == "" {
			rel = f.Target
		}
		f.Target = "/" + strings.TrimLeft(strings.TrimPrefix(rel, stage), "/")
	}
	return findings, nil
}

// streamToFile: the command's stdout into path (created / truncated).
func streamToFile(ctx *check.Ctx, h config.Host, command, path string, maxBytes int64, timeout time.Duration) (int64, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	n, err := ctx.SSH.Stream(ctx, h, command, f, maxBytes, timeout, nil)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// Files under root, relative and sorted: regular files and links to them; symlinked directories are not entered
// (Python's rglob + is_file).
func Files(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == root || d.IsDir() {
			return err
		}
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			rel, _ := filepath.Rel(root, p)
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}
