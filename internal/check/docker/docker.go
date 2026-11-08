// Package docker is the docker module: inventory of the host's Docker (version, containers, images) and, optionally,
// vulnerability scans of its images.
//
// scan_images:
//
//	false     inventory only
//	packages  only the package DBs (dpkg/apk/rpm + os-release) are copied out of one container of each image with
//	          `docker cp` (tar to stdout): kilobytes, no process started in the container (recommended)
//	registry  trivy pulls the image by digest from its registry (needs registry credentials on the scanner)
//	save      `docker save | gzip -1` is streamed over SSH to the scanner; nothing is written on the host
//
// images: running (default) — only images of running containers; all — every image on the host.
// image_parallel: how many images one host fetches/scans at once (default 2).
//
// Each image (by ID) is fetched and scanned once per org run, even if it is present on many hosts: the first host
// to claim it in check.Ctx.Cache scans it, the others wait for and reuse the result.
package docker

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/check/softwarefs"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/priv"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// trivyRun is trivy.Run; tests swap it for recorded reports.
var trivyRun = trivy.Run

// image: one entry of docker.json "images" plus what the scan needs.
type image struct {
	obj       pyfmt.Obj // Id, RepoTags, RepoDigests, Size, Created, running, container — as written
	id        string
	running   bool
	container string // a running container of the image ("" = none)
	ref       string // digest or tag to pull by ("" = none)
	label     string // what findings and logs call it
	size      int64
}

// scan: an org-wide image scan, shared through check.Ctx.Cache.
type scan struct {
	done   chan struct{}
	host   string
	result []finding.Finding
	err    string
}

// CacheKey of an image scan in check.Ctx.Cache.
func CacheKey(imageID string) string { return "docker-image:" + imageID }

func claim(ctx *check.Ctx, id, host string) (*scan, bool) {
	s := &scan{done: make(chan struct{}), host: host}
	v, loaded := ctx.Cache.LoadOrStore(CacheKey(id), s)
	return v.(*scan), !loaded
}

func privCmd(h config.Host, op string, args ...string) (string, error) {
	return priv.Cmd(h.Privilege, op, false, args...)
}

func runOp(ctx *check.Ctx, h config.Host, op string) (string, error) {
	c, err := privCmd(h, op)
	if err != nil {
		return "", err
	}
	return ctx.SSH.Run(ctx, h, c, 300*time.Second, true)
}

// jsonl: docker --format '{{json .}}' output, one document per line, key order kept.
func jsonl(text string) ([]any, error) {
	out := []any{}
	for _, line := range pyfmt.SplitLines(text) {
		if !strings.HasPrefix(pyfmt.Strip(line), "{") {
			continue
		}
		v, err := pyfmt.Loads(line)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// first string of a JSON list, "" when empty / absent.
func first(v any) string {
	if l, ok := v.([]any); ok && len(l) > 0 {
		return str(l[0])
	}
	return ""
}

// Mode: the scan_images setting; "" = inventory only. `true` behaves as save, like any other unknown value.
func Mode(cfg map[string]any) string {
	switch t := cfg["scan_images"].(type) {
	case nil:
		return ""
	case bool:
		if t {
			return "true"
		}
		return ""
	case string:
		return t
	}
	return fmt.Sprint(cfg["scan_images"])
}

// DeniedError: docker could not be asked, in plain words, with the raw error after them.
func DeniedError(h config.Host, err error) error {
	return fmt.Errorf("%s (%w)", i18n.T("denied.docker", i18n.Default, map[string]any{"why": check.DeniedWhy(h).Text}), err)
}

// Run is the module. Writes docker.json ({"version", "containers", "images"} as docker printed them, the shape the
// report layer reads) and, when images are scanned, images/<short id>.json.gz (raw trivy reports).
func Run(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, facts check.Facts) ([]finding.Finding, error) {
	which, err := ctx.SSH.Run(ctx, h, "command -v docker || ls /usr/bin/docker /usr/local/bin/docker 2>/dev/null",
		300*time.Second, false)
	if err != nil {
		return nil, err
	}
	if pyfmt.Strip(which) == "" {
		ctx.Log("%s: docker: not installed, skipped", h.Name)
		f := check.New(h, "docker", finding.Inventory, "docker-absent", "INFO", i18n.Msg("docker.absent", nil),
			i18n.Plain(""), 0)
		f.Pkg = "docker"
		return []finding.Finding{f}, nil
	}
	var version pyfmt.Obj
	raw, err := runOp(ctx, h, "docker-version")
	if err == nil {
		if raw == "" {
			raw = "{}"
		}
		var v any
		if v, err = pyfmt.Loads(raw); err == nil {
			var ok bool
			if version, ok = v.(pyfmt.Obj); !ok {
				err = errors.New("docker version: not a JSON object")
			}
		}
	}
	if err != nil {
		return nil, DeniedError(h, err)
	}
	raw, err = runOp(ctx, h, "docker-ps")
	if err != nil {
		return nil, err
	}
	containers, err := jsonl(raw)
	if err != nil {
		return nil, err
	}
	// running container -> image id; one container per image is enough for `docker cp`
	raw, err = runOp(ctx, h, "docker-running")
	if err != nil {
		return nil, err
	}
	containerOf := map[string]string{}
	for _, line := range pyfmt.SplitLines(raw) {
		if iid, cid, ok := strings.Cut(line, " "); ok {
			if _, seen := containerOf[iid]; !seen {
				containerOf[iid] = pyfmt.Strip(cid)
			}
		}
	}
	raw, err = runOp(ctx, h, "docker-images")
	if err != nil {
		return nil, err
	}
	images, err := parseImages(raw, containerOf)
	if err != nil {
		return nil, err
	}
	objs := make([]any, len(images))
	nRunning := 0
	for i, img := range images {
		objs[i] = img.obj
		if img.running {
			nRunning++
		}
	}
	doc := pyfmt.O("version", version, "containers", containers, "images", objs)
	if err := pyfmt.WriteJSON(filepath.Join(out, "docker.json"), doc, true); err != nil {
		return nil, err
	}
	ctx.Log("%s: docker: %d containers, %d images (%d used by running containers)", h.Name, len(containers),
		len(images), nRunning)

	var findings []finding.Finding
	if server, ok := version.Get("Server").(pyfmt.Obj); ok && pyfmt.Truthy(server.Get("Version")) {
		f := check.Base(h, "docker")
		f.Kind, f.ID, f.Pkg, f.Installed, f.Severity = finding.Inventory, "docker-engine", "docker-engine",
			pyfmt.Str(server.Get("Version")), "INFO"
		f.Title, f.Target = "Docker Engine version", "docker"
		findings = append(findings, f)
	}
	mode := Mode(cfg)
	if mode == "" {
		return findings, nil
	}
	which2, hasImages := cfg["images"]
	onlyRunning := !hasImages || which2 == "running"
	var todo []*image
	for _, img := range images {
		if onlyRunning && !img.running {
			continue
		}
		if img.ref == "" && mode == "registry" {
			continue
		}
		if mode == "packages" && img.container == "" {
			continue // needs a running container to copy from
		}
		todo = append(todo, img)
	}
	imgdir := filepath.Join(out, "images")
	if err := os.Mkdir(imgdir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	maxBytes := int64(softwarefs.Int(cfg, "max_image_mb", 4096)) << 20

	// pass 1: scan images nobody has claimed yet (a few in parallel); pass 2: wait for images other hosts scan now
	type item struct {
		img *image
		s   *scan
	}
	var mine, theirs []item
	for _, img := range todo {
		s, claimed := claim(ctx, img.id, h.Name)
		if claimed {
			mine = append(mine, item{img, s})
		} else {
			theirs = append(theirs, item{img, s})
		}
	}
	ctx.Log("%s: docker: %d images to check: %d to fetch, %d shared with other hosts", h.Name, len(todo), len(mine),
		len(theirs))
	var mu sync.Mutex
	counter := 0
	work := func(it item) {
		mu.Lock()
		counter++
		i := counter
		mu.Unlock()
		img, s := it.img, it.s
		defer close(s.done)
		ctx.Log("%s: docker: [%d/%d] %s (%d MB) ...", h.Name, i, len(mine), img.label, img.size>>20)
		t0 := time.Now()
		res, err := fetchAndScan(ctx, h, img, mode, imgdir, maxBytes)
		if err != nil {
			s.err = truncate(err.Error(), 300)
			ctx.Log("%s: docker: [%d/%d] %s: FAILED %v", h.Name, i, len(mine), img.label, err)
			return
		}
		s.result = res
		ctx.Log("%s: docker: [%d/%d] %s: %d vulns (%.0fs)", h.Name, i, len(mine), img.label, len(res),
			time.Since(t0).Seconds())
	}
	jobs := make(chan item)
	var wg sync.WaitGroup
	for range max(1, softwarefs.Int(cfg, "image_parallel", 2)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range jobs {
				work(it)
			}
		}()
	}
	for _, it := range mine {
		jobs <- it
	}
	close(jobs)
	wg.Wait()
	for _, it := range append(mine, theirs...) {
		select {
		case <-it.s.done:
		default:
			ctx.Log("%s: docker: waiting for %s (scanned by %s)", h.Name, it.img.label, it.s.host)
			select {
			case <-it.s.done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if it.s.err != "" {
			name := it.img.label
			name, _, _ = strings.Cut(name, "@")
			name = name[strings.LastIndex(name, "/")+1:]
			findings = append(findings, check.Misconfig(h, "docker", "image-scan-failed", "UNKNOWN",
				i18n.Msg("docker.scan_failed", map[string]any{"name": name}), i18n.Plain(it.s.err)))
			continue
		}
		for _, f := range it.s.result {
			b := check.Base(h, "docker")
			f.Org, f.Host, f.Group, f.Exposure, f.Module = b.Org, b.Host, b.Group, b.Exposure, b.Module
			inUse := it.img.running
			f.ImageInUse = &inUse
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// parseImages: `docker image inspect` output reduced to what docker.json keeps, in Python's key order.
func parseImages(raw string, containerOf map[string]string) ([]*image, error) {
	if raw == "" {
		raw = "[]"
	}
	v, err := pyfmt.Loads(raw)
	if err != nil {
		return nil, err
	}
	list, ok := v.([]any)
	if !ok {
		return nil, errors.New("docker image inspect: not a JSON list")
	}
	var out []*image
	for _, x := range list {
		in, _ := x.(pyfmt.Obj)
		img := &image{id: str(in.Get("Id"))}
		for _, k := range []string{"Id", "RepoTags", "RepoDigests", "Size", "Created"} {
			img.obj = append(img.obj, pyfmt.KV{K: k, V: in.Get(k)})
		}
		img.container, img.running = containerOf[img.id]
		var c any
		if img.running {
			c = img.container
		}
		img.obj = append(img.obj, pyfmt.KV{K: "running", V: img.running}, pyfmt.KV{K: "container", V: c})
		img.ref = first(in.Get("RepoDigests"))
		if img.ref == "" {
			img.ref = first(in.Get("RepoTags"))
		}
		if img.label = first(in.Get("RepoTags")); img.label == "" {
			img.label = img.ref
			if img.label == "" {
				img.label = img.id
			}
		}
		if n, ok := in.Get("Size").(json.Number); ok {
			img.size, _ = n.Int64()
		}
		out = append(out, img)
	}
	return out, nil
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// short: the first 12 hex digits of an image id, as docker prints it.
func short(id string) string {
	s := id[strings.LastIndex(id, ":")+1:]
	return s[:min(12, len(s))]
}

func fetchAndScan(ctx *check.Ctx, h config.Host, img *image, mode, imgdir string, maxBytes int64) ([]finding.Finding, error) {
	sid := short(img.id)
	base := finding.Finding{Target: "image:" + img.label}
	report := func(args []string) ([]finding.Finding, error) {
		data, err := trivyRun(ctx, args, filepath.Join(imgdir, sid+".json"), time.Hour)
		if err != nil {
			return nil, err
		}
		r, err := trivy.ParseReport(data)
		if err != nil {
			return nil, err
		}
		return trivy.VulnFindings(r, base), nil
	}
	switch mode {
	case "packages":
		return scanPackageDBs(ctx, h, img, imgdir, report)
	case "registry":
		return report([]string{"image", "--scanners", "vuln", img.ref})
	}
	raw := filepath.Join(imgdir, sid+".tar.part")
	tar := filepath.Join(imgdir, sid+".tar")
	defer os.Remove(raw)
	defer os.Remove(tar)
	save, err := privCmd(h, "docker-save", img.id)
	if err != nil {
		return nil, err
	}
	// gzip -1 on the host cuts transfer ~2-3x; if gzip is missing the stream goes through as is
	if _, err := stream(ctx, h, save+" | (gzip -1 2>/dev/null || cat)", raw, maxBytes, 1800*time.Second,
		func(mb int64) { ctx.Log("%s: docker: %s: %d MB received", h.Name, img.label, mb) }); err != nil {
		return nil, err
	}
	if err := gunzipOrRename(raw, tar); err != nil {
		return nil, err
	}
	return report([]string{"image", "--scanners", "vuln", "--input", tar})
}

func gunzipOrRename(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(f, 1<<20)
	if magic, _ := br.Peek(2); len(magic) < 2 || magic[0] != 0x1f || magic[1] != 0x8b {
		f.Close()
		return os.Rename(src, dst)
	}
	zr, err := gzip.NewReader(br)
	if err != nil {
		f.Close()
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		f.Close()
		return err
	}
	_, err = io.Copy(out, zr)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	f.Close() // before the remove: Windows does not delete a file that is open
	if err != nil {
		return err
	}
	return os.Remove(src)
}

func stream(ctx *check.Ctx, h config.Host, command, path string, maxBytes int64, timeout time.Duration,
	progress func(int64)) (int64, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	n, err := ctx.SSH.Stream(ctx, h, command, f, maxBytes, timeout, progress)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// scanPackageDBs: `docker cp` each package-DB path out of a running container into a staging root filesystem and
// `trivy rootfs` it. Images without an OS package DB (scratch, distroless, static binaries) are skipped: their
// app dependencies need `save` mode or CI.
func scanPackageDBs(ctx *check.Ctx, h config.Host, img *image, imgdir string,
	report func([]string) ([]finding.Finding, error)) ([]finding.Finding, error) {
	sid := short(img.id)
	stage := filepath.Join(imgdir, sid+".rootfs")
	part := filepath.Join(imgdir, sid+".part.tar")
	defer os.RemoveAll(stage)
	defer os.Remove(part)
	var got []string
	for _, path := range priv.PkgDBPaths {
		rel := strings.TrimLeft(path, "/")
		parent := stage
		if i := strings.LastIndex(rel, "/"); i >= 0 {
			parent = filepath.Join(stage, rel[:i])
		}
		c, err := privCmd(h, "docker-cp", img.container, path)
		if err != nil {
			return nil, err
		}
		// -L: follow symlinks (os-release is usually a link); missing paths just fail quietly
		n, err := stream(ctx, h, c+" 2>/dev/null", part, 256<<20, 300*time.Second, nil)
		if err != nil || n == 0 {
			continue
		}
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return nil, err
		}
		if err := softwarefs.Extract(part, parent); err != nil {
			return nil, err
		}
		got = append(got, path)
	}
	hasRelease, hasDB := false, false
	for _, p := range got {
		hasRelease = hasRelease || strings.HasSuffix(p, "os-release")
		hasDB = hasDB || strings.Contains(p, "dpkg") || strings.Contains(p, "apk") || strings.Contains(p, "rpm")
	}
	if !hasRelease || !hasDB {
		ctx.Log("%s: docker: %s: no OS package DB in image, skipped", h.Name, img.label)
		return nil, nil
	}
	return report([]string{"rootfs", "--scanners", "vuln", stage})
}
