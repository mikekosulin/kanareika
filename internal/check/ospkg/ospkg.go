// Package ospkg is the os_packages module: the host's package list (one read-only query over SSH) becomes a
// CycloneDX SBOM that trivy matches on the scanner side; kernels and the host's own repositories then refine what
// trivy says (see package vendor).
package ospkg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
	"github.com/mikekosulin/kanareika/internal/sbom"
	"github.com/mikekosulin/kanareika/internal/trivy"
	"github.com/mikekosulin/kanareika/internal/vendor"
)

// trivyRun is trivy.Run; tests swap it for recorded reports.
var trivyRun = trivy.Run

// buildBOM and marshalBOM are sbom.BuildCycloneDX and pyfmt.MarshalLine; tests swap them to reach the error paths
// (the OS family was checked before and a BOM always marshals, so the real ones do not fail here).
var (
	buildBOM   = sbom.BuildCycloneDX
	marshalBOM = pyfmt.MarshalLine
)

// Target texts of kernel findings, as the Python version wrote them (the report layer groups by them).
const (
	TargetPending = "os: new kernel (reboot pending)"
	TargetOld     = "os: старые ядра (не загружены)"
)

// osMeta: the part of the report's Metadata the EOL check reads (absent fields stay nil, as Python's None).
type osMeta struct {
	Metadata *struct {
		OS *struct {
			Family *string `json:"Family"`
			Name   *string `json:"Name"`
			EOSL   bool    `json:"EOSL"`
		} `json:"OS"`
	} `json:"Metadata"`
}

// orNone: Python's f"{x}" of an optional string.
func orNone(s *string) string {
	if s == nil {
		return "None"
	}
	return *s
}

// Run is the module. Files in out: packages.txt (raw query output), sbom.cdx.json, trivy-os.json.gz,
// changelog-cves.txt and upgrades.txt (when the package type has those queries).
func Run(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, facts check.Facts) ([]finding.Finding, error) {
	fam, ok := sbom.FamilyFor(facts.OSRelease)
	if !ok {
		pretty, has := facts.OSRelease["PRETTY_NAME"]
		if !has {
			pretty = "None"
		}
		return nil, fmt.Errorf("unsupported OS for package matching: %s", pretty)
	}
	raw, err := ctx.SSH.Run(ctx, h, sbom.PkgQuery[fam.Type], 300*time.Second, true)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(out, "packages.txt"), []byte(raw), 0o644); err != nil {
		return nil, err
	}
	pkgs := sbom.ParsePackages(fam.Type, raw)
	if len(pkgs) == 0 {
		return nil, errors.New("package list is empty")
	}
	bom, err := buildBOM(h.Name, facts.OSRelease, pkgs)
	if err != nil {
		return nil, err
	}
	bomJSON, err := marshalBOM(bom, true) // json.dumps(bom): field order from the struct
	if err != nil {
		return nil, err
	}
	bomPath := filepath.Join(out, "sbom.cdx.json")
	if err := os.WriteFile(bomPath, bomJSON, 0o644); err != nil {
		return nil, err
	}
	rep, err := trivyRun(ctx, []string{"sbom", "--scanners", "vuln", bomPath}, filepath.Join(out, "trivy-os.json"), time.Hour)
	if err != nil {
		return nil, err
	}
	defer rep.Close()
	ctx.Log("%s: os_packages: %d packages", h.Name, len(pkgs))

	running := ""
	if f := strings.Fields(facts.Uname); len(f) > 1 {
		running = f[1] // `uname -srm`: Linux <release> <machine>
	}
	newer := ""
	if fam.Type == "rpm" {
		newer = NewerKernel(pkgs, running)
	}
	cl, up := changelog(ctx, h, fam.Type, out), upgrades(ctx, h, fam.Type, out)
	src := sources(pkgs)
	n := map[string]int{"backported": 0, finding.FixAvailable: 0, finding.FixVendor: 0, finding.FixReboot: 0}
	// the report is read one vulnerability at a time (hundreds of MB on a large host), and each finding goes to
	// the scan's sink as soon as it is complete: a host's packages are never held whole
	var findings []finding.Finding
	emit := ctx.Sink(h.Name)
	if emit == nil {
		emit = func(f *finding.Finding) { findings = append(findings, *f) }
	}
	base := check.Base(h, "os_packages")
	base.Target = "os"
	var meta osMeta
	err = trivy.EachFinding(rep, base, &meta.Metadata, func(f *finding.Finding) {
		setSource(f, src)
		markKernel(f, running, fam.Type == "rpm")
		vendor.AnnotateOne(f, cl, up, newer, n)
		emit(f)
	})
	if err != nil {
		return nil, err
	}
	ctx.Log("%s: os_packages: backported %d, in repos %d, waiting for vendor %d, reboot %d", h.Name,
		n["backported"], n[finding.FixAvailable], n[finding.FixVendor], n[finding.FixReboot])

	if m := meta.Metadata; m != nil && m.OS != nil && m.OS.EOSL {
		name := facts.OSRelease["PRETTY_NAME"]
		if name == "" {
			name = orNone(m.OS.Family) + " " + orNone(m.OS.Name)
		}
		f := check.Misconfig(h, "os_packages", "os-eol", "HIGH", i18n.Msg("os.eol", map[string]any{"name": name}),
			i18n.Msg("os.eol.detail", nil))
		f.Pkg = name
		if m.OS.Name != nil {
			f.Installed = *m.OS.Name
		}
		emit(&f)
	}
	return findings, nil
}

// SetSources records the source package of each finding whose binary package comes from a source of another name
// (libssl3 and openssl from openssl, libc6 from glibc), so one update of one source reads as one fix.
func SetSources(findings []finding.Finding, pkgs []sbom.Package) {
	src := sources(pkgs)
	for i := range findings {
		setSource(&findings[i], src)
	}
}

// sources: binary package -> its source package, where the names differ.
func sources(pkgs []sbom.Package) map[string]string {
	src := map[string]string{}
	for _, p := range pkgs {
		if p.SrcName != "" && p.SrcName != p.Name {
			src[p.Name] = p.SrcName
		}
	}
	return src
}

func setSource(f *finding.Finding, src map[string]string) {
	if s, ok := src[f.Pkg]; ok {
		f.SrcPkg = s
	}
}

// MarkKernels flags kernel findings: Kernel for the running kernel; Inactive for an installed kernel that is not
// booted (not exploitable until someone boots it) — with Pending when it is newer than the running one (rpm: the
// update is in place, the reboot is not). running = `uname -r`; "" leaves the findings alone.
func MarkKernels(findings []finding.Finding, running string, rpm bool) {
	for i := range findings {
		markKernel(&findings[i], running, rpm)
	}
}

func markKernel(f *finding.Finding, running string, rpm bool) {
	if running == "" || !IsKernel(f.Pkg) {
		return
	}
	if KernelMatches(f.Pkg, f.Installed, running) {
		f.Kernel = true
		return
	}
	f.Inactive = true
	if rpm && vendor.Vercmp(f.Installed, EVR(running)) > 0 {
		f.Pending, f.Target = true, TargetPending
	} else {
		f.Target = TargetOld
	}
}

// IsKernel: packages versioned with the kernel — updated together, effective after a reboot.
func IsKernel(name string) bool {
	for _, p := range []string{"kernel", "linux-image-", "linux-modules-", "linux-headers-"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return name == "python3-perf" || name == "perf" || name == "bpftool"
}

// KernelMatches: the package belongs to the running kernel. running = `uname -r`, e.g. 5.14.0-575.el9.x86_64 or
// 6.1.0-18-amd64. deb kernels carry the version in the package name; rpm ones in the version (epoch ignored).
func KernelMatches(name, installed, running string) bool {
	for _, p := range []string{"linux-image-", "linux-modules-", "linux-headers-"} {
		if strings.HasPrefix(name, p) {
			return strings.Contains(running, strings.SplitN(name, "-", 3)[2])
		}
	}
	if _, v, ok := strings.Cut(installed, ":"); ok {
		installed = v
	}
	return strings.HasPrefix(running, installed)
}

var archSuffix = regexp.MustCompile(`\.(x86_64|aarch64|ppc64le|s390x|i686|noarch)$`)

// EVR: 5.14.0-575.el9.x86_64 -> 5.14.0-575.el9.
func EVR(unameR string) string { return archSuffix.ReplaceAllString(unameR, "") }

// NewerKernel: the newest installed kernel when it is newer than the running one (rpm), else "".
func NewerKernel(pkgs []sbom.Package, running string) string {
	if running == "" {
		return ""
	}
	best := ""
	for _, p := range pkgs {
		if p.Name != "kernel-core" && p.Name != "kernel" && p.Name != "kernel-uek" {
			continue
		}
		if v := p.Version + "-" + p.Release; best == "" || vendor.Vercmp(v, best) > 0 {
			best = v // the first of equal versions wins, as Python's max()
		}
	}
	if best != "" && vendor.Vercmp(best, EVR(running)) > 0 {
		return best
	}
	return ""
}

// changelog: CVEs fixed per package from the changelogs; nil when not asked or not readable — missing data must
// not fail the module, trivy's answer then stays as is.
func changelog(ctx *check.Ctx, h config.Host, ptype, out string) vendor.Changelog {
	q, ok := vendor.ChangelogQuery[ptype]
	if !ok {
		return nil
	}
	raw, err := ctx.SSH.Run(ctx, h, q, 300*time.Second, true)
	if err != nil {
		ctx.Log("%s: os_packages: changelog not read: %v", h.Name, err)
		return nil
	}
	if err := os.WriteFile(filepath.Join(out, "changelog-cves.txt"), []byte(raw), 0o644); err != nil {
		ctx.Log("%s: os_packages: changelog not read: %v", h.Name, err)
		return nil
	}
	return vendor.ParseChangelog(raw)
}

// upgrades: what the host's repositories offer; nil = unknown.
func upgrades(ctx *check.Ctx, h config.Host, ptype, out string) map[string]string {
	q, ok := vendor.UpgradesQuery[ptype]
	if !ok {
		return nil
	}
	raw, err := ctx.SSH.Run(ctx, h, q, 600*time.Second, false)
	if err != nil {
		ctx.Log("%s: os_packages: repositories not queried: %v", h.Name, err)
		return nil
	}
	if err := os.WriteFile(filepath.Join(out, "upgrades.txt"), []byte(raw), 0o644); err != nil {
		ctx.Log("%s: os_packages: repositories not queried: %v", h.Name, err)
		return nil
	}
	up := vendor.ParseUpgrades(ptype, raw)
	if up == nil {
		ctx.Log("%s: os_packages: repositories not queried (package manager error)", h.Name)
	}
	return up
}
