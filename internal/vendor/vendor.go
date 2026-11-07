// Package vendor: what the host's own repositories say about a vulnerable package — the "real situation" layer on top
// of trivy.
//
// trivy matches installed versions against vendor advisories. On some systems that answer is not the whole truth:
//   - CentOS Stream has no advisory feed of its own; it is matched against RHEL, whose fixes carry a z-stream suffix
//     (1.0.9-10.el9_8.1). Stream ships the same fix as 1.0.9-11.el9 — or as the very same 1.0.9-10.el9 with the
//     patch inside — and version comparison alone calls it vulnerable.
//   - a fix can exist in the advisory but not (yet) in the repositories the host is configured with: `dnf upgrade`
//     then does nothing and the finding never goes away.
//
// So for every OS finding we ask the host (read-only, no root):
//  1. the package changelog: a CVE listed there is fixed in the installed build (backported);
//  2. the upgrades its repositories offer: is there anything to install at all.
//
// Each finding gets a fix state (finding.FixAvailable / FixVendor / FixReboot) and Backported when the changelog says
// the CVE is fixed (the finding then leaves the plan).
package vendor

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

var cveRE = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ChangelogQuery: names + CVE ids only — the full changelog of a host is MBs, this is KBs.
var ChangelogQuery = map[string]string{
	"rpm": `rpm -qa --qf '@%{NAME}\n[%{CHANGELOGTEXT}\n]' 2>/dev/null | grep -oE '^@[^[:space:]]+|CVE-[0-9]{4}-[0-9]{4,}'`,
}

// UpgradesQuery: rc is printed so "no upgrades" and "could not ask" are not the same answer.
var UpgradesQuery = map[string]string{
	"rpm": "if command -v dnf >/dev/null 2>&1; then dnf -q repoquery --upgrades --qf '%{name}\\t%{evr}\\n' 2>/dev/null; rc=$?; " +
		"else yum -q check-update 2>/dev/null; rc=$?; [ $rc = 100 ] && rc=0; fi; echo \"@@rc $rc\"",
	// reads the local apt cache: as fresh as the host's last `apt-get update`
	"deb": "apt list --upgradable 2>/dev/null; echo \"@@rc $?\"",
}

// Changelog: package -> CVE ids its changelog lists as fixed. A nil Changelog means "not asked / unknown".
type Changelog map[string]map[string]bool

func ParseChangelog(text string) Changelog {
	out := Changelog{}
	var cur map[string]bool
	for _, line := range pyfmt.SplitLines(text) {
		line = strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(line, "@"); ok {
			if out[name] == nil {
				out[name] = map[string]bool{}
			}
			cur = out[name]
		} else if cur != nil && cveRE.MatchString(line) {
			cur[line] = true
		}
	}
	return out
}

var rcRE = regexp.MustCompile(`@@rc (\d+)`)

// ParseUpgrades: package -> version the repositories offer; nil when the query failed (state unknown).
func ParseUpgrades(ptype, text string) map[string]string {
	m := rcRE.FindStringSubmatchIndex(text)
	if m == nil || text[m[2]:m[3]] != "0" {
		return nil
	}
	out := map[string]string{}
	for _, line := range pyfmt.SplitLines(text[:m[0]]) {
		if ptype == "deb" { // openssl/stable-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]
			if strings.Contains(line, "/") && strings.Contains(line, "upgradable") {
				name, rest, _ := strings.Cut(line, "/")
				if parts := strings.Fields(rest); len(parts) >= 2 {
					out[name] = parts[1]
				}
			}
		} else if name, evr, ok := strings.Cut(line, "\t"); ok { // dnf repoquery: name<TAB>evr
			out[strings.TrimSpace(name)] = strings.TrimSpace(evr)
		} else { // yum check-update: name.arch  version  repo
			if parts := strings.Fields(line); len(parts) == 3 && strings.Contains(parts[0], ".") {
				out[parts[0][:strings.LastIndex(parts[0], ".")]] = parts[1]
			}
		}
	}
	return out
}

// --- rpm version comparison (rpmvercmp), for kernels installed but not booted ---------------------------------------

var segRE = regexp.MustCompile(`[0-9]+|[a-zA-Z]+|~|\^`)

func isDigits(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

// cmpNum compares digit strings of any length (no integer overflow).
func cmpNum(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return cmp.Compare(len(a), len(b))
	}
	return strings.Compare(a, b)
}

func cmpPart(a, b string) int {
	sa, sb := segRE.FindAllString(a, -1), segRE.FindAllString(b, -1)
	for i := range min(len(sa), len(sb)) {
		x, y := sa[i], sb[i]
		switch {
		case x == y:
			continue
		case x == "~" || y == "~":
			if x == "~" {
				return -1
			}
			return 1
		case x == "^" || y == "^":
			if x == "^" {
				return 1
			}
			return -1
		case isDigits(x) && isDigits(y):
			return cmpNum(x, y) // "01" vs "1" ends the comparison as equal, as in the Python version
		case isDigits(x) != isDigits(y):
			if isDigits(x) {
				return 1
			}
			return -1
		}
		return strings.Compare(x, y)
	}
	if len(sa) == len(sb) {
		return 0
	}
	longer, rest := 1, ""
	if len(sa) > len(sb) {
		rest = sa[len(sb)]
	} else {
		longer, rest = -1, sb[len(sa)]
	}
	if rest == "~" {
		return -longer
	}
	return longer
}

// Vercmp compares [epoch:]version[-release] the way rpm does: -1, 0, 1. A non-numeric epoch counts as 0 (the Python
// version raised ValueError there).
func Vercmp(a, b string) int {
	split := func(v string) (int, string, string) {
		e, rest := "0", v
		if i := strings.LastIndex(v, ":"); i >= 0 {
			e, rest = v[:i], v[i+1:]
		}
		n, _ := strconv.Atoi(e)
		ver, rel, _ := strings.Cut(rest, "-")
		return n, ver, rel
	}
	ea, va, ra := split(a)
	eb, vb, rb := split(b)
	if ea != eb {
		return cmp.Compare(ea, eb)
	}
	if c := cmpPart(va, vb); c != 0 {
		return c
	}
	return cmpPart(ra, rb)
}

// --- annotate findings ----------------------------------------------------------------------------------------------

// Annotate sets Backported / FixState / RepoVersion on OS findings. changelog nil / upgrades nil: unknown (not asked
// or the query failed) — an empty non-nil map means "asked, nothing there". newerKernel: the newest installed kernel
// when it is newer than the running one, else "". Returns counters for the log.
func Annotate(findings []finding.Finding, changelog Changelog, upgrades map[string]string,
	newerKernel string) map[string]int {
	n := map[string]int{"backported": 0, finding.FixAvailable: 0, finding.FixVendor: 0, finding.FixReboot: 0}
	for i := range findings {
		f := &findings[i]
		if f.Kind != finding.Vuln || f.Inactive {
			continue
		}
		if changelog != nil && changelog[f.Pkg][f.ID] {
			f.Backported = true
			n["backported"]++
			continue
		}
		if f.Fixed == "" {
			continue // no fix anywhere: nothing to look for in the repositories
		}
		v, ok := upgrades[f.Pkg]
		switch {
		case f.Kernel && newerKernel != "" && Vercmp(newerKernel, f.Fixed) >= 0:
			f.FixState, f.RepoVersion = finding.FixReboot, newerKernel // the installed kernel already has the fix
		case upgrades == nil:
			continue // could not ask the repositories: leave it as trivy says
		case ok:
			f.FixState, f.RepoVersion = finding.FixAvailable, v
		default:
			f.FixState = finding.FixVendor
		}
		n[f.FixState]++
	}
	return n
}
