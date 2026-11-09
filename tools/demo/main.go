// Command demo writes a working directory of made-up data for screenshots and trying the interfaces out:
//
//	go run ./tools/demo -out /tmp/kanareika-demo
//	KANAREIKA_FEEDS_DIR=/tmp/kanareika-demo/feeds TRIVY_CACHE_DIR=/tmp/kanareika-demo/trivy kanareika --home /tmp/kanareika-demo
//
// One organization, a production and a staging environment, a month of daily full runs: vulnerabilities fixed
// over time and new ones appearing, logins and password guessing, open ports, disks filling up. Everything is
// invented: documentation addresses (RFC 5737), example.com, CVE ids of the year 0000, which are never assigned
// (the CVE program starts at 1999; ids of the current year are, as soon as their numbers come up).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
	"github.com/mikekosulin/kanareika/internal/report"
)

// seams for tests: main's fatal exit, and the file system and loaders failing midway
var (
	fatal         = log.Fatal
	mkdirAll      = os.MkdirAll
	writeFile     = os.WriteFile
	newLoader     = config.NewLoader
	loadPolicy    = priority.LoadPolicy
	updateCurrent = report.UpdateCurrent
)

func main() {
	out := flag.String("out", "kanareika-demo", "directory to write (created; must be empty or new)")
	end := flag.String("end", time.Now().UTC().Format(time.DateOnly), "the day of the last run")
	days := flag.Int("days", 30, "runs, one a day")
	flag.Parse()
	last, err := time.Parse(time.DateOnly, *end)
	if err != nil {
		fatal(err)
	}
	if err := generate(*out, last, *days); err != nil {
		fatal(err)
	}
	fmt.Printf("demo data in %s\nKANAREIKA_FEEDS_DIR=%s TRIVY_CACHE_DIR=%s kanareika --home %s\n", *out,
		filepath.Join(*out, "feeds"), filepath.Join(*out, "trivy"), *out)
}

type host struct {
	name, group, env, addr, os, kernel, family string
	exposure                                   int
	public                                     []string
	pkgs                                       []string
}

// fleet: a mid-size company's production (118 hosts) and a small staging, in groups; three distro families;
// edge, web and bastion hosts face the internet. Addresses: RFC 5737.
type group struct {
	name, env, role, family, os, kernel string
	n, exposure                         int
	pkgs                                []string
}

var groups = []group{
	{"edge", "production", "front", "deb", "Debian GNU/Linux 12 (bookworm)", "6.1.0-18-amd64", 6, 1, []string{"nginx"}},
	{"web", "production", "front", "deb", "Debian GNU/Linux 12 (bookworm)", "6.1.0-18-amd64", 22, 1, []string{"nginx"}},
	{"bastion", "production", "front", "deb", "Debian GNU/Linux 12 (bookworm)", "6.1.0-18-amd64", 2, 1, nil},
	{"api", "production", "app", "ubu", "Ubuntu 22.04.5 LTS", "5.15.0-119-generic", 18, 2, []string{"python3.10"}},
	{"worker", "production", "app", "ubu", "Ubuntu 22.04.5 LTS", "5.15.0-119-generic", 24, 2, []string{"python3.10"}},
	{"ci", "production", "app", "ubu", "Ubuntu 22.04.5 LTS", "5.15.0-119-generic", 6, 2, []string{"python3.10", "git"}},
	{"k8s-node", "production", "k8s_node", "ubu", "Ubuntu 22.04.5 LTS", "5.15.0-119-generic", 20, 2, nil},
	{"db", "production", "internal", "rpm", "Rocky Linux 9.4 (Blue Onyx)", "5.14.0-427.el9.x86_64", 10, 3, []string{"postgresql-server"}},
	{"cache", "production", "internal", "ubu18", "Ubuntu 18.04.6 LTS", "4.15.0-213-generic", 6, 3, []string{"redis-server"}},
	{"mon", "production", "internal", "deb", "Debian GNU/Linux 12 (bookworm)", "6.1.0-18-amd64", 4, 3, nil},
	{"stage-web", "staging", "front", "deb", "Debian GNU/Linux 12 (bookworm)", "6.1.0-18-amd64", 4, 2, []string{"nginx"}},
	{"stage-app", "staging", "app", "ubu", "Ubuntu 22.04.5 LTS", "5.15.0-119-generic", 6, 3, []string{"python3.10"}},
	{"stage-db", "staging", "internal", "rpm", "Rocky Linux 9.4 (Blue Onyx)", "5.14.0-427.el9.x86_64", 2, 3, []string{"postgresql-server"}},
}

// base packages of each family (the groups add theirs)
var familyPkgs = map[string][]string{
	"deb":   {"openssl", "libc6", "curl", "openssh-server", "libxml2", "systemd", "linux-image-6.1.0-18-amd64"},
	"ubu":   {"libssl3", "libc6", "sudo", "openssh-server", "curl", "linux-image-5.15.0-119-generic"},
	"rpm":   {"openssl-libs", "glibc", "kernel-core", "sudo", "libxml2", "curl"},
	"ubu18": {"libssl1.1", "libc6", "openssh-server", "linux-image-4.15.0-213-generic"},
}

var hosts = func() []host {
	var out []host
	prod, stage, pub := 10, 10, 10
	for _, g := range groups {
		for i := 1; i <= g.n; i++ {
			h := host{name: fmt.Sprintf("%s-%02d", g.name, i), group: g.name, env: g.env, os: g.os, kernel: g.kernel,
				family: g.family, exposure: g.exposure, pkgs: append(slices.Clone(familyPkgs[g.family]), g.pkgs...)}
			if g.env == "production" {
				h.addr = fmt.Sprintf("192.0.2.%d", prod)
				prod++
			} else {
				h.addr = fmt.Sprintf("198.51.100.%d", stage)
				stage++
			}
			if g.name == "edge" || g.name == "bastion" {
				h.public = []string{fmt.Sprintf("203.0.113.%d", pub)}
				pub++
			}
			out = append(out, h)
		}
	}
	return out
}()

func groupOf(name string) group {
	for _, g := range groups {
		if g.name == name {
			return g
		}
	}
	return group{}
}

// vuln: one made-up CVE on a package of a host, present from day `from` until day `fixed` (exclusive; -1: never).
// state: the fix as the host's repositories see it (available, vendor = none yet, reboot = installed, the old
// kernel runs, backported = the changelog lists the CVE as fixed).
type vuln struct {
	host, pkg, id, sev, installed, fixedIn, state, published string
	from, fixed                                              int
	kev, rce, preauth                                        bool
	epss, cvss                                               float64
}

func generate(out string, last time.Time, days int) error {
	if ents, err := os.ReadDir(out); err == nil && len(ents) > 0 {
		return fmt.Errorf("%s is not empty", out)
	}
	paths := config.PathsAt(out)
	for _, d := range []string{paths.Orgs, paths.Secrets, paths.Reports, filepath.Join(out, "feeds"),
		filepath.Join(out, "trivy", "db"), filepath.Join(out, "trivy", "java-db")} {
		if err := mkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := writeFile(filepath.Join(paths.Orgs, "acme.yml"), []byte(orgFile(last)), 0o644); err != nil {
		return err
	}
	l, err := newLoader(paths)
	if err != nil {
		return err
	}
	org, errs := l.LoadOrg(filepath.Join(paths.Orgs, "acme.yml"))
	if len(errs) > 0 {
		return fmt.Errorf("demo org: %v", errs)
	}
	pol, err := loadPolicy(paths)
	if err != nil {
		return err
	}

	r := rand.New(rand.NewPCG(7, 42)) // the same data every time
	vulns := makeVulns(r, days)
	feeds := priority.Feeds{KEV: map[string]bool{}, EPSS: map[string]float64{}, Updated: last.Add(2 * time.Hour).Format("2006-01-02T15:04:05.000000+00:00")}
	var kev []string
	for _, v := range vulns {
		if v.kev {
			feeds.KEV[v.id] = true
			kev = append(kev, v.id)
		}
		feeds.EPSS[v.id] = v.epss
	}
	for _, c := range containers {
		for _, p := range c.parts {
			if p.kev && !feeds.KEV[p.id] {
				feeds.KEV[p.id] = true
				kev = append(kev, p.id)
			}
			feeds.EPSS[p.id] = p.epss
		}
	}
	sort.Strings(kev)
	if err := writeJSON(filepath.Join(out, "feeds", "kev.json"), kev); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(out, "feeds", "epss.json"), feeds.EPSS); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(out, "feeds", "updated"), []byte(feeds.Updated), 0o644); err != nil {
		return err
	}
	// a trivy cache with only its metadata (TRIVY_CACHE_DIR=<out>/trivy): the interfaces show a DB built that
	// morning and current until the evening, wherever the demo runs
	for _, db := range []string{"db", "java-db"} {
		meta := map[string]any{"Version": 2, "UpdatedAt": last.Add(6 * time.Hour), "NextUpdate": last.Add(18 * time.Hour),
			"DownloadedAt": last.Add(7 * time.Hour)}
		if err := writeJSON(filepath.Join(out, "trivy", db, "metadata.json"), meta); err != nil {
			return err
		}
	}

	for _, env := range []string{"production", "staging"} {
		envDir := report.EnvDir(paths, "acme", env)
		for d := 0; d < days; d++ { // like scans: each run counts its due dates from the state before it
			started := last.AddDate(0, 0, d-days+1).Add(3 * time.Hour)
			prev, err := report.PrevIndex(envDir)
			if err != nil {
				return err
			}
			if err := saveRun(r, envDir, org, env, d, days, started, vulns, pol, feeds, prev); err != nil {
				return err
			}
			if _, err := updateCurrent(envDir, true, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// advisory: one upstream flaw, packaged under different names per family (openssl / libssl3 / openssl-libs), so a
// CVE spans packages and dozens of hosts, and one package update closes several CVEs.
type advisory struct {
	upstream string   // what the flaw is in
	pkgs     []string // the package names carrying it
	sev      string
	vector   string
	kev      bool
	epss     float64
}

// versions: installed -> fixed per package ("" fixed: none in the repositories)
var versions = map[string][2]string{
	"openssl": {"3.0.13-1~deb12u1", "3.0.15-1~deb12u1"}, "libssl3": {"3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.18"},
	"openssl-libs": {"1:3.0.7-27.el9", "1:3.2.2-6.el9_5"}, "libssl1.1": {"1.1.1-1ubuntu2.1~18.04.23", ""},
	"libc6": {"2.36-9+deb12u7", "2.36-9+deb12u9"}, "glibc": {"2.34-100.el9", "2.34-125.el9_5"},
	"curl": {"7.88.1-10+deb12u7", "7.88.1-10+deb12u8"}, "openssh-server": {"1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u3"},
	"libxml2": {"2.9.14+dfsg-1.3", ""}, "systemd": {"252.30-1~deb12u2", "252.31-1~deb12u1"},
	"nginx": {"1.22.1-9", "1.22.1-9+deb12u1"}, "sudo": {"1.9.9-1ubuntu2.4", "1.9.9-1ubuntu2.5"},
	"python3.10": {"3.10.12-1~22.04.5", "3.10.12-1~22.04.7"}, "git": {"1:2.34.1-1ubuntu1.11", "1:2.34.1-1ubuntu1.12"},
	"postgresql-server": {"13.14-1.el9", "13.18-1.el9_5"}, "redis-server": {"5:4.0.9-1ubuntu0.2", ""},
	"linux-image-6.1.0-18-amd64": {"6.1.76-1", "6.1.112-1"}, "linux-image-5.15.0-119-generic": {"5.15.0-119.129", "5.15.0-125.135"},
	"kernel-core": {"5.14.0-427.el9", "5.14.0-503.el9"}, "linux-image-4.15.0-213-generic": {"4.15.0-213.224", ""},
}

// byFamily: the same package name in another family has its own versions.
var byFamily = map[string][2]string{
	"ubu:libc6": {"2.35-0ubuntu3.8", "2.35-0ubuntu3.9"}, "ubu18:libc6": {"2.27-3ubuntu1.6", ""},
	"ubu:openssh-server": {"1:8.9p1-3ubuntu0.7", "1:8.9p1-3ubuntu0.10"}, "ubu18:openssh-server": {"1:7.6p1-4ubuntu0.7", ""},
	"ubu:curl": {"7.81.0-1ubuntu1.16", "7.81.0-1ubuntu1.18"}, "rpm:curl": {"7.76.1-29.el9_4", "7.76.1-31.el9"},
	"rpm:sudo": {"1.9.5p2-10.el9_3", "1.9.5p2-10.el9_5"}, "rpm:libxml2": {"2.9.13-6.el9_4", ""},
}

func versionOf(family, pkg string) [2]string {
	if v, ok := byFamily[family+":"+pkg]; ok {
		return v
	}
	return versions[pkg]
}

var advisories = []advisory{
	{"openssh", []string{"openssh-server"}, "CRITICAL", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", false, .87},
	{"openssh", []string{"openssh-server"}, "MEDIUM", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", false, .03},
	{"openssl", []string{"openssl", "libssl3", "openssl-libs", "libssl1.1"}, "HIGH", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", false, .21},
	{"openssl", []string{"openssl", "libssl3", "openssl-libs"}, "MEDIUM", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", false, .012},
	{"openssl", []string{"openssl", "openssl-libs"}, "LOW", "AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", false, .001},
	{"glibc", []string{"libc6", "glibc"}, "HIGH", "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", true, .16},
	{"glibc", []string{"libc6", "glibc"}, "MEDIUM", "AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", false, .004},
	{"curl", []string{"curl"}, "MEDIUM", "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", false, .009},
	{"curl", []string{"curl"}, "LOW", "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", false, .002},
	{"linux", []string{"linux-image-6.1.0-18-amd64", "linux-image-5.15.0-119-generic", "kernel-core", "linux-image-4.15.0-213-generic"}, "HIGH", "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", false, .051},
	{"linux", []string{"linux-image-5.15.0-119-generic", "kernel-core"}, "MEDIUM", "AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", false, .004},
	{"redis", []string{"redis-server"}, "CRITICAL", "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", true, .94},
	{"libxml2", []string{"libxml2"}, "MEDIUM", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", false, .006},
	{"sudo", []string{"sudo"}, "HIGH", "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", false, .022},
	{"python", []string{"python3.10"}, "HIGH", "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", false, .018},
	{"nginx", []string{"nginx"}, "HIGH", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", false, .12},
	{"systemd", []string{"systemd"}, "MEDIUM", "AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", false, .003},
	{"git", []string{"git"}, "HIGH", "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", false, .041},
	{"postgresql", []string{"postgresql-server"}, "HIGH", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", false, .07},
}

// cvssScore: a plausible base score for a made-up vector.
func cvssScore(sev string) float64 {
	return map[string]float64{"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.3, "LOW": 3.1}[sev]
}

// makeVulns: every advisory on the hosts carrying one of its packages. Updates roll out per group: a group starts
// on its day and its hosts follow within a few days; some groups never get to it, some advisories arrive during
// the month, and a few hosts lag behind.
func makeVulns(r *rand.Rand, days int) []vuln {
	var out []vuln
	for i, a := range advisories {
		id := fmt.Sprintf("CVE-0000-9%04d", 1001+i)
		from := 0
		if r.IntN(5) == 0 {
			from = min(days-1, 3+r.IntN(max(days-4, 1))) // published during the month
		}
		rollout := map[string]int{}
		for _, g := range groups {
			switch x := r.IntN(10); {
			case x < 5:
				rollout[g.name] = from + 1 + int(float64(days-2-from)*r.Float64()*r.Float64())
			case x < 7:
				rollout[g.name] = from + days/2 + r.IntN(max(days/2, 1))
			default:
				rollout[g.name] = -1 // not yet
			}
		}
		published := fmt.Sprintf("2026-%02d-%02d", 4+r.IntN(6), 1+r.IntN(28))
		for _, h := range hosts {
			for _, p := range h.pkgs {
				if !slices.Contains(a.pkgs, p) {
					continue
				}
				v := versionOf(h.family, p)
				fixed := rollout[h.group]
				if fixed >= 0 {
					fixed += r.IntN(4)
					if r.IntN(15) == 0 {
						fixed = -1 // the one host nobody got to
					}
				}
				state := "available"
				switch {
				case v[1] == "":
					state, fixed = "vendor", -1
				case strings.HasPrefix(p, "linux-image") && r.IntN(5) == 0:
					state = "reboot"
				case p == "sudo" && r.IntN(3) == 0:
					state = "backported"
				}
				out = append(out, vuln{host: h.name, pkg: p, id: id, sev: a.sev, installed: v[0], fixedIn: v[1], state: state,
					published: published, from: from, fixed: fixed, kev: a.kev, epss: a.epss, cvss: cvssScore(a.sev),
					preauth: strings.Contains(a.vector, "AV:N/") && strings.Contains(a.vector, "PR:N") && strings.Contains(a.vector, "UI:N"),
					rce:     strings.Contains(a.vector, "C:H/I:H")})
			}
		}
	}
	return out
}

// containers: images that run on the fleet, with what is inside them, made up the same way.
type container struct {
	image, runtime, where string   // docker: the container name; k8s: namespace/Kind/name
	hosts                 []string // docker: the hosts running it; k8s: the cluster
	parts                 []part
}

type part struct {
	pkg, path, installed, fixed, id, sev string
	kev, preauth, rce                    bool
	epss                                 float64
}

var containers = func() []container {
	var api, legacy []string
	for _, h := range hosts {
		switch {
		case h.group == "api" && h.name < "api-17":
			api = append(api, h.name)
		case h.group == "api":
			legacy = append(legacy, h.name)
		}
	}
	log4j := part{"log4j-core", "/app/lib/log4j-core-2.14.1.jar", "2.14.1", "2.17.1", "CVE-0000-91090", "CRITICAL", true, true, true, .975}
	urllib := part{"urllib3", "/app/requirements.txt", "1.26.15", "1.26.19", "CVE-0000-91092", "MEDIUM", false, false, false, .004}
	return []container{
		{"registry.example.com/api:2.14.0", "docker", "api", api, []part{urllib,
			{"openssl", "", "3.0.13-1~deb12u1", "3.0.15-1~deb12u1", "CVE-0000-91003", "HIGH", false, true, false, .21}}},
		{"registry.example.com/api:2.11.3", "docker", "api-legacy", legacy, []part{urllib, log4j}},
		{"registry.example.com/worker:5.3.1", "k8s", "jobs/Deployment/worker", []string{"k8s:prod-eu"}, []part{log4j,
			{"jackson-databind", "/app/lib/jackson-databind-2.13.2.jar", "2.13.2", "2.13.4.2", "CVE-0000-91091", "HIGH", false, true, false, .31},
			{"libssl3", "", "3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.18", "CVE-0000-91003", "HIGH", false, true, false, .21}}},
		{"registry.k8s.io/ingress-nginx/controller:v1.9.4", "k8s", "ingress-nginx/DaemonSet/ingress-nginx-controller", []string{"k8s:prod-eu"},
			[]part{{"nginx", "", "1.21.6-r0", "1.25.3-r0", "CVE-0000-91016", "HIGH", false, true, false, .12}}},
	}
}()

func saveRun(r *rand.Rand, envDir string, org *config.Org, env string, day, days int, started time.Time,
	vulns []vuln, pol *priority.Policy, feeds priority.Feeds, prev priority.Prev) error {
	runID := started.Format("2006-01-02_150405")
	runDir := filepath.Join(envDir, runID)
	var names []string
	var fs []finding.Finding
	failed := pyfmt.Ordered[string]{}
	byHost := map[string][]string{}
	modules := []string{"access", "exposure", "health", "os_packages"}
	for _, h := range hosts {
		if h.env != env {
			continue
		}
		names = append(names, h.name)
		byHost[h.name] = modules
		if h.group == "api" {
			byHost[h.name] = append(slices.Clone(modules), "docker")
		}
		if h.name == "cache-01" && day%9 == 4 { // a flaky one
			failed.Set(h.name, "unreachable: dial tcp 192.0.2.32:22: i/o timeout")
			continue
		}
		if h.name == downHost && day == days-1 { // down since this morning: the server view shows it failed
			failed.Set(h.name, "unreachable: dial tcp "+h.addr+":22: connect: connection refused")
			continue
		}
		if err := writeHostFiles(r, filepath.Join(runDir, "hosts", h.name), h, day); err != nil {
			return err
		}
		base := finding.Finding{Org: "acme", Host: h.name, Group: h.group, Exposure: h.exposure}
		for _, v := range vulns {
			if h.name == cleanHost {
				break
			}
			if v.host != h.name || day < v.from || v.fixed >= 0 && day >= v.fixed {
				continue
			}
			f := base
			f.Module, f.Kind, f.ID, f.Pkg, f.Installed, f.Fixed, f.Status, f.Severity = "os_packages", finding.Vuln, v.id, v.pkg,
				v.installed, v.fixedIn, "fixed", v.sev
			f.Title, f.Target, f.FixState, f.RCE, f.Preauth = v.pkg+": made-up vulnerability", "os", v.state, v.rce && v.preauth, v.preauth
			f.Kernel = strings.HasPrefix(v.pkg, "linux-image") || v.pkg == "kernel-core"
			f.Pending = v.state == "reboot"
			f.Backported = v.state == "backported"
			if v.state == "vendor" || v.state == "backported" {
				f.Status = "affected"
			}
			if v.state == "backported" {
				f.FixState = ""
			}
			f.URL, f.Published, f.CVSSScore = "https://example.com/"+v.id, v.published, &v.cvss
			f.Description = "Made-up: a flaw in " + v.pkg + " for demonstration; it does not exist."
			fs = append(fs, f)
		}
		misc := func(module, kind, id, sev string, title, target i18n.Text) {
			f := base
			f.Module, f.Kind, f.ID, f.Severity = module, kind, id, sev
			f.Title, f.Msg, f.Args, f.Target, f.TargetMsg, f.TargetArgs = title.Text, title.Key, title.Args, target.Text, target.Key, target.Args
			fs = append(fs, f)
		}
		if (h.name == "web-01" || h.name == "web-07" || h.name == "edge-03") && day < days-6 {
			misc("access", finding.Misconfig, "ssh-password-auth", "HIGH", i18n.Msg("ssh.password", nil), i18n.Plain("PasswordAuthentication yes"))
		}
		if h.name == "web-01" {
			misc("exposure", finding.Misconfig, "listen-public-6379-tcp", "HIGH",
				i18n.Msg("net.close", map[string]any{"service": "redis", "port": 6379}), i18n.Plain("tcp *:6379 redis-server"))
		}
		if h.group == "cache" {
			misc("health", finding.Misconfig, "os-eol", "HIGH", i18n.Msg("os.eol", map[string]any{"name": "Ubuntu 18.04"}), i18n.Msg("os.eol.detail", nil))
		}
		if h.name == "db-01" && day > days-10 {
			use := 80 + (day - (days - 10))
			misc("health", finding.Health, "disk-/var", "MEDIUM", i18n.Msg("health.disk", map[string]any{"mount": "/var/lib/pgsql", "use": use}), i18n.Plain(""))
		}
		if h.name == partialHost { // the audit user has no sudo here: some access checks were not possible
			title, why := check.Denied(config.Host{User: "audit", Privilege: "sudo"}, []string{"denied.shadow", "denied.authlog"})
			misc("access", finding.Inventory, "access-limited", "INFO", title, why)
		}
		if h.exposure == 1 {
			misc("access", finding.Inventory, "ssh-bruteforce", "MEDIUM",
				i18n.Msg("ssh.bruteforce", map[string]any{"n": 3000 + r.IntN(4000), "ips": 40 + r.IntN(60)}), i18n.Plain("203.0.113.66 (812)"))
		}
	}
	if env == "production" {
		fs = append(fs, containerFindings(names, failed)...)
	}
	fs, err := priority.Apply(fs, org, env, pol, feeds, started, prev)
	if err != nil {
		return err
	}
	if env == "production" {
		modules = append(modules, "docker", "k8s")
		sort.Strings(modules)
	}
	tv := "0.76.2"
	fu := feeds.Updated
	meta := &report.Meta{Org: "acme", Env: env, RunID: runID, Kanareika: "demo", TrivyVersion: &tv,
		Started:   started.Format("2006-01-02T15:04:05.000000+00:00"),
		Finished:  started.Add(11 * time.Minute).Format("2006-01-02T15:04:05.000000+00:00"),
		Selection: report.Selection{Groups: []string{}, Hosts: []string{}, Modules: []string{}}, Modules: modules,
		HostsScanned: names, HostsOK: len(names) - failed.Len(), ModulesByHost: byHost, HostsFailed: failed,
		ModuleErrors: pyfmt.Ordered[[]string]{}, FeedsUpdated: &fu}
	if err := mkdirAll(runDir, 0o755); err != nil {
		return err
	}
	return report.SaveRun(runDir, meta, fs)
}

// writeHostFiles: what the modules write per host: facts, access, exposure, health.
// The server view's cases: a host with nothing to do, one only partly checked (no sudo), one down in the last run,
// one in the org file that was never scanned (added after the last run).
const (
	cleanHost   = "mon-04"
	partialHost = "bastion-02"
	downHost    = "db-10"
	newHost     = "mon-05"
)

// containerFindings: what the docker and k8s modules would report for the images that run (failed hosts report
// nothing).
func containerFindings(scanned []string, failed pyfmt.Ordered[string]) []finding.Finding {
	var out []finding.Finding
	for _, c := range containers {
		for _, h := range c.hosts {
			_, down := failed.Get(h)
			if down || (c.runtime == "docker" && !slices.Contains(scanned, h)) {
				continue
			}
			for _, p := range c.parts {
				f := finding.Finding{Org: "acme", Host: h, Kind: finding.Vuln, ID: p.id, Pkg: p.pkg, PkgPath: p.path,
					Installed: p.installed, Fixed: p.fixed, Status: "fixed", Severity: p.sev, Preauth: p.preauth, RCE: p.rce,
					Title: p.pkg + ": made-up vulnerability", URL: "https://example.com/" + p.id, Published: "2026-06-12",
					Description: "Made-up: a flaw in " + p.pkg + " for demonstration; it does not exist."}
				score := cvssScore(p.sev)
				f.CVSSScore = &score
				if c.runtime == "docker" {
					hh := hostNamed(h)
					f.Group, f.Exposure, f.Module, f.Target = hh.group, hh.exposure, "docker", "image:"+c.image
					inUse := true
					f.ImageInUse = &inUse
				} else {
					f.Group, f.Exposure, f.Module, f.Target, f.Image = h, 2, "k8s", c.where, c.image
				}
				out = append(out, f)
			}
		}
	}
	return out
}

func hostNamed(name string) host {
	for _, h := range hosts {
		if h.name == name {
			return h
		}
	}
	return host{}
}

func writeHostFiles(r *rand.Rand, dir string, h host, day int) error {
	if err := mkdirAll(dir, 0o755); err != nil {
		return err
	}
	pw := h.exposure == 1 && day < 24
	var accepted []any
	for i, u := range []string{"deploy", "alice", "bob", "root"} {
		if u == "root" && h.exposure != 3 {
			continue
		}
		accepted = append(accepted, map[string]any{"user": u, "ip": fmt.Sprintf("198.51.100.%d", 40+i), "method": "publickey",
			"count": 3 + r.IntN(60), "first": "2026-10-09T08:12:00", "last": fmt.Sprintf("2026-11-%02dT%02d:%02d:00", 1+r.IntN(7), 8+r.IntN(10), r.IntN(60))})
	}
	var attackers []any
	failed := 0
	if h.exposure == 1 {
		for i := range 6 {
			n := 50 + r.IntN(900)
			failed += n
			attackers = append(attackers, map[string]any{"ip": fmt.Sprintf("203.0.113.%d", 60+i*7), "n": n, "first": "2026-10-20T01:00:00",
				"last": fmt.Sprintf("2026-11-%02dT0%d:%02d:00", 1+r.IntN(7), r.IntN(9), r.IntN(60)), "users": []any{[]any{"root", n / 2}, []any{"admin", n / 4}, []any{"oracle", n / 8}}})
		}
	}
	keys := []any{map[string]any{"user": "deploy", "file": "/home/deploy/.ssh/authorized_keys", "type": "ssh-ed25519",
		"fp": "SHA256:demoKeyDeploy000000000000000000000000000001", "comment": "ci@example.com", "options": ""}}
	if h.exposure == 3 {
		keys = append(keys, map[string]any{"user": "root", "file": "/root/.ssh/authorized_keys", "type": "ssh-rsa",
			"fp": "SHA256:demoKeyRoot00000000000000000000000000000002", "comment": "ops@example.com", "options": ""})
	}
	users := []any{}
	if pw {
		users = []any{"admin"}
	}
	access := map[string]any{"sshd": map[string]any{"port": "22", "permitrootlogin": "without-password", "passwordauthentication": map[bool]string{true: "yes", false: "no"}[pw]},
		"sshd_source": "sshd -T", "password_auth": pw, "password_auth_match_users": []any{}, "users_with_password": users, "keys": keys,
		"logins": map[string]any{"accepted": accepted, "failed_total": failed, "failed_ips": len(attackers) * 9, "attackers": attackers,
			"failed_top_ips": []any{}, "failed_daily": map[string]any{}}, "denied": []any{}}
	if failed > 0 { // the last day of the log
		access["logins"].(map[string]any)["failed_daily"] = map[string]any{"2026-11-07": failed / 12}
	}
	if h.name == partialHost { // no sudo: who has a password and the login log were not readable
		access["users_with_password"], access["denied"] = nil, []any{"denied.shadow", "denied.authlog"}
	}
	listen := []any{map[string]any{"proto": "tcp", "addr": "*", "port": 22, "process": "sshd", "public": h.exposure == 1}}
	if groupOf(h.group).role == "front" && h.group != "bastion" {
		listen = append(listen, map[string]any{"proto": "tcp", "addr": "*", "port": 443, "process": "nginx", "public": true},
			map[string]any{"proto": "tcp", "addr": "*", "port": 80, "process": "nginx", "public": true})
	}
	if h.name == "web-01" {
		listen = append(listen, map[string]any{"proto": "tcp", "addr": "*", "port": 6379, "process": "redis-server", "public": true})
	}
	if h.group == "db" {
		listen = append(listen, map[string]any{"proto": "tcp", "addr": "192.0.2.31", "port": 5432, "process": "postgres"})
	}
	listen = append(listen, map[string]any{"proto": "udp", "addr": "127.0.0.1", "port": 323, "process": "chronyd", "local_only": true})
	public := []any{}
	for _, p := range h.public {
		public = append(public, p)
	}
	exposure := map[string]any{"addresses": []any{}, "public": public, "unlisted_public": []any{}, "listen": listen,
		"firewall": map[string]any{"readable": true, "has_input_filtering": h.name != "web-01", "firewalld": nil, "ufw_active": h.family == "deb",
			"iptables_input_policy": map[bool]string{true: "DROP", false: "ACCEPT"}[h.name != "web-01"], "docker_rules": h.group == "api"},
		"firewall_raw": map[string]any{"iptables": "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT"}, "denied": []any{}}
	use := 35 + r.IntN(30)
	if h.name == "db-01" {
		use = 70 + day
	}
	health := map[string]any{"disks": []any{map[string]any{"fs": "/dev/sda1", "mount": "/", "use": use}, map[string]any{"fs": "/dev/sdb1", "mount": "/var", "use": 20 + r.IntN(40)}},
		"inodes": []any{map[string]any{"fs": "/dev/sda1", "mount": "/", "use": 4 + r.IntN(10)}},
		"mem":    map[string]any{"total_mb": 8192, "available_mb": 2000 + r.IntN(4000)}, "load": map[string]any{"load1": 0.4, "load15": float64(r.IntN(30)) / 10, "cpus": 4},
		"failed_units": []any{}, "readonly_mounts": []any{}, "journal": map[string]any{"errors_7d": r.IntN(40)},
		"time":   map[string]any{"timezone": "Etc/UTC", "synced": "yes", "service": "chronyd", "service_active": true, "offset_s": float64(r.IntN(9)) / 1000, "skew_s": 0.1},
		"denied": []any{}}
	if h.name == "app-02" {
		health["failed_units"] = []any{"celery-worker.service"}
	}
	facts := map[string]any{"os_release": map[string]any{"PRETTY_NAME": h.os}, "uname": "Linux " + h.kernel + " x86_64", "hostname": h.name}
	for name, v := range map[string]any{"access.json": access, "exposure.json": exposure, "health.json": health, "facts.json": facts} {
		if err := writeJSON(filepath.Join(dir, name), v); err != nil {
			return err
		}
	}
	return nil
}

func orgFile(last time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, `org:
  id: acme
  name: "ACME Corp"
  contacts:
    - name: Alice Smith
      email: it@example.com
      role: admin
consent:
  document: "Audit agreement #42, appendix 3"
  signed: %s
  valid_until: %s
  external_scan: true
access:
  user: audit
  key: acme/id_ed25519
  host_key_checking: accept-new
  jumps:
    bastion:
      address: 203.0.113.10
groups:
`, last.AddDate(0, -2, 0).Format(time.DateOnly), last.AddDate(1, 0, 0).Format(time.DateOnly))
	for _, g := range groups {
		fmt.Fprintf(&b, "  %s:\n    role: %s\n    env: %s\n    exposure: %d\n", g.name, g.role, g.env, g.exposure)
		if g.name != "bastion" && g.env == "production" {
			b.WriteString("    jump: bastion\n")
		}
		b.WriteString("    hosts:\n")
		for _, h := range hosts {
			if h.group == g.name {
				fmt.Fprintf(&b, "      %s:\n        address: %s\n", h.name, h.addr)
			}
		}
		if g.name == "mon" {
			fmt.Fprintf(&b, "      %s:\n        address: 192.0.2.250\n", newHost)
		}
	}
	b.WriteString("k8s:\n  - name: prod-eu\n    env: production\n    kubeconfig: acme/kubeconfig-prod-eu\n    namespaces: [jobs, ingress-nginx]\n    exposure: 2\n")
	b.WriteString("external:\n  production: [203.0.113.10, 203.0.113.11]\n")
	return b.String()
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return writeFile(path, b, 0o644)
}
