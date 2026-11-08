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
	"sort"
	"strings"
	"time"

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

var hosts = []host{
	{"web-01", "front", "production", "192.0.2.11", "Debian GNU/Linux 12 (bookworm)", "6.1.0-18-amd64", "deb", 1, []string{"203.0.113.11"},
		[]string{"openssl", "nginx", "libc6", "curl", "openssh-server", "libxml2", "systemd", "linux-image-6.1.0-18-amd64"}},
	{"web-02", "front", "production", "192.0.2.12", "Debian GNU/Linux 12 (bookworm)", "6.1.0-18-amd64", "deb", 1, []string{"203.0.113.12"},
		[]string{"openssl", "nginx", "libc6", "curl", "openssh-server", "libxml2", "linux-image-6.1.0-18-amd64"}},
	{"app-01", "app", "production", "192.0.2.21", "Ubuntu 22.04.5 LTS", "5.15.0-119-generic", "deb", 2, nil,
		[]string{"python3.10", "libssl3", "sudo", "git", "openssh-server", "libexpat1", "linux-image-5.15.0-119-generic"}},
	{"app-02", "app", "production", "192.0.2.22", "Ubuntu 22.04.5 LTS", "5.15.0-119-generic", "deb", 2, nil,
		[]string{"python3.10", "libssl3", "sudo", "openssh-server", "libexpat1", "linux-image-5.15.0-119-generic"}},
	{"db-01", "db", "production", "192.0.2.31", "Rocky Linux 9.4 (Blue Onyx)", "5.14.0-427.el9.x86_64", "rpm", 3, nil,
		[]string{"postgresql-server", "glibc", "openssl-libs", "kernel-core", "sudo", "libxml2"}},
	{"cache-01", "db", "production", "192.0.2.32", "Ubuntu 18.04.6 LTS", "4.15.0-213-generic", "deb", 3, nil,
		[]string{"redis-server", "libssl1.1", "openssh-server", "libc6", "linux-image-4.15.0-213-generic"}},
	{"bastion-01", "bastion", "production", "192.0.2.5", "Debian GNU/Linux 11 (bullseye)", "5.10.0-30-amd64", "deb", 1, []string{"203.0.113.5"},
		[]string{"openssh-server", "openssl", "sudo", "libc6"}},
	{"stage-web-01", "stage", "staging", "198.51.100.11", "Debian GNU/Linux 12 (bookworm)", "6.1.0-18-amd64", "deb", 2, nil,
		[]string{"openssl", "nginx", "curl", "libxml2"}},
	{"stage-app-01", "stage", "staging", "198.51.100.21", "Ubuntu 22.04.5 LTS", "5.15.0-119-generic", "deb", 3, nil,
		[]string{"python3.10", "libssl3", "git"}},
}

// vuln: one made-up CVE on a package of a host, present from day `from` until day `fixed` (exclusive; -1: never).
type vuln struct {
	host, pkg, id, sev, installed, fixedIn string
	from, fixed                            int
	kev, rce                               bool
	epss                                   float64
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
		for d := 0; d < days; d++ {
			started := last.AddDate(0, 0, d-days+1).Add(3 * time.Hour)
			if err := saveRun(r, envDir, org, env, d, days, started, vulns, pol, feeds); err != nil {
				return err
			}
		}
		if _, err := updateCurrent(envDir, true, false); err != nil {
			return err
		}
	}
	return nil
}

func makeVulns(r *rand.Rand, days int) []vuln {
	var out []vuln
	n := 0
	sevs := []string{"CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "MEDIUM", "LOW"}
	for _, h := range hosts {
		for _, p := range h.pkgs {
			// a package is updated all at once: its CVEs share the day they go; most are updated during the month,
			// some show up during it (a new advisory), the rest wait
			from, fixed := 0, -1
			switch x := r.IntN(20); {
			case x < 13:
				fixed = 1 + int(float64(days-2)*r.Float64()*r.Float64()) // earlier more often: the urgent ones first
			case x < 16:
				from = min(4, days-1) + r.IntN(max(days-6, 1))
			}
			k := 2 + r.IntN(4)
			if strings.HasPrefix(p, "linux-image") || p == "kernel-core" {
				k += 4
			}
			installed := fmt.Sprintf("%d.%d.%d", 1+r.IntN(3), r.IntN(20), r.IntN(10))
			for range k {
				n++
				v := vuln{host: h.name, pkg: p, id: fmt.Sprintf("CVE-0000-9%04d", n), sev: sevs[r.IntN(len(sevs))],
					installed: installed, fixedIn: installed + "-1", from: from, fixed: fixed, epss: r.Float64() * 0.2}
				if r.IntN(12) == 0 {
					v.kev, v.epss = true, 0.6+r.Float64()*0.39
				}
				v.rce = v.sev == "CRITICAL" && r.IntN(2) == 0
				out = append(out, v)
			}
		}
	}
	return out
}

func saveRun(r *rand.Rand, envDir string, org *config.Org, env string, day, days int, started time.Time,
	vulns []vuln, pol *priority.Policy, feeds priority.Feeds) error {
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
		if h.name == "cache-01" && day%9 == 4 { // a flaky one
			failed.Set(h.name, "unreachable: dial tcp 192.0.2.32:22: i/o timeout")
			continue
		}
		if err := writeHostFiles(r, filepath.Join(runDir, "hosts", h.name), h, day); err != nil {
			return err
		}
		base := finding.Finding{Org: "acme", Host: h.name, Group: h.group, Exposure: h.exposure}
		for _, v := range vulns {
			if v.host != h.name || day < v.from || v.fixed >= 0 && day >= v.fixed {
				continue
			}
			f := base
			f.Module, f.Kind, f.ID, f.Pkg, f.Installed, f.Fixed, f.Status, f.Severity = "os_packages", finding.Vuln, v.id, v.pkg,
				v.installed, v.fixedIn, "fixed", v.sev
			f.Title, f.Target, f.FixState, f.RCE, f.Preauth = v.pkg+": made-up vulnerability", "os", "available", v.rce, v.rce
			f.Kernel = strings.HasPrefix(v.pkg, "linux-image") || v.pkg == "kernel-core"
			f.URL = "https://example.com/" + v.id
			fs = append(fs, f)
		}
		misc := func(module, kind, id, sev string, title, target i18n.Text) {
			f := base
			f.Module, f.Kind, f.ID, f.Severity = module, kind, id, sev
			f.Title, f.Msg, f.Args, f.Target, f.TargetMsg, f.TargetArgs = title.Text, title.Key, title.Args, target.Text, target.Key, target.Args
			fs = append(fs, f)
		}
		if h.exposure == 1 && day < days-6 {
			misc("access", finding.Misconfig, "ssh-password-auth", "HIGH", i18n.Msg("ssh.password", nil), i18n.Plain("PasswordAuthentication yes"))
		}
		if h.name == "web-01" {
			misc("exposure", finding.Misconfig, "listen-public-6379-tcp", "HIGH",
				i18n.Msg("net.close", map[string]any{"service": "redis", "port": 6379}), i18n.Plain("tcp *:6379 redis-server"))
		}
		if h.name == "cache-01" {
			misc("health", finding.Misconfig, "os-eol", "HIGH", i18n.Msg("os.eol", map[string]any{"name": "Ubuntu 18.04"}), i18n.Msg("os.eol.detail", nil))
		}
		if h.name == "db-01" && day > days-10 {
			use := 80 + (day - (days - 10))
			misc("health", finding.Health, "disk-/var", "MEDIUM", i18n.Msg("health.disk", map[string]any{"mount": "/var/lib/pgsql", "use": use}), i18n.Plain(""))
		}
		if h.exposure == 1 {
			misc("access", finding.Inventory, "ssh-bruteforce", "MEDIUM",
				i18n.Msg("ssh.bruteforce", map[string]any{"n": 3000 + r.IntN(4000), "ips": 40 + r.IntN(60)}), i18n.Plain("203.0.113.66 (812)"))
		}
	}
	fs = priority.Apply(fs, org, pol, feeds, started)
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
	listen := []any{map[string]any{"proto": "tcp", "addr": "*", "port": 22, "process": "sshd", "public": h.exposure == 1}}
	if h.group == "front" {
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
			"iptables_input_policy": map[bool]string{true: "DROP", false: "ACCEPT"}[h.name != "web-01"], "docker_rules": h.group == "app"},
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
      address: 203.0.113.5
groups:
`, last.AddDate(0, -2, 0).Format(time.DateOnly), last.AddDate(1, 0, 0).Format(time.DateOnly))
	groups := map[string][]host{}
	var order []string
	for _, h := range hosts {
		if groups[h.group] == nil {
			order = append(order, h.group)
		}
		groups[h.group] = append(groups[h.group], h)
	}
	roles := map[string]string{"front": "front", "app": "app", "db": "internal", "bastion": "front", "stage": "app"}
	for _, g := range order {
		h0 := groups[g][0]
		fmt.Fprintf(&b, "  %s:\n    role: %s\n    env: %s\n    exposure: %d\n", g, roles[g], h0.env, h0.exposure)
		if g != "bastion" && h0.env == "production" {
			b.WriteString("    jump: bastion\n")
		}
		b.WriteString("    hosts:\n")
		for _, h := range groups[g] {
			fmt.Fprintf(&b, "      %s:\n        address: %s\n", h.name, h.addr)
		}
	}
	b.WriteString("external:\n  production: [203.0.113.11, 203.0.113.12]\n")
	return b.String()
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return writeFile(path, b, 0o644)
}
