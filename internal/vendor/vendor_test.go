package vendor

import (
	"encoding/json"
	"maps"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
)

func f(id, pkg string, mod func(*finding.Finding)) finding.Finding {
	x := finding.Finding{Org: "acme", Host: "web-01", Module: "os_packages", Kind: finding.Vuln, ID: id, Pkg: pkg,
		Installed: "1", Fixed: "2", Severity: "HIGH", Exposure: 1, Target: "os"}
	if mod != nil {
		mod(&x)
	}
	return x
}

func TestParsers(t *testing.T) {
	cl := ParseChangelog("@sqlite-libs\nCVE-2026-11822\nCVE-2026-11824\n@libbrotli\n@rsync\nCVE-2024-12086\n")
	want := Changelog{"sqlite-libs": {"CVE-2026-11822": true, "CVE-2026-11824": true}, "libbrotli": {},
		"rsync": {"CVE-2024-12086": true}}
	if !reflect.DeepEqual(cl, want) {
		t.Fatal(cl)
	}
	eq := func(got, want map[string]string) {
		t.Helper()
		if (got == nil) != (want == nil) || !maps.Equal(got, want) {
			t.Fatalf("%v, want %v", got, want)
		}
	}
	eq(ParseUpgrades("rpm", "rsync\t3.2.7-1.el9\n@@rc 0\n"), map[string]string{"rsync": "3.2.7-1.el9"})
	eq(ParseUpgrades("rpm", "@@rc 0\n"), map[string]string{}) // asked: nothing to install
	eq(ParseUpgrades("rpm", "Error\n@@rc 1\n"), nil)          // could not ask: unknown
	eq(ParseUpgrades("rpm", "openssl.x86_64  1:1.0.2k-26.el7_9  updates\n@@rc 0\n"),
		map[string]string{"openssl": "1:1.0.2k-26.el7_9"})
	deb := "Listing...\nopenssl/stable-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]\n@@rc 0\n"
	eq(ParseUpgrades("deb", deb), map[string]string{"openssl": "3.0.15-1~deb12u1"})
}

func TestVercmpRpmRules(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0.9-10.el9", "1.0.9-10.el9_8.1", -1}, // the Stream vs RHEL z-stream case
		{"5.14.0-759.el9", "5.14.0-575.el9", 1},
		{"1:1.0-1", "2.0-1", 1}, // epoch wins
		{"1.0~rc1-1", "1.0-1", -1},
		{"2.54.1-1.el9", "2.54.1-1.el9", 0},
	} {
		if got := Vercmp(c.a, c.b); got != c.want {
			t.Errorf("Vercmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAnnotateFixStates(t *testing.T) {
	fs := []finding.Finding{f("CVE-BP", "sqlite-libs", nil), f("CVE-UP", "openssl", nil), f("CVE-V", "libbrotli", nil),
		f("CVE-K", "kernel-core", func(x *finding.Finding) { x.Kernel = true }),
		f("CVE-NOFIX", "vim", func(x *finding.Finding) { x.Fixed = "" }),
		f("CVE-OLD", "kernel-core", func(x *finding.Finding) { x.Inactive = true })}
	n := Annotate(fs, Changelog{"sqlite-libs": {"CVE-BP": true}}, map[string]string{"openssl": "3.5.9-1.el9"},
		"5.14.0-759.el9")
	if !fs[0].Backported || fs[0].FixState != "" {
		t.Fatal(fs[0])
	}
	if fs[1].FixState != "available" || fs[1].RepoVersion != "3.5.9-1.el9" || fs[2].FixState != "vendor" {
		t.Fatal(fs[1], fs[2])
	}
	if fs[3].FixState != "reboot" || fs[3].RepoVersion != "5.14.0-759.el9" || fs[4].FixState != "" || fs[5].FixState != "" {
		t.Fatal(fs[3:])
	}
	if !maps.Equal(n, map[string]int{"backported": 1, "available": 1, "vendor": 1, "reboot": 1}) {
		t.Fatal(n)
	}
	old := []finding.Finding{f("CVE-K2", "kernel-core", func(x *finding.Finding) { x.Kernel = true; x.Fixed = "5.14.0-800.el9" })}
	Annotate(old, Changelog{}, map[string]string{}, "5.14.0-759.el9") // installed kernel is newer, but not fixed yet
	if old[0].FixState != "vendor" {
		t.Fatal(old[0])
	}
	unknown := []finding.Finding{f("CVE-1", "openssl", nil)}
	Annotate(unknown, nil, nil, "") // nothing known: trivy's answer stays as is
	if unknown[0].FixState != "" || unknown[0].Backported {
		t.Fatal(unknown[0])
	}
}

// testdata/python.json: recorded with the former Python implementation over a real host's changelog / upgrades output,
// findings of that host (findings.json, anonymized) and version pairs from real reports plus edge cases
// (vercmp-pairs.json). Recorded once with the former Python implementation (removed from the repo; the Go port had
// to match it) and kept as a frozen fixture: a change here is a behaviour change — review it as such.
type golden struct {
	Queries struct {
		Changelog map[string]string `json:"changelog"`
		Upgrades  map[string]string `json:"upgrades"`
	} `json:"queries"`
	Changelog       map[string]map[string][]string `json:"changelog"`
	ChangelogOrphan map[string][]string            `json:"changelog_orphan"`
	Upgrades        map[string]*map[string]string  `json:"upgrades"`
	UpgradesIn      map[string][2]string           `json:"upgrades_in"`
	Vercmp          []any                          `json:"vercmp"`
	Annotate        map[string]struct {
		Counts map[string]int `json:"counts"`
		Fields []struct {
			Backported  bool   `json:"backported"`
			FixState    string `json:"fix_state"`
			RepoVersion string `json:"repo_version"`
		} `json:"fields"`
	} `json:"annotate"`
}

func load(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, name string) string {
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sets(c Changelog) map[string][]string {
	out := map[string][]string{}
	for p, s := range c {
		out[p] = slices.Sorted(maps.Keys(s))
		if out[p] == nil {
			out[p] = []string{}
		}
	}
	return out
}

func TestMatchesPython(t *testing.T) {
	var g golden
	load(t, "python.json", &g)
	if !maps.Equal(g.Queries.Changelog, ChangelogQuery) || !maps.Equal(g.Queries.Upgrades, UpgradesQuery) {
		t.Error("queries differ")
	}
	cl := map[string]string{"centos9": read(t, "changelog-centos9.txt"),
		"edge": "@a\nCVE-2024-1\nCVE-2024-12345\n  CVE-2024-99999  \nxCVE-2024-12345\nCVE-2024-12345x\n@b c\n@\nCVE-2020-0000\n" +
			"@a\nCVE-2021-11111\n\r\n@ spaced \nCVE-2022-22222\r\n"}
	for k, text := range cl {
		if got := sets(ParseChangelog(text)); !reflect.DeepEqual(got, g.Changelog[k]) {
			t.Errorf("changelog %s differs", k)
		}
	}
	if got := sets(ParseChangelog("CVE-2024-12345\n@x\n")); !reflect.DeepEqual(got, g.ChangelogOrphan) {
		t.Error("orphan CVE", got)
	}
	in := map[string][2]string{"dnf": {"rpm", read(t, "upgrades-dnf.txt")}, "yum": {"rpm", read(t, "upgrades-yum.txt")},
		"apt": {"deb", read(t, "upgrades-apt.txt")}}
	maps.Copy(in, g.UpgradesIn)
	if len(in) != len(g.Upgrades) {
		t.Fatal("upgrades cases")
	}
	for k, c := range in {
		got, want := ParseUpgrades(c[0], c[1]), g.Upgrades[k]
		if (got == nil) != (want == nil) || want != nil && !maps.Equal(got, *want) {
			t.Errorf("upgrades %s: %v, want %v", k, got, want)
		}
	}

	var pairs [][2]string
	load(t, "vercmp-pairs.json", &pairs)
	bad := 0
	for i, p := range pairs {
		want, ok := g.Vercmp[i].(float64)
		if !ok { // Python raised (a non-numeric epoch): no answer to compare with
			bad++
			continue
		}
		if got := Vercmp(p[0], p[1]); got != int(want) {
			t.Errorf("Vercmp(%q, %q) = %d, want %v", p[0], p[1], got, want)
		}
	}
	if bad > len(pairs)/20 {
		t.Errorf("%d pairs without an answer", bad)
	}

	var in2 struct {
		NewerKernel string            `json:"newer_kernel"`
		Findings    []finding.Finding `json:"findings"`
	}
	load(t, "findings.json", &in2)
	changelog := ParseChangelog(cl["centos9"])
	upgrades := ParseUpgrades("rpm", in["dnf"][1])
	runs := map[string]func(fs []finding.Finding) map[string]int{
		"all":         func(fs []finding.Finding) map[string]int { return Annotate(fs, changelog, upgrades, in2.NewerKernel) },
		"no-kernel":   func(fs []finding.Finding) map[string]int { return Annotate(fs, changelog, upgrades, "") },
		"unknown":     func(fs []finding.Finding) map[string]int { return Annotate(fs, nil, nil, "") },
		"no-upgrades": func(fs []finding.Finding) map[string]int { return Annotate(fs, changelog, nil, in2.NewerKernel) },
		"empty": func(fs []finding.Finding) map[string]int {
			return Annotate(fs, Changelog{}, map[string]string{}, in2.NewerKernel)
		},
	}
	for name, run := range runs {
		want := g.Annotate[name]
		fs := slices.Clone(in2.Findings)
		if n := run(fs); !maps.Equal(n, want.Counts) {
			t.Errorf("%s: counts %v, want %v", name, n, want.Counts)
		}
		for i, x := range fs {
			w := want.Fields[i]
			if x.Backported != w.Backported || x.FixState != w.FixState || x.RepoVersion != w.RepoVersion {
				t.Errorf("%s: %s %s: %v %q %q, want %+v", name, x.ID, x.Pkg, x.Backported, x.FixState, x.RepoVersion, w)
			}
		}
	}
}
