package priority

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
)

var root, _ = filepath.Abs("../..")

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// acme: orgs/_example.yml loaded the regular way (its exception: CVE-2023-4911 on ci-01, glibc, review 2026-12-15).
func acme(t *testing.T) *config.Org {
	t.Helper()
	p := config.PathsAt(t.TempDir())
	must(t, os.MkdirAll(p.Orgs, 0o755))
	b, err := os.ReadFile(filepath.Join(root, "orgs", "_example.yml"))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(p.Orgs, "acme.yml"), b, 0o644))
	l, err := config.NewLoader(p)
	must(t, err)
	orgs, errs := l.LoadAll()
	if len(errs) > 0 || len(orgs) == 0 {
		t.Fatal(errs)
	}
	return orgs[0]
}

func policy(t *testing.T) *Policy {
	t.Helper()
	pol, err := LoadPolicy(config.PathsAt(t.TempDir())) // no policy/ there: the built-in one
	must(t, err)
	return pol
}

func f(id string, mod func(*finding.Finding)) finding.Finding {
	x := finding.Finding{Org: "acme", Host: "web-01", Module: "os_packages", Kind: finding.Vuln, ID: id, Pkg: "openssl",
		Installed: "1", Fixed: "2", Severity: "HIGH", Exposure: 1, Target: "os"}
	if mod != nil {
		mod(&x)
	}
	return x
}

func day(s string) time.Time { d, _ := time.Parse(time.DateOnly, s); return d }

func TestPriorityAndExceptions(t *testing.T) {
	org, pol := acme(t), policy(t)
	feeds := Feeds{KEV: map[string]bool{"CVE-KEV": true}, EPSS: map[string]float64{"CVE-EPSS": 0.9}}
	sev := func(s string, e int) func(*finding.Finding) {
		return func(x *finding.Finding) { x.Severity, x.Exposure = s, e }
	}
	fs := Apply([]finding.Finding{
		f("CVE-KEV", sev("LOW", 3)),
		f("CVE-KEV", sev("LOW", 1)),
		f("CVE-1", sev("CRITICAL", 1)),
		f("CVE-EPSS", sev("MEDIUM", 2)),
		f("CVE-1", sev("LOW", 3)),
		f("CVE-2023-4911", func(x *finding.Finding) { x.Host, x.Pkg, x.Exposure = "ci-01", "glibc", 3 }),
	}, org, pol, feeds, day("2026-11-01"))
	var got []string
	for _, x := range fs {
		got = append(got, x.PriorityOr())
	}
	if !slices.Equal(got, []string{"P2", "P1", "P1", "P2", "P4", "P3"}) {
		t.Fatal(got)
	}
	if fs[1].DueOr() != "2026-11-08" || !fs[5].Accepted || fs[5].Exception.Expired {
		t.Fatal(fs[1].DueOr(), fs[5].Accepted, fs[5].Exception)
	}
	fs = Apply([]finding.Finding{f("CVE-2023-4911", func(x *finding.Finding) { x.Host, x.Pkg = "ci-01", "glibc" })},
		org, pol, feeds, day("2027-01-01"))
	if fs[0].Accepted || !fs[0].Exception.Expired {
		t.Fatal(fs[0])
	}
}

func setExceptions(org *config.Org, ex ...map[string]any) {
	l := make([]any, len(ex))
	for i, e := range ex {
		l[i] = e
	}
	org.Data["exceptions"] = l
}

func TestExceptionUntilAvailable(t *testing.T) {
	org, pol := acme(t), policy(t)
	setExceptions(org, map[string]any{"id": "CVE-V", "package": "rsync", "reason": "no fix yet", "owner": "x",
		"review_by": "2026-12-31", "until_available": true})
	state := func(s string) func(*finding.Finding) {
		return func(x *finding.Finding) { x.Pkg, x.FixState = "rsync", s }
	}
	fs := Apply([]finding.Finding{f("CVE-V", state("vendor")), f("CVE-V", state("available"))}, org, pol, Feeds{},
		day("2026-11-02"))
	if !fs[0].Accepted || fs[1].Accepted || !fs[1].Exception.FixAvailable {
		t.Fatal(fs[0].Accepted, fs[1].Accepted, fs[1].Exception)
	}
	setExceptions(org, map[string]any{"id": "*", "package": "rsync", "reason": "r", "owner": "x",
		"review_by": "2026-12-31", "until_available": true},
		map[string]any{"id": "*", "reason": "no package: ignored", "owner": "x", "review_by": "2026-12-31"})
	fs = Apply([]finding.Finding{f("CVE-NEW", state("vendor")), f("CVE-NEW", nil)}, org, pol, Feeds{}, day("2026-11-02"))
	if !fs[0].Accepted || fs[1].Accepted {
		t.Fatal(fs[0].Accepted, fs[1].Accepted)
	}
}

func TestBadPolicyRejected(t *testing.T) {
	for _, y := range []string{"rules: x", "rules:\n  - when: {}", "rules:\n  - priority: P1\n    when: {exposure: 1}",
		"rules:\n  - priority: P1\n    when: {epss_gte: high}", "rules: []\nsla_days: {P1: soon}"} {
		if _, err := ParsePolicy([]byte(y)); err == nil {
			t.Errorf("%q accepted", y)
		}
	}
}

func TestFeedsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KANAREIKA_FEEDS_DIR", dir)
	if FeedsDir() != dir {
		t.Fatal(FeedsDir())
	}
	fd, err := LoadFeeds() // nothing downloaded yet
	if err != nil || len(fd.KEV) != 0 || fd.Updated != "" {
		t.Fatal(fd, err)
	}
	// files as the Python version wrote them
	must(t, os.WriteFile(filepath.Join(dir, "kev.json"), []byte(`["CVE-2021-44228", "CVE-2024-3094"]`), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "epss.json"), []byte(`{"CVE-2021-44228": 0.94358, "CVE-1": 1e-05}`), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "updated"), []byte("2026-11-01T10:00:00.123456+00:00"), 0o644))
	fd, err = LoadFeeds()
	if err != nil || !fd.KEV["CVE-2024-3094"] || fd.EPSS["CVE-1"] != 1e-05 || fd.Updated != "2026-11-01T10:00:00.123456+00:00" {
		t.Fatal(fd, err)
	}
}

// testdata/python.json: recorded with the former Python implementation: findings sampled from a real run (findings.json,
// anonymized; with the KEV ids / EPSS scores they had), the default policy and policy-edge.yml, a set of exceptions,
// three scan dates. Recorded once with the former Python implementation (removed from the repo; the Go port had to
// match it) and kept as a frozen fixture: a change here is a behaviour change — review it as such.
func TestMatchesPython(t *testing.T) {
	var in struct {
		Findings []finding.Finding `json:"findings"`
		KEV      []string          `json:"kev"`
		EPSS     map[string]float64
	}
	var g struct {
		Exceptions []any                        `json:"exceptions"`
		Runs       map[string][]json.RawMessage `json:"runs"`
	}
	for name, v := range map[string]any{"findings.json": &in, "python.json": &g} {
		b, err := os.ReadFile("testdata/" + name)
		must(t, err)
		must(t, json.Unmarshal(b, v))
	}
	feeds := Feeds{KEV: map[string]bool{}, EPSS: in.EPSS}
	for _, id := range in.KEV {
		feeds.KEV[id] = true
	}
	org := &config.Org{ID: "acme", Data: map[string]any{"exceptions": g.Exceptions}}
	b, err := os.ReadFile("testdata/policy-edge.yml")
	must(t, err)
	edge, err := ParsePolicy(b)
	must(t, err)
	pols := map[string]*Policy{"default": policy(t), "edge": edge}
	if len(g.Runs) != 6 {
		t.Fatal(len(g.Runs))
	}
	type out struct {
		KEV       bool               `json:"kev"`
		EPSS      *float64           `json:"epss"`
		Priority  *string            `json:"priority"`
		Due       *string            `json:"due"`
		Accepted  bool               `json:"accepted"`
		Exception *finding.Exception `json:"exception"`
	}
	for name, want := range g.Runs {
		pname, date, _ := strings.Cut(name, " ")
		fs := Apply(slices.Clone(in.Findings), org, pols[pname], feeds, day(date))
		for i, x := range fs {
			var w out
			must(t, json.Unmarshal(want[i], &w))
			got := out{x.KEV, x.EPSS, x.Priority, x.Due, x.Accepted, x.Exception}
			if !reflect.DeepEqual(got, w) {
				gb, _ := json.Marshal(got)
				t.Errorf("%s: %s %s %s: %s, want %s", name, x.Host, x.ID, x.Pkg, gb, want[i])
			}
		}
	}
}
