package priority

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// prevOf: a Prev that knows one earlier finding, whatever is asked.
func prevOf(p *finding.Finding) Prev { return func(*finding.Finding) *finding.Finding { return p } }

func prioritized(t *testing.T, x finding.Finding, prev Prev, at string, mods ...func(*Policy)) finding.Finding {
	t.Helper()
	pol := policy(t)
	for _, m := range mods {
		m(pol)
	}
	fs, err := Apply([]finding.Finding{x}, acme(t), "production", pol, Feeds{KEVDue: map[string]string{"CVE-KEV": "2026-11-05"}}, day(at), prev)
	must(t, err)
	return fs[0]
}

func start(s string) func(*Policy) { return func(p *Policy) { p.Due.Start = s } }

func due(x finding.Finding) string { return x.DueOr() + " " + x.DueWhy + " " + x.ClockStart }

// TestDueClock: the clock counts from the first scan that saw the finding, not from every scan.
func TestDueClock(t *testing.T) {
	high := f("CVE-1", nil) // HIGH, perimeter, fixable: P2, 30 days
	if got := prioritized(t, high, nil, "2026-11-08"); got.PriorityOr() != "P2" || due(got) != "2026-12-08 first_seen 2026-11-08" ||
		got.FirstSeen != "2026-11-08" || got.FixSince != "2026-11-08" {
		t.Fatalf("new: %s %+v", due(got), got)
	}
	old := finding.Finding{Priority: ptr("P2"), FirstSeen: "2026-09-01", FixSince: "2026-09-15"}
	got := prioritized(t, high, prevOf(&old), "2026-11-08")
	if due(got) != "2026-10-01 first_seen 2026-09-01" || got.FirstSeen != "2026-09-01" || got.FixSince != "2026-09-15" {
		t.Fatalf("seen in September: overdue now, not 30 days from today: %s", due(got))
	}
	if got := prioritized(t, high, prevOf(&old), "2026-11-08", start("scan")); due(got) != "2026-12-08 scan 2026-11-08" {
		t.Fatalf("start: scan is the old behaviour: %s", due(got))
	}
	if got := prioritized(t, high, prevOf(&old), "2026-11-08", start("fix_available")); due(got) != "2026-10-15 fix_available 2026-09-15" {
		t.Fatalf("from the fix: %s", due(got))
	}
	vendor := f("CVE-1", func(x *finding.Finding) { x.FixState = finding.FixVendor })
	if got := prioritized(t, vendor, prevOf(&old), "2026-11-08", start("fix_available")); got.Due != nil ||
		got.DueWhy != finding.DueNoFix || got.FixSince != "" {
		t.Fatalf("no fix in the repositories: no date yet: %s %q", due(got), got.FixSince)
	}
	pub := f("CVE-1", func(x *finding.Finding) { x.Published = "2026-08-01" })
	if got := prioritized(t, pub, nil, "2026-11-08", start("published")); due(got) != "2026-08-31 published 2026-08-01" {
		t.Fatalf("from publication: %s", due(got))
	}
	if got := prioritized(t, high, nil, "2026-11-08", start("published")); due(got) != "2026-12-08 first_seen 2026-11-08" {
		t.Fatalf("no publication date: first seen: %s", due(got))
	}
	misconf := f("ssh-password", func(x *finding.Finding) { x.Kind, x.Fixed, x.Pkg = finding.Misconfig, "", "" })
	if got := prioritized(t, misconf, prevOf(&old), "2026-11-08", start("fix_available")); got.FixSince != "2026-09-01" {
		t.Fatalf("a misconfiguration is fixable since it was seen: %q", got.FixSince)
	}
	inv := f("ssh-bruteforce", func(x *finding.Finding) { x.Kind = finding.Inventory })
	if got := prioritized(t, inv, nil, "2026-11-08"); got.Due != nil || got.DueWhy != "" {
		t.Fatalf("inventory has no due date: %s", due(got))
	}
	future := finding.Finding{Priority: ptr("P2"), FirstSeen: "2027-01-01"}
	if got := prioritized(t, high, prevOf(&future), "2026-11-08"); got.FirstSeen != "2026-11-08" {
		t.Fatalf("a first_seen after today (clock skew, restored backup) is not trusted: %q", got.FirstSeen)
	}
}

// TestDueEscalation: going up restarts the clock with the new SLA, never later than before; it sticks while the
// priority stays.
func TestDueEscalation(t *testing.T) {
	crit := f("CVE-1", func(x *finding.Finding) { x.Severity = "CRITICAL" }) // P1, 7 days
	was := finding.Finding{Priority: ptr("P3"), FirstSeen: "2026-06-01", Due: ptr("2026-08-30"), DueWhy: finding.DueFirstSeen}
	got := prioritized(t, crit, prevOf(&was), "2026-11-08")
	if got.PriorityOr() != "P1" || due(got) != "2026-08-30 escalated 2026-11-08" {
		t.Fatalf("already overdue as P3: stays at its date: %s", due(got))
	}
	was.Due = ptr("2027-01-01")
	got = prioritized(t, crit, prevOf(&was), "2026-11-08")
	if due(got) != "2026-11-15 escalated 2026-11-08" {
		t.Fatalf("P3 -> P1: 7 days from today, not from June: %s", due(got))
	}
	again := prioritized(t, crit, prevOf(&got), "2026-11-10")
	if due(again) != "2026-11-15 escalated 2026-11-08" {
		t.Fatalf("the next scan keeps the restarted clock: %s", due(again))
	}
	keep := prioritized(t, crit, prevOf(&was), "2026-11-08", func(p *Policy) { p.Due.Escalation = "keep" })
	if due(keep) != "2026-06-08 first_seen 2026-06-01" {
		t.Fatalf("escalation: keep: %s", due(keep))
	}
	down := finding.Finding{Priority: ptr("P1"), FirstSeen: "2026-10-01", Due: ptr("2026-10-08"), DueWhy: finding.DueEscalated,
		ClockStart: "2026-10-01"}
	if got := prioritized(t, f("CVE-1", nil), prevOf(&down), "2026-11-08"); due(got) != "2026-10-31 first_seen 2026-10-01" {
		t.Fatalf("P1 -> P2: the P2 SLA from first seen: %s", due(got))
	}
}

// TestDueAfterException: an accepted risk that ends starts the clock again that day.
func TestDueAfterException(t *testing.T) {
	was := finding.Finding{Priority: ptr("P2"), FirstSeen: "2026-01-01", Accepted: true}
	got := prioritized(t, f("CVE-1", nil), prevOf(&was), "2026-11-08")
	if due(got) != "2026-12-08 exception_ended 2026-11-08" {
		t.Fatalf("%s", due(got))
	}
	if got := prioritized(t, f("CVE-1", nil), prevOf(&was), "2026-11-08", func(p *Policy) { p.Due.AfterException = "keep" }); due(got) != "2026-01-31 first_seen 2026-01-01" {
		t.Fatalf("after_exception: keep: %s", due(got))
	}
}

// TestDueKEV: CISA's date comes first when it is earlier; kev: off ignores it.
func TestDueKEV(t *testing.T) {
	kev := f("CVE-KEV", nil)
	if got := prioritized(t, kev, nil, "2026-11-01"); due(got) != "2026-11-05 kev 2026-11-01" || got.KEVDue != "2026-11-05" {
		t.Fatalf("%s %q", due(got), got.KEVDue)
	}
	if got := prioritized(t, kev, nil, "2026-11-01", func(p *Policy) { p.Due.KEV = "off" }); got.DueOr() == "2026-11-05" {
		t.Fatalf("kev: off: %s", due(got))
	}
	notVuln := f("CVE-KEV", func(x *finding.Finding) { x.Kind = finding.Misconfig })
	if got := prioritized(t, notVuln, nil, "2026-11-01"); got.KEVDue != "" {
		t.Fatal("KEV dates belong to vulnerabilities only")
	}
}

// TestDueFor: the policy's rules, then the org's due block, then its envs.<env> block; bad values are errors.
func TestDueFor(t *testing.T) {
	pol, err := ParsePolicy([]byte("rules: []\nsla_days: {P1: 7, P2: 30}\ndue: {start: fix_available, sla_days: {P2: 21}}"))
	must(t, err)
	if pol.Due.Start != "fix_available" || pol.Due.SLADays["P1"] != 7 || pol.Due.SLADays["P2"] != 21 || pol.SLADays["P2"] != 21 ||
		pol.Due.KEV != "cisa" {
		t.Fatalf("%+v", pol.Due)
	}
	org := acme(t)
	org.Data["due"] = map[string]any{"sla_days": map[string]any{"P1": 3.0}, "envs": map[string]any{
		"staging": map[string]any{"sla_days": map[string]any{"P1": 14.0}, "kev": "off"}}}
	prod, err := pol.DueFor(org, "production")
	must(t, err)
	stg, err := pol.DueFor(org, "staging")
	must(t, err)
	if prod.SLADays["P1"] != 3 || prod.SLADays["P2"] != 21 || prod.KEV != "cisa" || stg.SLADays["P1"] != 14 || stg.KEV != "off" ||
		pol.Due.SLADays["P1"] != 7 {
		t.Fatalf("prod %+v staging %+v policy %+v", prod, stg, pol.Due)
	}
	for _, bad := range []map[string]any{
		{"start": "yesterday"}, {"kev": true}, {"sla_days": "7"}, {"sla_days": map[string]any{"P1": -1.0}},
		{"color": "red"}, {"envs": map[string]any{"x": map[string]any{"envs": map[string]any{}}}},
		{"envs": map[string]any{"x": map[string]any{"escalation": "maybe"}}},
	} {
		org.Data["due"] = bad
		if _, err := pol.DueFor(org, "x"); err == nil {
			t.Errorf("%v accepted", bad)
		}
		if _, err := Apply([]finding.Finding{f("CVE-1", nil)}, org, "x", pol, Feeds{}, day("2026-11-08"), nil); err == nil {
			t.Errorf("Apply with %v: no error", bad)
		}
	}
	for _, y := range []string{"rules: []\ndue: {start: never}", "rules: []\ndue: {envs: {prod: {}}}", "rules: []\ndue: {sla_days: {P1: x}}"} {
		if _, err := ParsePolicy([]byte(y)); err == nil {
			t.Errorf("%q accepted", y)
		}
	}
	if d, err := (&Policy{SLADays: map[string]float64{"P1": 5}}).DueFor(nil, "x"); err != nil || d.SLADays["P1"] != 5 || d.Start != "first_seen" {
		t.Fatalf("a Policy built in code: %+v %v", d, err)
	}
}

// TestKEVDueDates: CISA's due dates are stored next to the ids (the earliest when a CVE is listed twice);
// feeds downloaded before 0.5 have none.
func TestKEVDueDates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "feeds")
	t.Setenv("KANAREIKA_FEEDS_DIR", dir)
	kev := `{"vulnerabilities":[{"cveID":"CVE-2026-0002","dueDate":"2026-12-01"},{"cveID":"CVE-2026-0001","dueDate":"bad"},` +
		`{"cveID":"CVE-2026-0002","dueDate":"2026-11-20"}]}`
	srv := feedServer(t, map[string][]byte{"/kev.json": []byte(kev), "/epss.csv.gz": gz(epssCSV)})
	_, err := UpdateFeeds(context.Background(), &Policy{KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz"})
	must(t, err)
	fd, err := LoadFeeds()
	must(t, err)
	if len(fd.KEV) != 2 || fd.KEVDue["CVE-2026-0002"] != "2026-11-20" || fd.KEVDue["CVE-2026-0001"] != "" {
		t.Fatalf("%+v", fd.KEVDue)
	}
	must(t, os.Remove(filepath.Join(dir, "kev_due.json")))
	if fd, err = LoadFeeds(); err != nil || len(fd.KEVDue) != 0 || len(fd.KEV) != 2 {
		t.Fatal(fd, err)
	}
	must(t, os.WriteFile(filepath.Join(dir, "kev_due.json"), []byte("{"), 0o644))
	if _, err = LoadFeeds(); err == nil || !strings.Contains(err.Error(), "kev_due.json") {
		t.Fatal(err)
	}
}

func ptr(s string) *string { return &s }

// TestRefreshScores: KEV and EPSS are fetched when missing or older than maxAge, left alone otherwise; the IP
// databases are not touched.
func TestRefreshScores(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "feeds")
	t.Setenv("KANAREIKA_FEEDS_DIR", dir)
	hits := 0
	srv := feedServer(t, map[string][]byte{"/kev.json": []byte(kevJSON), "/epss.csv.gz": gz(epssCSV)})
	pol := &Policy{KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz"}
	for i, want := range []bool{true, false} {
		got, err := RefreshScores(context.Background(), pol, time.Hour)
		must(t, err)
		if got != want {
			t.Fatalf("call %d: downloaded %v, want %v", i, got, want)
		}
		if got {
			hits++
		}
	}
	if got, err := RefreshScores(context.Background(), pol, 0); err != nil || !got {
		t.Fatal("max age 0: always", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "dbip-city.mmdb")); err == nil || hits != 1 {
		t.Fatal("IP databases are db update's business", hits)
	}
	if _, err := RefreshScores(context.Background(), &Policy{}, 0); err == nil {
		t.Fatal("no feed URLs: an error")
	}
	if _, err := FeedsTime("yesterday"); err == nil {
		t.Fatal("bad stamp")
	}
}
