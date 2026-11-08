package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOrgFileErrors: what `kanareika validate` says about a wrong org file. Each case breaks the example org one way.
func TestOrgFileErrors(t *testing.T) {
	for _, c := range []struct {
		name  string
		edit  func(d map[string]any)
		parts []string
	}{
		{"id differs from the file name", func(d map[string]any) { mapOf(d["org"])["id"] = "other" },
			[]string{"org.id 'other' must match file name 'acme'"}},
		{"unknown jump of a jump", func(d map[string]any) {
			mapOf(mapOf(mapOf(d["access"])["jumps"])["inner-bastion"])["jump"] = "nowhere"
		}, []string{"jump 'inner-bastion' refers to unknown jump 'nowhere'"}},
		{"jump cycle", func(d map[string]any) {
			mapOf(mapOf(mapOf(d["access"])["jumps"])["bastion"])["jump"] = "inner-bastion"
		}, []string{"jump chain cycle"}},
		{"unknown jump of a host", func(d map[string]any) {
			mapOf(mapOf(mapOf(mapOf(d["groups"])["front"])["hosts"])["web-01"])["jump"] = "ghost"
		}, []string{"host 'web-01' uses unknown jump 'ghost'"}},
		{"group without a role", func(d map[string]any) {
			g := mapOf(d["groups"])
			g["misc"] = map[string]any{"hosts": map[string]any{"misc-01": map[string]any{"address": "192.0.2.99"}}}
		}, []string{"group 'misc' has no valid role"}},
		{"host in two groups", func(d map[string]any) {
			g := mapOf(d["groups"])
			mapOf(mapOf(g["app"])["hosts"])["web-01"] = map[string]any{"address": "192.0.2.11"}
		}, []string{"host 'web-01' defined in groups"}},
		{"org-level check on a host", func(d map[string]any) {
			mapOf(mapOf(mapOf(mapOf(d["groups"])["front"])["hosts"])["web-01"])["checks"] = map[string]any{"k8s": true}
		}, []string{"host 'web-01': 'k8s' can only be set in top-level checks"}},
		{"exception for an unknown host", func(d map[string]any) {
			d["exceptions"] = []any{map[string]any{"id": "CVE-2026-0001", "hosts": []any{"ghost-01"}, "reason": "r",
				"owner": "A", "review_by": "2027-01-01"}}
		}, []string{"refers to unknown host 'ghost-01'"}},
		{"consent ends before it starts", func(d map[string]any) {
			mapOf(d["consent"])["valid_until"] = "2020-01-01"
		}, []string{"consent.valid_until is before consent.signed"}},
		{"unknown timezone", func(d map[string]any) {
			mapOf(mapOf(d["consent"])["window"])["tz"] = "Mars/Olympus"
		}, []string{"unknown timezone 'Mars/Olympus'"}},
		{"schema: wrong type, with where", func(d map[string]any) {
			mapOf(d["access"])["port"] = "twenty-two"
		}, []string{"acme.yml: access/port: got string, want integer"}},
		{"schema: unknown top-level key", func(d map[string]any) { d["colour"] = "blue" }, []string{"acme.yml: <root>:"}},
		{"schema: due start", func(d map[string]any) { d["due"] = map[string]any{"start": "yesterday"} }, []string{"acme.yml: due/start"}},
		{"schema: due days", func(d map[string]any) {
			d["due"] = map[string]any{"envs": map[string]any{"staging": map[string]any{"sla_days": map[string]any{"P1": -3}}}}
		}, []string{"acme.yml: due/envs/staging/sla_days/P1"}},
		{"schema: due unknown key", func(d map[string]any) { d["due"] = map[string]any{"grace": 3} }, []string{"acme.yml: due:"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := home(t)
			f := filepath.Join(p.Orgs, "acme.yml")
			d := readYAML(t, f)
			c.edit(d)
			writeYAML(t, f, d)
			if _, errs := loadAll(t, p); !hasErr(errs, c.parts...) {
				t.Fatalf("want %v in %v", c.parts, errs)
			}
		})
	}
}

// TestDueBlockAccepted: an org's due block with per-environment overrides is valid.
func TestDueBlockAccepted(t *testing.T) {
	p := home(t)
	f := filepath.Join(p.Orgs, "acme.yml")
	d := readYAML(t, f)
	d["due"] = map[string]any{"sla_days": map[string]any{"P1": 3}, "start": "fix_available", "kev": "off",
		"escalation": "keep", "after_exception": "restart",
		"envs": map[string]any{"staging": map[string]any{"sla_days": map[string]any{"P1": 14}, "start": "first_seen"}}}
	writeYAML(t, f, d)
	if _, errs := loadAll(t, p); len(errs) > 0 {
		t.Fatal(errs)
	}
}

// TestBrokenFiles: unreadable, not YAML, empty, and a second file claiming the same org id.
func TestBrokenFiles(t *testing.T) {
	p := home(t)
	must(t, os.WriteFile(filepath.Join(p.Orgs, "bad.yml"), []byte("org: [unclosed"), 0o644))
	must(t, os.WriteFile(filepath.Join(p.Orgs, "empty.yml"), nil, 0o644))
	_, errs := loadAll(t, p)
	if !hasErr(errs, "bad.yml", "YAML error") || !hasErr(errs, "empty.yml") {
		t.Fatal(errs)
	}

	p = home(t)
	must(t, os.Mkdir(filepath.Join(p.Orgs, "dir.yml"), 0o755)) // not a file
	if _, errs := loadAll(t, p); !hasErr(errs, "dir.yml") {
		t.Fatal(errs)
	}

}

// TestBrokenProfiles: a policy override that breaks the schema is reported with where it is wrong.
func TestBrokenProfiles(t *testing.T) {
	p := home(t)
	must(t, os.MkdirAll(p.Policy, 0o755))
	must(t, os.WriteFile(filepath.Join(p.Policy, "profiles.yml"), []byte("roles: 5\n"), 0o644))
	if _, err := NewLoader(p); err == nil {
		t.Fatal("broken profiles accepted")
	}
	must(t, os.WriteFile(filepath.Join(p.Policy, "profiles.yml"), []byte("roles: [\n"), 0o644))
	if _, err := NewLoader(p); err == nil {
		t.Fatal("not YAML accepted")
	}
}

// TestSchemaErrorsSayWhere: messages name the place and the problem, never the schema's location on disk.
func TestSchemaErrorsSayWhere(t *testing.T) {
	p := home(t)
	f := filepath.Join(p.Orgs, "acme.yml")
	d := readYAML(t, f)
	mapOf(d["access"])["port"] = "x"
	delete(mapOf(d["access"]), "user")
	writeYAML(t, f, d)
	_, errs := loadAll(t, p)
	if !hasErr(errs, "access: missing property 'user'") || !hasErr(errs, "access/port: got string, want integer") {
		t.Fatal(errs)
	}
	for _, e := range errs {
		if strings.Contains(e, "file://") || strings.Contains(e, "validation failed") {
			t.Fatalf("%q", e)
		}
	}
	if got := schemaErrors(errors.New("plain")); len(got) != 1 || got[0] != "plain" {
		t.Fatal(got)
	}
}
