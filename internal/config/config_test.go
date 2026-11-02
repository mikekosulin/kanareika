package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// repo root: tests read orgs/_example.yml and orgs/_template.yml from it
var root, _ = filepath.Abs("../..")

// home: an isolated working directory with orgs/acme.yml (the example org). Policy and schema come built in.
func home(t *testing.T) Paths {
	t.Helper()
	p := PathsAt(t.TempDir())
	must(t, os.MkdirAll(p.Orgs, 0o755))
	b, err := os.ReadFile(filepath.Join(root, "orgs", "_example.yml"))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(p.Orgs, "acme.yml"), b, 0o644))
	return p
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func loadAll(t *testing.T, p Paths) ([]*Org, []string) {
	t.Helper()
	l, err := NewLoader(p)
	must(t, err)
	return l.LoadAll()
}

func readYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	must(t, err)
	var m map[string]any
	must(t, yaml.Unmarshal(b, &m))
	return m
}

func writeYAML(t *testing.T, path string, m map[string]any) {
	t.Helper()
	b, err := yaml.Marshal(m)
	must(t, err)
	must(t, os.WriteFile(path, b, 0o644))
}

// secondOrg: the template as org "beta" with one app host.
func secondOrg(t *testing.T, p Paths, address string, external []any) {
	b, err := os.ReadFile(filepath.Join(root, "orgs", "_template.yml"))
	must(t, err)
	var d map[string]any
	must(t, yaml.Unmarshal([]byte(strings.ReplaceAll(string(b), "__ORG_ID__", "beta")), &d))
	mapOf(mapOf(mapOf(mapOf(d["groups"])["app"])["hosts"])["app-01"])["address"] = address
	mapOf(mapOf(mapOf(d["access"])["jumps"])["bastion"])["address"] = "192.0.2.250"
	d["external"] = external
	if external == nil {
		d["external"] = []any{}
	}
	writeYAML(t, filepath.Join(p.Orgs, "beta.yml"), d)
}

func hasErr(errs []string, parts ...string) bool {
	for _, e := range errs {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(e, p)
		}
		if ok {
			return true
		}
	}
	return false
}

func TestExampleOrgIsValid(t *testing.T) {
	orgs, errs := loadAll(t, home(t))
	if len(errs) != 0 || len(orgs) != 1 || orgs[0].ID != "acme" {
		t.Fatalf("orgs=%v errs=%v", orgs, errs)
	}
}

func TestTemplateIsValid(t *testing.T) {
	p := home(t)
	secondOrg(t, p, "192.0.2.200", nil)
	if _, errs := loadAll(t, p); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestCrossOrgOverlap(t *testing.T) {
	p := home(t)
	secondOrg(t, p, "192.0.2.11", nil) // = acme web-01
	if _, errs := loadAll(t, p); !hasErr(errs, "overlap", "web-01") {
		t.Fatal(errs)
	}
	p = home(t)
	secondOrg(t, p, "192.0.2.200", []any{"192.0.2.0/28"}) // covers acme hosts
	if _, errs := loadAll(t, p); !hasErr(errs, "overlap") {
		t.Fatal(errs)
	}
	p = home(t)
	secondOrg(t, p, "192.0.2.200", []any{"https://SHOP.acme.example/path"})
	if _, errs := loadAll(t, p); !hasErr(errs, "shop.acme.example") {
		t.Fatal(errs)
	}
}

func TestMergeOrder(t *testing.T) {
	orgs, _ := loadAll(t, home(t))
	acme := orgs[0]
	h := map[string]Host{}
	for _, x := range acme.Hosts {
		h[x.Name] = x
	}
	if !h["mongo-01"].Enabled("os_packages") || h["mongo-01"].Enabled("software_fs") || !h["mongo-01"].Enabled("mongo") {
		t.Fatal("profile/role/host layers")
	}
	sw := h["app-01"].Checks["software_fs"]
	paths := sw["paths"].([]any)
	if len(paths) != 2 || paths[0] != "/opt/acme" || sw["enabled"] != true || !strings.Contains(MarshalChecks(Checks{"x": sw}), "*.jar") {
		t.Fatalf("group override must keep profile keys: %v", sw)
	}
	if d := h["web-01"].Checks["docker"]; d["enabled"] != true || d["scan_images"] != "save" {
		t.Fatalf("org-level docker on top of role: %v", d)
	}
	if _, ok := h["web-01"].Checks["k8s"]; ok {
		t.Fatal("org-only module on a host")
	}
	if !acme.Enabled("k8s") || !acme.Enabled("network_external") {
		t.Fatal("org modules")
	}
}

func TestHostsKeepFileOrder(t *testing.T) {
	orgs, _ := loadAll(t, home(t))
	var got []string
	for _, h := range orgs[0].Hosts {
		got = append(got, h.Name)
	}
	if !strings.HasPrefix(strings.Join(got, ","), "web-01,") {
		t.Fatalf("file order lost: %v", got)
	}
}

func TestOrgModuleOnHostRejected(t *testing.T) {
	p := home(t)
	f := filepath.Join(p.Orgs, "acme.yml")
	d := readYAML(t, f)
	mapOf(mapOf(d["groups"])["front"])["checks"] = map[string]any{"k8s": true}
	writeYAML(t, f, d)
	if _, errs := loadAll(t, p); !hasErr(errs, "top-level") {
		t.Fatal(errs)
	}
}

func TestWindowCrossingMidnight(t *testing.T) {
	orgs, _ := loadAll(t, home(t))
	acme := orgs[0]
	acme.Consent()["window"] = map[string]any{"days": []any{"mon"}, "from": "22:00", "to": "06:00", "tz": "UTC"}
	at := func(d, h int) time.Time { return time.Date(2026, 11, d, h, 0, 0, 0, time.UTC) }
	if !InWindow(acme, at(2, 23)) || !InWindow(acme, at(3, 5)) || InWindow(acme, at(3, 23)) || InWindow(acme, at(2, 12)) {
		t.Fatal("window")
	}
}

func TestConsentExpiry(t *testing.T) {
	orgs, _ := loadAll(t, home(t))
	if len(ConsentProblems(orgs[0], time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))) != 0 ||
		len(ConsentProblems(orgs[0], time.Date(2027, 9, 2, 0, 0, 0, 0, time.UTC))) == 0 {
		t.Fatal("consent")
	}
}

func envsOrg(t *testing.T, p Paths, mixed bool, external any) {
	b, err := os.ReadFile(filepath.Join(root, "orgs", "_template.yml"))
	must(t, err)
	var d map[string]any
	must(t, yaml.Unmarshal([]byte(strings.ReplaceAll(string(b), "__ORG_ID__", "gamma")), &d))
	mapOf(d["access"])["jumps"] = map[string]any{}
	app := mapOf(mapOf(d["groups"])["app"])
	delete(app, "jump")
	prod, stg := DeepMerge(app, map[string]any{"env": "production"}), DeepMerge(app, nil)
	prod["hosts"] = map[string]any{"p-01": map[string]any{"address": "10.10.0.1"}}
	stg["hosts"] = map[string]any{"s-01": map[string]any{"address": "10.20.0.1"}}
	if !mixed {
		stg["env"] = "staging"
	}
	d["groups"] = map[string]any{"prod": prod, "stg": stg}
	d["external"] = external
	if external == nil {
		d["external"] = []any{}
	}
	writeYAML(t, filepath.Join(p.Orgs, "gamma.yml"), d)
}

func TestEnvsSplitHosts(t *testing.T) {
	p := home(t)
	envsOrg(t, p, false, map[string]any{"production": []any{"198.51.100.77"}, "staging": []any{"x.example"}})
	orgs, errs := loadAll(t, p)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var g *Org
	for _, o := range orgs {
		if o.ID == "gamma" {
			g = o
		}
	}
	if strings.Join(g.Envs(), ",") != "production,staging" || g.External("production")[0] != "198.51.100.77" ||
		g.External("staging")[0] != "x.example" {
		t.Fatal(g.Envs(), g.External("production"))
	}
}

func TestMixedEnvRejected(t *testing.T) {
	p := home(t)
	envsOrg(t, p, true, nil)
	if _, errs := loadAll(t, p); !hasErr(errs, "set env on every group") {
		t.Fatal(errs)
	}
	p = home(t)
	envsOrg(t, p, false, []any{"198.51.100.77"})
	if _, errs := loadAll(t, p); !hasErr(errs, "env 'default' has no hosts") {
		t.Fatal(errs)
	}
}

// --- format migrations ------------------------------------------------------------------------------------------

func TestMigrationsRunInMemoryAndRewriteFile(t *testing.T) {
	saved := migrations
	defer func() { migrations = saved }()
	// a pretend v2: org.notes was renamed to org.description
	migrations = []migration{{to: 2, about: "org.notes -> org.description", apply: func(r *yaml.Node) error {
		renameKey(lookup(r, "org"), "notes", "description")
		deleteKey(lookup(r, "org"), "obsolete")
		return nil
	}}}
	src := "# my org\norg:\n  id: x\n  notes: hello  # keep me\n  obsolete: 1\n"
	var doc yaml.Node
	must(t, yaml.Unmarshal([]byte(src), &doc))
	steps, err := Migrate(&doc)
	must(t, err)
	if len(steps) != 1 {
		t.Fatal(steps)
	}
	out, _ := yaml.Marshal(&doc)
	s := string(out)
	if !strings.Contains(s, "version: 2") || !strings.Contains(s, "description: hello") || !strings.Contains(s, "# keep me") ||
		!strings.Contains(s, "# my org") {
		t.Fatalf("migrated:\n%s", s)
	}
	// a file newer than the binary is refused
	must(t, yaml.Unmarshal([]byte("version: 9\norg: {id: x}\n"), &doc))
	if _, err := Migrate(&doc); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatal(err)
	}
	// on disk: rewritten with a .bak copy; dry run leaves it alone
	f := filepath.Join(t.TempDir(), "x.yml")
	must(t, os.WriteFile(f, []byte(src), 0o600))
	if steps, _ := MigrateFile(f, true); len(steps) != 1 {
		t.Fatal("dry run")
	}
	if b, _ := os.ReadFile(f); string(b) != src {
		t.Fatal("dry run wrote")
	}
	_, err = MigrateFile(f, false)
	must(t, err)
	if b, _ := os.ReadFile(f + ".bak"); string(b) != src {
		t.Fatal("no backup")
	}
}

func TestCurrentFilesNeedNoMigration(t *testing.T) {
	orgs, _ := loadAll(t, home(t))
	if len(orgs[0].Migrated) != 0 {
		t.Fatal(orgs[0].Migrated)
	}
}
