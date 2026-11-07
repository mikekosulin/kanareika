package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// repo root: tests read orgs/_example.yml and assets/templates/org.yml from it
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
	b, err := os.ReadFile(filepath.Join(root, "assets", "templates", "org.yml"))
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
	b, err := os.ReadFile(filepath.Join(root, "assets", "templates", "org.yml"))
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

func TestSplitAddress(t *testing.T) {
	for in, want := range map[string]struct {
		host string
		port int
		err  bool
	}{
		"192.0.2.1":          {"192.0.2.1", 0, false},
		"192.0.2.1:2222":     {"192.0.2.1", 2222, false},
		"web.example.org:22": {"web.example.org", 22, false},
		"web.example.org":    {"web.example.org", 0, false},
		"2001:db8::1":        {"2001:db8::1", 0, false},
		"[2001:db8::1]":      {"2001:db8::1", 0, false},
		"[2001:db8::1]:2200": {"2001:db8::1", 2200, false},
		"[2001:db8::1":       {"", 0, true},
		"[2001:db8::1]2200":  {"", 0, true},
		"192.0.2.1:ssh":      {"", 0, true},
		"192.0.2.1:0":        {"", 0, true},
		"192.0.2.1:70000":    {"", 0, true},
		":22":                {"", 0, true},
		"[2001:db8::1]:x":    {"", 0, true},
	} {
		h, p, err := SplitAddress(in)
		if (err != nil) != want.err || !want.err && (h != want.host || p != want.port) {
			t.Errorf("%s: %q %d %v", in, h, p, err)
		}
	}
}

// TestPorts: host port > port in the address > group port > access.port > 22; jumps likewise without the group.
func TestPorts(t *testing.T) {
	p := home(t)
	f := filepath.Join(p.Orgs, "acme.yml")
	d := readYAML(t, f)
	acc := mapOf(d["access"])
	acc["port"] = 2022
	groups := mapOf(d["groups"])
	mapOf(groups["app"])["port"] = 2200
	front := mapOf(mapOf(groups["front"])["hosts"])
	mapOf(front["web-01"])["address"] = "192.0.2.11:2211"
	mapOf(front["web-02"])["port"] = 2212
	mapOf(mapOf(acc["jumps"])["inner-bastion"])["address"] = "[2001:db8::5]:2205"
	writeYAML(t, f, d)
	orgs, errs := loadAll(t, p)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	got := map[string]string{}
	for _, h := range orgs[0].Hosts {
		got[h.Name] = h.Address + " " + strconv.Itoa(h.Port)
	}
	for name, want := range map[string]string{"web-01": "192.0.2.11 2211", "web-02": "192.0.2.12 2212",
		"app-01": "192.0.2.21 2200", "swm-01": "192.0.2.31 2022"} {
		if got[name] != want {
			t.Errorf("%s: %q, want %q", name, got[name], want)
		}
	}
	j := orgs[0].Jumps()
	if j["bastion"]["port"] != 2222 || j["bastion"]["address"] != "203.0.113.5" { // its own port
		t.Error(j["bastion"])
	}
	if j["inner-bastion"]["port"] != 2205 || j["inner-bastion"]["address"] != "2001:db8::5" {
		t.Error(j["inner-bastion"])
	}
	if raw := mapOf(mapOf(mapOf(orgs[0].Data["access"])["jumps"])["inner-bastion"]); raw["address"] != "[2001:db8::5]:2205" {
		t.Error("the org data was rewritten:", raw)
	}

	// without access.port everything falls back to 22
	delete(acc, "port")
	delete(mapOf(groups["app"]), "port")
	mapOf(mapOf(acc["jumps"])["inner-bastion"])["address"] = "192.0.2.5"
	writeYAML(t, f, d)
	orgs, _ = loadAll(t, p)
	if orgs[0].Jumps()["inner-bastion"]["port"] != 22 {
		t.Fatal(orgs[0].Jumps())
	}
	for _, h := range orgs[0].Hosts {
		if h.Name == "app-01" && h.Port != 22 {
			t.Fatal(h)
		}
	}
}

func TestPortErrors(t *testing.T) {
	for name, edit := range map[string]func(d map[string]any){
		"host disagrees": func(d map[string]any) {
			h := mapOf(mapOf(mapOf(mapOf(d["groups"])["front"])["hosts"])["web-01"])
			h["address"], h["port"] = "192.0.2.11:2211", 2212
		},
		"host malformed": func(d map[string]any) {
			mapOf(mapOf(mapOf(mapOf(d["groups"])["front"])["hosts"])["web-01"])["address"] = "192.0.2.11:ssh"
		},
		"jump disagrees": func(d map[string]any) {
			mapOf(mapOf(mapOf(d["access"])["jumps"])["bastion"])["address"] = "203.0.113.5:22"
		},
	} {
		p := home(t)
		f := filepath.Join(p.Orgs, "acme.yml")
		d := readYAML(t, f)
		edit(d)
		writeYAML(t, f, d)
		if _, errs := loadAll(t, p); !hasErr(errs, "port") {
			t.Errorf("%s: %v", name, errs)
		}
	}
	// the same: an address with the same port as `port` is fine
	p := home(t)
	f := filepath.Join(p.Orgs, "acme.yml")
	d := readYAML(t, f)
	mapOf(mapOf(mapOf(d["access"])["jumps"])["bastion"])["address"] = "203.0.113.5:2222"
	writeYAML(t, f, d)
	if _, errs := loadAll(t, p); len(errs) != 0 {
		t.Fatal(errs)
	}
}
