package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"gopkg.in/yaml.v3"
)

func TestOrgAccessors(t *testing.T) {
	p := home(t)
	orgs, errs := loadAll(t, p)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	o := orgs[0]
	if o.Name() != "ACME Corp (example)" {
		t.Fatalf("Name() = %q", o.Name())
	}
	if k := o.K8s(DefaultEnv); len(k) != 1 || k[0]["name"] != "prod" {
		t.Fatalf("K8s(default) = %v", k)
	}
	if k := o.K8s("staging"); k != nil {
		t.Fatalf("K8s(staging) = %v", k)
	}
	o.Data["k8s"] = []any{map[string]any{"name": "a", "env": "staging"}, map[string]any{"name": "b"}}
	if k := o.K8s("staging"); len(k) != 1 || k[0]["name"] != "a" {
		t.Fatalf("K8s(staging) = %v", k)
	}

	if s, err := o.Secret(""); s != "" || err != nil {
		t.Fatal(s, err)
	}
	base, _ := filepath.Abs(p.Secrets)
	if s, err := o.Secret("acme/id_ed25519"); err != nil || s != filepath.Join(base, "acme", "id_ed25519") {
		t.Fatal(s, err)
	}
	for _, rel := range []string{"../orgs/acme.yml", "acme/../../x", "."} {
		if _, err := o.Secret(rel); err == nil || !strings.Contains(err.Error(), "escapes secrets/") {
			t.Errorf("Secret(%q): %v", rel, err)
		}
	}
}

func TestJumpsIntPort(t *testing.T) {
	o := &Org{Data: map[string]any{"access": map[string]any{"port": 2200, "jumps": map[string]any{
		"bastion": map[string]any{"address": "203.0.113.5", "port": 2222},
		"inner":   map[string]any{"address": "192.0.2.5"},
	}}}}
	j := o.Jumps()
	if j["bastion"]["port"] != 2222 || j["inner"]["port"] != 2200 {
		t.Fatal(j)
	}
}

func TestConsentNotYetSigned(t *testing.T) {
	orgs, _ := loadAll(t, home(t))
	got := ConsentProblems(orgs[0], time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	if !slices.Equal(got, []string{"consent not yet in force (signed 2026-09-01)"}) {
		t.Fatal(got)
	}
}

func TestInWindowVariants(t *testing.T) {
	o := &Org{Data: map[string]any{"consent": map[string]any{}}}
	at := func(d, h int) time.Time { return time.Date(2026, 11, d, h, 0, 0, 0, time.UTC) } // 2 Nov 2026: Monday
	if !InWindow(o, at(2, 12)) {
		t.Fatal("no window: any time")
	}
	set := func(w map[string]any) { o.Data["consent"] = map[string]any{"window": w} }

	set(map[string]any{"from": "09:00", "to": "18:00"}) // no tz: UTC, no days: every day
	if !InWindow(o, at(8, 12)) || InWindow(o, at(8, 18)) || InWindow(o, at(8, 8)) {
		t.Fatal("day window, every day, UTC")
	}
	set(map[string]any{"from": "09:00", "to": "18:00", "days": []any{"mon"}, "tz": "Asia/Tokyo"})
	if !InWindow(o, at(2, 3)) || InWindow(o, at(2, 12)) || InWindow(o, at(3, 3)) {
		t.Fatal("day window on Monday in Tokyo")
	}
	set(map[string]any{"from": "09:00", "to": "18:00", "tz": "Mars/Olympus"})
	if InWindow(o, at(2, 12)) {
		t.Fatal("unknown timezone: never")
	}
}

// fakeDefaults swaps the built-in policy/schema files.
func fakeDefaults(t *testing.T, fsys fs.FS) {
	t.Helper()
	old := defaultsFS
	defaultsFS = func() fs.FS { return fsys }
	t.Cleanup(func() { defaultsFS = old })
}

func TestNewLoaderBuiltinErrors(t *testing.T) {
	profiles := &fstest.MapFile{Data: []byte("default: {}\n")}
	for _, c := range []struct {
		name string
		fsys fstest.MapFS
		want string
	}{
		{"no schema", fstest.MapFS{"policy/profiles.yml": profiles}, "file does not exist"},
		{"schema not JSON", fstest.MapFS{"schemas/org.schema.json": {Data: []byte("{")}}, ""},
		{"schema does not compile", fstest.MapFS{"schemas/org.schema.json": {Data: []byte(`{"type": 5}`)}}, "schemas/org.schema.json: "},
		{"no profiles", fstest.MapFS{"schemas/org.schema.json": {Data: []byte(`{"type": "object"}`)}}, "file does not exist"},
		{"profiles refer to missing checks", fstest.MapFS{
			"schemas/org.schema.json": {Data: []byte(`{"type": "object", "$defs": {}}`)}, "policy/profiles.yml": profiles,
		}, "checks"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fakeDefaults(t, c.fsys)
			_, err := NewLoader(PathsAt(t.TempDir()))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestLoadAllDuplicateID(t *testing.T) {
	p := home(t)
	b, err := os.ReadFile(filepath.Join(p.Orgs, "acme.yml"))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(p.Orgs, "acme2.yml"), b, 0o644))
	orgs, errs := loadAll(t, p)
	if len(orgs) != 2 || !hasErr(errs, "acme2.yml: duplicate org id acme") || !hasErr(errs, "acme2.yml: org.id 'acme' must match") {
		t.Fatal(len(orgs), errs)
	}
}

func TestLoadOrgVersionAndDecodeErrors(t *testing.T) {
	p := home(t)
	f := filepath.Join(p.Orgs, "acme.yml")
	b, err := os.ReadFile(f)
	must(t, err)
	l, err := NewLoader(p)
	must(t, err)

	must(t, os.WriteFile(f, append([]byte("version: abc\n"), b...), 0o644))
	if o, errs := l.LoadOrg(f); o != nil || !slices.Equal(errs, []string{`acme.yml: version: "abc" is not a positive integer`}) {
		t.Fatal(errs)
	}
	must(t, os.WriteFile(f, append(b, []byte("\nexternal: []\n")...), 0o644)) // a key twice
	if o, errs := l.LoadOrg(f); o != nil || len(errs) != 1 || !strings.Contains(errs[0], "acme.yml: YAML error:") {
		t.Fatal(errs)
	}
}

func TestK8sEnvWithoutHosts(t *testing.T) {
	p := home(t)
	f := filepath.Join(p.Orgs, "acme.yml")
	d := readYAML(t, f)
	d["k8s"] = []any{map[string]any{"name": "stage", "kubeconfig": "acme/kc", "env": "staging"}}
	writeYAML(t, f, d)
	if _, errs := loadAll(t, p); !hasErr(errs, "k8s stage: env 'staging' has no hosts") {
		t.Fatal(errs)
	}
}

func TestPrivilege(t *testing.T) {
	for _, c := range []struct {
		h, access map[string]any
		want      string
	}{
		{map[string]any{"user": "root"}, map[string]any{"sudo": true}, "none"},
		{map[string]any{}, map[string]any{"user": "root", "privilege": "sudo"}, "none"},
		{map[string]any{}, map[string]any{"user": "audit", "sudo": true}, "sudo"},
		{map[string]any{"sudo": false}, map[string]any{"user": "audit", "sudo": true}, "none"},
	} {
		if got := privilege(c.h, c.access); got != c.want {
			t.Errorf("privilege(%v, %v) = %q, want %q", c.h, c.access, got, c.want)
		}
	}
}

func TestDeepMergeNested(t *testing.T) {
	base := map[string]any{"a": map[string]any{"x": 1.0, "y": 2.0}, "l": []any{1.0}}
	got := DeepMerge(base, map[string]any{"a": map[string]any{"y": 3.0}, "l": []any{2.0}, "n": "new"})
	a := got["a"].(map[string]any)
	if a["x"] != 1.0 || a["y"] != 3.0 || got["n"] != "new" || !slices.Equal(got["l"].([]any), []any{2.0}) {
		t.Fatal(got)
	}
	if base["a"].(map[string]any)["y"] != 2.0 {
		t.Fatal("base changed")
	}
}

func TestYAMLTimestamps(t *testing.T) {
	v, err := YAML([]byte("d: 2026-09-01\nt: 2026-09-01T10:30:00Z\nn: 3\n"))
	must(t, err)
	m := v.(map[string]any)
	if m["d"] != "2026-09-01" || m["t"] != "2026-09-01T10:30:00Z" || m["n"] != 3.0 {
		t.Fatal(m)
	}
}

func TestOrderedFallbacks(t *testing.T) {
	var doc yaml.Node
	must(t, yaml.Unmarshal([]byte("groups:\n  b: 1\n  a: 2\nalias: &x {q: 1}\nother: *x\n"), &doc))
	m := map[string]any{"b": 1, "a": 2}
	if got := ordered(&doc, m, "groups"); !slices.Equal(got, []string{"b", "a"}) {
		t.Fatalf("file order: %v", got)
	}
	if got := ordered(&doc, m, "nothing"); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("missing path: %v", got)
	}
	if got := ordered(&doc, m, "groups", "b"); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("path through a scalar: %v", got)
	}
	m["c"] = 3 // not in the file
	if got := ordered(&doc, m, "groups"); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("keys differ: %v", got)
	}
}

// --- migrations ---------------------------------------------------------------------------------------------

func fakeMigrations(t *testing.T, ms ...migration) {
	t.Helper()
	old := migrations
	migrations = ms
	t.Cleanup(func() { migrations = old })
}

func node(t *testing.T, s string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	must(t, yaml.Unmarshal([]byte(s), &doc))
	return &doc
}

func encode(t *testing.T, n *yaml.Node) string {
	t.Helper()
	b, err := yaml.Marshal(n)
	must(t, err)
	return string(b)
}

func TestMigrateSteps(t *testing.T) {
	fakeMigrations(t,
		migration{to: 1, about: "never applied", apply: func(*yaml.Node) error { t.Fatal("v1 step ran"); return nil }},
		migration{to: 2, about: "colour -> color", apply: func(r *yaml.Node) error { renameKey(r, "colour", "color"); return nil }},
		migration{to: 3, about: "drop legacy", apply: func(r *yaml.Node) error { deleteKey(r, "legacy"); return nil }},
	)
	doc := node(t, "version: 1\ncolour: blue # keep me\nlegacy: x\n")
	steps, err := Migrate(doc)
	must(t, err)
	if !slices.Equal(steps, []string{"v2: colour -> color", "v3: drop legacy"}) {
		t.Fatal(steps)
	}
	if got := encode(t, doc); got != "version: 3\ncolor: blue # keep me\n" {
		t.Fatalf("%q", got)
	}

	doc = node(t, "colour: blue\n") // no version: 1; the version key is added first
	steps, err = Migrate(doc)
	must(t, err)
	if len(steps) != 2 || encode(t, doc) != "version: 3\ncolor: blue\n" {
		t.Fatal(steps, encode(t, doc))
	}
}

func TestMigrateErrors(t *testing.T) {
	boom := errors.New("boom")
	fakeMigrations(t,
		migration{to: 2, about: "ok", apply: func(*yaml.Node) error { return nil }},
		migration{to: 3, about: "fails", apply: func(*yaml.Node) error { return boom }},
	)
	steps, err := Migrate(node(t, "a: 1\n"))
	if !errors.Is(err, boom) || err.Error() != "migration to version 3: boom" || !slices.Equal(steps, []string{"v2: ok"}) {
		t.Fatal(steps, err)
	}
	if _, err := Migrate(node(t, "version: 0\n")); err == nil || !strings.Contains(err.Error(), "not a positive integer") {
		t.Fatal(err)
	}
	if steps, err := Migrate(&yaml.Node{Kind: yaml.DocumentNode}); steps != nil || err != nil {
		t.Fatal("empty document", steps, err)
	}
}

func TestNodeHelpers(t *testing.T) {
	scalar := &yaml.Node{Kind: yaml.ScalarNode, Value: "x"}
	if lookup(nil, "a") != nil || lookup(scalar, "a") != nil {
		t.Fatal("lookup on a non-mapping")
	}
	if renameKey(nil, "a", "b") || renameKey(scalar, "a", "b") || deleteKey(nil, "a") || deleteKey(scalar, "a") {
		t.Fatal("edit of a non-mapping")
	}
	m := docRoot(node(t, "a: 1\nb: 2\n"))
	if renameKey(m, "zz", "y") || deleteKey(m, "zz") {
		t.Fatal("missing key edited")
	}
	if !renameKey(m, "a", "c") || !deleteKey(m, "b") || encode(t, m) != "c: 1\n" {
		t.Fatal(encode(t, m))
	}
	if docRoot(scalar) != scalar {
		t.Fatal("docRoot of a non-document")
	}
}

func TestMigrateFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "acme.yml")
	orig := "# acme\norg:\n    id: acme\n"
	must(t, os.WriteFile(f, []byte(orig), 0o644))
	fakeMigrations(t, migration{to: 2, about: "noop", apply: func(*yaml.Node) error { return nil }})

	steps, err := MigrateFile(f, true)
	must(t, err)
	if b, _ := os.ReadFile(f); len(steps) != 1 || string(b) != orig {
		t.Fatal("dry run changed the file", steps)
	}
	steps, err = MigrateFile(f, false)
	must(t, err)
	b, _ := os.ReadFile(f)
	bak, _ := os.ReadFile(f + ".bak")
	if len(steps) != 1 || string(b) != "version: 2\n# acme\norg:\n  id: acme\n" || string(bak) != orig {
		t.Fatalf("%q %q", b, bak)
	}

	// errors: missing, not YAML, cannot encode, .bak cannot be written
	if _, err := MigrateFile(filepath.Join(dir, "missing.yml"), false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.yml")
	must(t, os.WriteFile(bad, []byte("a: [unclosed"), 0o644))
	if _, err := MigrateFile(bad, false); err == nil {
		t.Fatal("not YAML accepted")
	}

	must(t, os.WriteFile(f, []byte(orig), 0o644))
	fakeMigrations(t, migration{to: 2, about: "breaks", apply: func(r *yaml.Node) error {
		r.Content = append(r.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "k"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!binary", Value: "\xff"}) // binary that is not base64
		return nil
	}})
	if _, err := MigrateFile(f, false); err == nil {
		t.Fatal("unencodable document written")
	}
	if b, _ := os.ReadFile(f); string(b) != orig {
		t.Fatal("file changed on an encode error")
	}

	fakeMigrations(t, migration{to: 2, about: "noop", apply: func(*yaml.Node) error { return nil }})
	other := filepath.Join(dir, "beta.yml")
	must(t, os.WriteFile(other, []byte(orig), 0o644))
	must(t, os.Mkdir(other+".bak", 0o755))
	if _, err := MigrateFile(other, false); err == nil {
		t.Fatal(".bak is a directory")
	}
	if b, _ := os.ReadFile(other); string(b) != orig {
		t.Fatal("file changed without a backup")
	}
}
