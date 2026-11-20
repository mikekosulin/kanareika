package onboard

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mikekosulin/kanareika/internal/config"
)

// The functions TestMain and TestDiscover replace, as the package has them (package variables are set before
// TestMain runs).
var (
	defaultLocalSSHConfig = LocalSSHConfig
	defaultAgentKeys      = agentKeys
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// loadAcme: orgs/acme.yml as the loader reads it, hosts by name, and its jump hosts.
func loadAcme(t *testing.T, p config.Paths) (map[string]config.Host, map[string]map[string]any) {
	t.Helper()
	l, err := config.NewLoader(p)
	must(t, err)
	o, lerrs := l.LoadOrg(filepath.Join(p.Orgs, "acme.yml"))
	if len(lerrs) > 0 {
		t.Fatal(lerrs)
	}
	by := map[string]config.Host{}
	for _, h := range o.Hosts {
		by[h.Name] = h
	}
	return by, o.Jumps()
}

// newAcme: orgs/acme.yml made by Create from r, and its content.
func newAcme(t *testing.T, r Request) (config.Paths, []byte) {
	t.Helper()
	p := config.PathsAt(t.TempDir())
	path, errs, err := Create(p, r, time.Now())
	if err != nil || len(errs) > 0 {
		t.Fatal(errs, err)
	}
	b, err := os.ReadFile(path)
	must(t, err)
	return p, b
}

// noTempDir: os.MkdirTemp("", …) fails for the rest of the test, so the scratch copy the loader judges a new file
// in can't be made. Call it after the test's first t.TempDir().
func noTempDir(t *testing.T) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "missing")
	for _, k := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(k, missing)
	}
}

// brokenPolicy: a policy/profiles.yml the loader can't read.
func brokenPolicy(t *testing.T, p config.Paths) {
	t.Helper()
	must(t, os.MkdirAll(p.Policy, 0o755))
	must(t, os.WriteFile(filepath.Join(p.Policy, "profiles.yml"), []byte("default: [unclosed\n"), 0o644))
}

// TestParseHostsEdges: a pasted ssh config block with an unusable alias, a chain of jump hosts or an alias twice is
// skipped with a word, the rest kept; an alias without HostName is its own address; an Ansible line named by a DNS
// name gets its first label as the name; ssh options with the value glued on or missing at the end still parse.
func TestParseHostsEdges(t *testing.T) {
	cfg := "Host ---\n  HostName 192.0.2.1\nHost app\n  HostName 192.0.2.2\n  ProxyJump j1,j2\n" +
		"Host web\n  HostName 192.0.2.3\nHost web\n  HostName 192.0.2.4\nHost nas.example.com\n  User admin\n"
	hs, errs := ParseHosts(cfg)
	if len(hs) != 2 || hs[0] != (Host{Name: "web", Address: "192.0.2.3", Line: 6}) ||
		hs[1] != (Host{Name: "nas", Address: "nas.example.com", User: "admin", Line: 10}) {
		t.Fatalf("%+v", hs)
	}
	want := []string{`Host "---": not a usable host name, skipped`, `Host "app": jump host "j1,j2": [user@]host[:port], skipped`,
		`Host "web" twice, the second skipped`}
	if !slices.Equal(errs, want) {
		t.Fatalf("%q", errs)
	}
	hs, errs = ParseHosts("web-01.example.com ansible_user=deploy\nssh -p2222 -lops 192.0.2.7\nssh 192.0.2.8 -p")
	if len(errs) != 0 || len(hs) != 3 ||
		hs[0] != (Host{Name: "web-01", Address: "web-01.example.com", User: "deploy", Line: 1}) ||
		hs[1] != (Host{Name: "192-0-2-7", Address: "192.0.2.7:2222", User: "ops", Line: 2}) ||
		hs[2] != (Host{Name: "192-0-2-8", Address: "192.0.2.8", Line: 3}) {
		t.Fatalf("%+v %q", hs, errs)
	}
}

// TestParseSSHConfigBareKeyword: a keyword line without a value is skipped; the block's other keywords still apply.
func TestParseSSHConfigBareKeyword(t *testing.T) {
	hs := ParseSSHConfig("Host web\n  Compression\n  User alice\n")
	if len(hs) != 1 || hs[0] != (SSHHost{Alias: "web", User: "alice"}) {
		t.Fatalf("%+v", hs)
	}
}

// TestHostLine: the line of a `Host` entry naming the alias, 0 when no entry names it.
func TestHostLine(t *testing.T) {
	text := "# hosts\nHost web db\n  User alice\n"
	if hostLine(text, "db") != 2 || hostLine(text, "app") != 0 {
		t.Fatal(hostLine(text, "db"), hostLine(text, "app"))
	}
	// quoted aliases (valid ssh_config) are found too: the setup's preview shows their line
	text = "# hosts\nHost \"web-01\"\n  HostName 192.0.2.11\nHost \"db-01 db-02\"\n  HostName 192.0.2.12\n"
	if hostLine(text, "web-01") != 2 || hostLine(text, "db-02") != 4 {
		t.Fatal(hostLine(text, "web-01"), hostLine(text, "db-02"))
	}
	hosts, errs := ParseHosts(text)
	if len(errs) > 0 || len(hosts) != 3 || hosts[0].Name != "web-01" || hosts[0].Line != 2 || hosts[2].Line != 4 {
		t.Fatalf("%+v %v", hosts, errs)
	}
}

// TestLocalSSHConfig: a pasted alias resolves through ~/.ssh/config of the home (a fake one here): HostName, and
// ProxyJump written out with the jump's own user and port; without a config file or a home there is nothing to
// resolve against.
func TestLocalSSHConfig(t *testing.T) {
	old := LocalSSHConfig
	t.Cleanup(func() { LocalSSHConfig = old })
	LocalSSHConfig = defaultLocalSSHConfig
	home := fakeHome(t)
	if got := LocalSSHConfig(); got != nil {
		t.Fatalf("no config file: %+v", got)
	}
	cfg := "Host app\n  HostName 198.51.100.31\n  ProxyJump bastion\nHost bastion\n  HostName 203.0.113.5\n  User jump\n  Port 2222\n"
	must(t, os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(cfg), 0o600))
	hs, errs := ParseHosts("app")
	if len(errs) != 0 || len(hs) != 1 ||
		hs[0] != (Host{Name: "app", Address: "198.51.100.31", Jump: "jump@203.0.113.5:2222", Line: 1, From: "ssh-config"}) {
		t.Fatalf("%+v %q", hs, errs)
	}
	homeDir = func() (string, error) { return "", os.ErrNotExist }
	if got := LocalSSHConfig(); got != nil {
		t.Fatalf("no home: %+v", got)
	}
}

// TestDiscoverWithoutUSER: without $USER the local login comes from the account (without a Windows DOMAIN\ part);
// without the server's hook the agent's keys are not counted.
func TestDiscoverWithoutUSER(t *testing.T) {
	fakeHome(t)
	old := agentKeys
	t.Cleanup(func() { agentKeys = old })
	agentKeys = defaultAgentKeys
	t.Setenv("USER", "")
	f := Discover()
	if u, err := user.Current(); err == nil && (f.User == "" || strings.Contains(f.User, `\`) || !strings.HasSuffix(u.Username, f.User)) {
		t.Fatalf("user %q, account %q", f.User, u.Username)
	}
	if f.AgentKeys != 0 || len(f.Keys) != 0 || len(f.Hosts) != 0 {
		t.Fatalf("%+v", f)
	}
}

// TestYAMLScalar: ys writes every value on one line, and YAML reads it back as the same string.
func TestYAMLScalar(t *testing.T) {
	for _, s := range []string{"web-01", "yes", "[2001:db8::1]:2222", "a: b", "line one\nline two"} {
		out := ys(s)
		var v map[string]string
		if strings.ContainsAny(out, "\n\r") || yaml.Unmarshal([]byte("v: "+out), &v) != nil || v["v"] != s {
			t.Errorf("%q -> %q -> %q", s, out, v["v"])
		}
	}
}

// TestCreateJumpWithoutUser: a jump host given without a user is written with its address only; the servers go
// through it.
func TestCreateJumpWithoutUser(t *testing.T) {
	r := req()
	r.Jump = "203.0.113.10"
	p, _ := newAcme(t, r)
	by, js := loadAcme(t, p)
	if j := js["bastion"]; j == nil || j["address"] != "203.0.113.10" || j["user"] != nil {
		t.Fatalf("jumps: %v", js)
	}
	if by["web-01"].Jump != "bastion" || by["192-0-2-12"].Jump != "bastion" {
		t.Fatalf("%+v", by)
	}
}

// TestKeyWithoutHome: a ~/ key path when there is no home is refused in the same words as any other key.
func TestKeyWithoutHome(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	old := homeDir
	t.Cleanup(func() { homeDir = old })
	homeDir = func() (string, error) { return "", os.ErrNotExist }
	r := req()
	r.Key = "~/.ssh/id_ed25519"
	_, errs, err := Create(p, r, time.Now())
	if err != nil || len(errs) != 1 || errs[0] != "key ~/.ssh/id_ed25519: not a private key file in ~/.ssh or "+p.Secrets {
		t.Fatalf("%q %v", errs, err)
	}
}

// TestCreateLoaderRefuses: a file the loader refuses (an IPv6 address without its ']') comes back as the loader's
// problem, not written; Add refuses the same host the same way, the org file untouched.
func TestCreateLoaderRefuses(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	r := req()
	r.Hosts = "web-05 [2001:db8::1"
	path, errs, err := Create(p, r, time.Now())
	if err != nil || path != "" || len(errs) != 1 || !strings.Contains(errs[0], `address "[2001:db8::1": missing ']'`) {
		t.Fatalf("%q %v", errs, err)
	}
	if _, err := os.Stat(filepath.Join(p.Orgs, "acme.yml")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("written:", err)
	}
	p, before := newAcme(t, req())
	added, errs, err := Add(p, "acme", Request{Hosts: "web-05 [2001:db8::1"})
	if err != nil || len(added) != 0 || len(errs) != 1 || !strings.Contains(errs[0], "missing ']'") {
		t.Fatalf("%v %q %v", added, errs, err)
	}
	if b, _ := os.ReadFile(filepath.Join(p.Orgs, "acme.yml")); string(b) != string(before) {
		t.Fatal("the org file changed")
	}
}

// TestCreateWriteFailures: when the new org's directories, its key copy, the policy or the scratch directory can't
// be had, Create fails with the error and no org file is written.
func TestCreateWriteFailures(t *testing.T) {
	for _, c := range []struct {
		name string
		prep func(t *testing.T, p config.Paths, r *Request)
	}{
		{"reports is a file", func(t *testing.T, p config.Paths, _ *Request) { must(t, os.WriteFile(p.Reports, nil, 0o600)) }},
		{"secrets is a file", func(t *testing.T, p config.Paths, _ *Request) { must(t, os.WriteFile(p.Secrets, nil, 0o600)) }},
		{"key copy", func(t *testing.T, p config.Paths, r *Request) {
			r.Key = filepath.Join(fakeHome(t), ".ssh", "id_ed25519")
			must(t, os.WriteFile(r.Key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600))
			must(t, os.MkdirAll(filepath.Join(p.Secrets, "acme", "id_ed25519"), 0o700)) // a directory where the copy goes
		}},
		{"policy", func(t *testing.T, p config.Paths, _ *Request) { brokenPolicy(t, p) }},
		{"no temp dir", func(t *testing.T, _ config.Paths, _ *Request) { noTempDir(t) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := config.PathsAt(t.TempDir())
			r := req()
			c.prep(t, p, &r)
			path, errs, err := Create(p, r, time.Now())
			if err == nil || errors.Is(err, ErrExists) || len(errs) > 0 || path != "" {
				t.Fatalf("%q %q %v", path, errs, err)
			}
			if _, err := os.Stat(filepath.Join(p.Orgs, "acme.yml")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("written:", err)
			}
		})
	}
}

// TestCreateNeverFollowsALink: a symlink planted where the org file goes counts as an existing file; nothing is
// written where it points.
func TestCreateNeverFollowsALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need a privilege on Windows and open differently there")
	}
	p := config.PathsAt(t.TempDir())
	must(t, os.MkdirAll(p.Orgs, 0o755))
	target := filepath.Join(t.TempDir(), "elsewhere.yml")
	must(t, os.Symlink(target, filepath.Join(p.Orgs, "acme.yml")))
	if _, errs, err := Create(p, req(), time.Now()); !errors.Is(err, ErrExists) || len(errs) > 0 {
		t.Fatal(errs, err)
	}
	if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("written through the link:", err)
	}
}

// TestReadOnlyOrgsDir: where orgs/ can't be written, Create fails without a file and Add fails with the org file
// as it was (its .bak, there already, is rewritten in place; the new file can't be made next to it).
func TestReadOnlyOrgsDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory modes do not stop this user from writing")
	}
	p, before := newAcme(t, req())
	orgFile := filepath.Join(p.Orgs, "acme.yml")
	must(t, os.WriteFile(orgFile+".bak", nil, 0o600))
	must(t, os.Chmod(p.Orgs, 0o500))
	t.Cleanup(func() { _ = os.Chmod(p.Orgs, 0o700) })
	r := req()
	r.ID = "beta"
	if path, errs, err := Create(p, r, time.Now()); err == nil || errors.Is(err, ErrExists) || len(errs) > 0 || path != "" {
		t.Fatal("a new org file in a read-only orgs/:", path, errs, err)
	}
	if _, errs, err := Add(p, "acme", Request{Hosts: "192.0.2.50"}); err == nil || len(errs) != 0 {
		t.Fatal("added:", errs, err)
	}
	if b, _ := os.ReadFile(orgFile); string(b) != string(before) {
		t.Fatal("the org file changed")
	}
	if ents, _ := os.ReadDir(p.Orgs); len(ents) != 2 {
		t.Fatalf("left behind: %v", ents)
	}
}

// TestAddFailures: Add leaves the org file as it was when the file has problems already (said first, then the
// loader's words), and fails with the error when the policy can't be read, the old file can't be kept as .bak or
// there is no scratch directory.
func TestAddFailures(t *testing.T) {
	t.Run("problems already", func(t *testing.T) {
		p, b := newAcme(t, req())
		bad := strings.Replace(string(b), "id: acme", "id: other", 1)
		must(t, os.WriteFile(filepath.Join(p.Orgs, "acme.yml"), []byte(bad), 0o600))
		added, errs, err := Add(p, "acme", Request{Hosts: "192.0.2.50"})
		if err != nil || len(added) != 0 || len(errs) != 2 || errs[0] != "the org file has problems already; fix them first:" ||
			!strings.Contains(errs[1], "must match file name") {
			t.Fatalf("%v %q %v", added, errs, err)
		}
		if got, _ := os.ReadFile(filepath.Join(p.Orgs, "acme.yml")); string(got) != bad {
			t.Fatal("the org file changed")
		}
		if _, err := os.Stat(filepath.Join(p.Orgs, "acme.yml.bak")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("a .bak of a file that was not replaced:", err)
		}
	})
	for _, c := range []struct {
		name string
		prep func(t *testing.T, p config.Paths)
	}{
		{"policy", brokenPolicy},
		{"no .bak", func(t *testing.T, p config.Paths) {
			must(t, os.MkdirAll(filepath.Join(p.Orgs, "acme.yml.bak", "x"), 0o700))
		}},
		{"no temp dir", func(t *testing.T, _ config.Paths) { noTempDir(t) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, before := newAcme(t, req())
			c.prep(t, p)
			if added, errs, err := Add(p, "acme", Request{Hosts: "192.0.2.50"}); err == nil || len(added) != 0 || len(errs) != 0 {
				t.Fatal(added, errs, err)
			}
			if b, _ := os.ReadFile(filepath.Join(p.Orgs, "acme.yml")); string(b) != string(before) {
				t.Fatal("the org file changed")
			}
		})
	}
}

// TestAddPlacement: without an environment new hosts go to production when the org has several; a jump naming a
// host pasted along points at that host's address; a group that exists in another environment gets a group of its
// own; the internet flag makes new groups front-facing unless front groups are named.
func TestAddPlacement(t *testing.T) {
	r := req()
	r.Hosts = "web-01,192.0.2.11,web,production\ndb-01,192.0.2.21,db,staging"
	p, _ := newAcme(t, r)
	add := Request{Hosts: "192.0.2.50\nbastion 203.0.113.10\nssh -J bastion admin@198.51.100.7\nweb-09,192.0.2.59,web,staging"}
	if _, errs, err := Add(p, "acme", add); err != nil || len(errs) > 0 {
		t.Fatal(errs, err)
	}
	by, js := loadAcme(t, p)
	if h := by["192-0-2-50"]; h.Env != "production" || h.Group != Ungrouped {
		t.Errorf("no env: %+v", h)
	}
	if j := js["bastion"]; by["198-51-100-7"].Jump != "bastion" || j["address"] != "203.0.113.10" || j["user"] != nil {
		t.Errorf("jump through a pasted host: %+v %v", by["198-51-100-7"], js)
	}
	if h := by["web-09"]; h.Group != "web-staging" || h.Env != "staging" || by["web-01"].Group != "web" {
		t.Errorf("web in staging: %+v", h)
	}
	if _, errs, err := Add(p, "acme", Request{Hosts: "app-01,192.0.2.31,app", Internet: true}); err != nil || len(errs) > 0 {
		t.Fatal(errs, err)
	}
	if _, errs, err := Add(p, "acme", Request{Hosts: "cache-01,192.0.2.41,cache", Internet: true, Front: []string{"app"}}); err != nil || len(errs) > 0 {
		t.Fatal(errs, err)
	}
	by, _ = loadAcme(t, p)
	if by["app-01"].Exposure != 1 || by["app-01"].Env != "production" || by["cache-01"].Exposure != 3 {
		t.Errorf("internet: %+v %+v", by["app-01"], by["cache-01"])
	}
}

// TestAddThroughAlias: a group whose env is a YAML alias of another group's is in that env (not in one named after
// the anchor): a host added to it joins it.
func TestAddThroughAlias(t *testing.T) {
	r := req()
	r.Hosts = "web-01,192.0.2.11,web,production\ndb-01,192.0.2.21,db,production"
	p, b := newAcme(t, r)
	s := strings.Replace(string(b), "env: production", "env: &env production", 1)
	s = strings.Replace(s, "env: production", "env: *env", 1)
	must(t, os.WriteFile(filepath.Join(p.Orgs, "acme.yml"), []byte(s), 0o600))
	if _, errs, err := Add(p, "acme", Request{Hosts: "db-02,192.0.2.22,db"}); err != nil || len(errs) > 0 {
		t.Fatal(errs, err)
	}
	by, _ := loadAcme(t, p)
	if h := by["db-02"]; h.Group != "db" || h.Env != "production" {
		t.Fatalf("db-02: %+v", h)
	}
}

// TestReplaceFileFailure: a replace that fails leaves no temporary file behind.
func TestReplaceFileFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "acme.yml")
	must(t, os.MkdirAll(filepath.Join(target, "x"), 0o700)) // a non-empty directory can't be renamed over
	if err := replaceFile(target, []byte("org: {}\n")); err == nil {
		t.Fatal("replaced a directory")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("left behind: %v", ents)
	}
}
