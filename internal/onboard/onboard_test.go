package onboard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
)

func TestParseHosts(t *testing.T) {
	hs, errs := ParseHosts("192.0.2.11\nweb-02 192.0.2.12:2222  # the second\n\n# a comment\ndb.example.com, \n[2001:db8::1]:22\n")
	if len(errs) != 0 || len(hs) != 4 || hs[0].Name != "192-0-2-11" || hs[1] != (Host{Name: "web-02", Address: "192.0.2.12:2222"}) ||
		hs[2].Name != "db" || hs[3].Name != "2001-db8-1" {
		t.Fatalf("%+v %v", hs, errs)
	}
	for _, bad := range []string{"", "a b c", "Bad!Name 192.0.2.1", "x 192.0.2.1\nx 192.0.2.2"} {
		if _, errs := ParseHosts(bad); len(errs) == 0 {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestParseFleet: CSV with groups and environments, an Ansible INI inventory (vars and children skipped).
func TestParseFleet(t *testing.T) {
	hs, errs := ParseHosts("web-01,192.0.2.11,web,production\napp-01,192.0.2.21,app,staging\n,192.0.2.31\n")
	if len(errs) != 0 || len(hs) != 3 || hs[0].Group != "web" || hs[1].Env != "staging" || hs[2].Name != "192-0-2-31" {
		t.Fatalf("%+v %v", hs, errs)
	}
	inv := `[web]
web-01 ansible_host=192.0.2.11 ansible_port=2222 ansible_user=deploy
web-02.example.com
[db:vars]
ansible_user=postgres
[db]
db-01 ansible_host=192.0.2.31
[all:children]
web
`
	hs, errs = ParseHosts(inv)
	if len(errs) != 0 || len(hs) != 3 || hs[0] != (Host{Name: "web-01", Address: "192.0.2.11:2222", Group: "web", User: "deploy"}) ||
		hs[1].Name != "web-02" || hs[1].Group != "web" || hs[2].Group != "db" || hs[2].Address != "192.0.2.31" {
		t.Fatalf("%+v %v", hs, errs)
	}
	for _, bad := range []string{",,", "a,192.0.2.1,Bad Group", "a,192.0.2.1,g,Bad Env"} {
		if _, errs := ParseHosts(bad); len(errs) == 0 {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestCreateFleet: groups and environments become groups, a jump host is shared, front groups face the internet.
func TestCreateFleet(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	r := req()
	r.Hosts = "web-01,192.0.2.11,web\nweb-02,192.0.2.12,web,staging\ndb-01,192.0.2.31,db\napp-01 ansible_host=192.0.2.21 ansible_user=deploy"
	r.Front, r.Jump = []string{"web"}, "jumper@203.0.113.10:2222"
	path, errs, err := Create(p, r, time.Now())
	if err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	l, _ := config.NewLoader(p)
	o, lerrs := l.LoadOrg(path)
	if len(lerrs) > 0 {
		b, _ := os.ReadFile(path)
		t.Fatal(lerrs, string(b))
	}
	by := map[string]config.Host{}
	for _, h := range o.Hosts {
		by[h.Name] = h
	}
	if by["web-01"].Exposure != 1 || by["db-01"].Exposure != 3 || by["web-02"].Env != "staging" || by["web-01"].Env != "production" ||
		by["app-01"].User != "deploy" || by["db-01"].Jump != "bastion" {
		t.Fatalf("%+v", by)
	}
}

// TestParsePasted: whatever people have at hand: user@host, an ssh command line, a pasted ssh config.
func TestParsePasted(t *testing.T) {
	hs, errs := ParseHosts("admin@192.0.2.40\nnas root@192.0.2.41:2222\nssh -p 2200 -i ~/.ssh/k -J jump@203.0.113.10 deploy@web-01.example.com uptime\nssh -l ops db.example.com\n")
	if len(errs) != 0 || len(hs) != 4 ||
		hs[0] != (Host{Name: "192-0-2-40", Address: "192.0.2.40", User: "admin"}) ||
		hs[1] != (Host{Name: "nas", Address: "192.0.2.41:2222", User: "root"}) ||
		hs[2] != (Host{Name: "web-01", Address: "web-01.example.com:2200", User: "deploy", Jump: "jump@203.0.113.10"}) ||
		hs[3] != (Host{Name: "db", Address: "db.example.com", User: "ops"}) {
		t.Fatalf("%+v %v", hs, errs)
	}
	if _, errs := ParseHosts("ssh -v"); len(errs) == 0 {
		t.Fatal("an ssh command without a host")
	}
	cfg := "Host bastion\n  HostName 203.0.113.10\n  User jumper\nHost app-01\n  HostName 10.0.0.5\n  User deploy\n  Port 2222\n  ProxyJump bastion\n"
	hs, errs = ParseHosts(cfg)
	if len(errs) != 0 || len(hs) != 2 || hs[1] != (Host{Name: "app-01", Address: "10.0.0.5:2222", User: "deploy", Jump: "bastion"}) {
		t.Fatalf("%+v %v", hs, errs)
	}
	if _, errs := ParseHosts("Host *\n  User x\n"); len(errs) == 0 {
		t.Fatal("only wildcards")
	}
	// the pasted config becomes an org with the bastion as a jump host, the app reached through it
	p := config.PathsAt(t.TempDir())
	r := req()
	r.Hosts = cfg
	path, errs, err := Create(p, r, time.Now())
	if err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	l, _ := config.NewLoader(p)
	o, lerrs := l.LoadOrg(path)
	if len(lerrs) > 0 {
		b, _ := os.ReadFile(path)
		t.Fatal(lerrs, string(b))
	}
	for _, h := range o.Hosts {
		if h.Name == "app-01" && (h.Jump != "bastion" || h.User != "deploy" || h.Port != 2222) {
			t.Fatalf("%+v", h)
		}
	}
	if j := o.Jumps()["bastion"]; j == nil || j["address"] != "203.0.113.10" || j["user"] != "jumper" {
		t.Fatalf("jumps: %v", o.Jumps())
	}
}

// TestAdd: hosts go into an existing org (ungrouped unless a line says), comments stay, the old file is kept,
// hosts already there are refused.
func TestAdd(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	r := req()
	if _, errs, err := Create(p, r, time.Now()); err != nil || len(errs) > 0 {
		t.Fatal(errs, err)
	}
	add := Request{Hosts: "admin@192.0.2.50\nssh -J jumper@203.0.113.9 deploy@10.0.0.7\nweb-09,192.0.2.59,web,staging"}
	added, errs, err := Add(p, "acme", add)
	if err != nil || len(errs) > 0 || strings.Join(added, ",") != "192-0-2-50,10-0-0-7,web-09" {
		t.Fatal(added, errs, err)
	}
	b, _ := os.ReadFile(filepath.Join(p.Orgs, "acme.yml"))
	if !strings.Contains(string(b), "# Created by kanareika") || !strings.Contains(string(b), "ungrouped:") {
		t.Fatal("comments kept, the ungrouped group made:\n" + string(b))
	}
	if _, err := os.Stat(filepath.Join(p.Orgs, "acme.yml.bak")); err != nil {
		t.Fatal(err)
	}
	l, _ := config.NewLoader(p)
	o, lerrs := l.LoadOrg(filepath.Join(p.Orgs, "acme.yml"))
	if len(lerrs) > 0 {
		t.Fatal(lerrs)
	}
	by := map[string]config.Host{}
	for _, h := range o.Hosts {
		by[h.Name] = h
	}
	if by["192-0-2-50"].User != "admin" || by["192-0-2-50"].Env != "production" || by["10-0-0-7"].Jump == "" ||
		by["web-09"].Env != "staging" || len(o.Hosts) != 5 {
		t.Fatalf("%+v", by)
	}
	if _, errs, _ := Add(p, "acme", Request{Hosts: "web-01 192.0.2.99"}); len(errs) == 0 || !strings.Contains(strings.Join(errs, " "), "already") {
		t.Fatal("a host already there:", errs)
	}
	if _, errs, _ := Add(p, "acme", Request{Hosts: ""}); len(errs) == 0 {
		t.Fatal("nothing to add")
	}
	if _, _, err := Add(p, "nope", Request{Hosts: "192.0.2.1"}); err == nil {
		t.Fatal("unknown org")
	}
}

// TestOneBadLineSkipped: a broken line or host is skipped with a word about it; the rest goes in.
func TestOneBadLineSkipped(t *testing.T) {
	text := "admin@192.0.2.40\nHost nas\n  HostName 192.0.2.41\n  User root\nthis line makes no sense at all\nweb 192.0.2.42:99999\nssh -p 2222 deploy@10.0.0.7"
	hs, skipped := ParseHosts(text)
	if len(hs) != 3 || len(skipped) != 2 || hs[0].Name != "nas" {
		t.Fatalf("mixed paste: %+v %v", hs, skipped)
	}
	p := config.PathsAt(t.TempDir())
	r := req()
	r.Hosts = text
	path, sk, errs, err := CreateWithSkipped(p, r, time.Now())
	if err != nil || len(errs) != 0 || path == "" || len(sk) != 2 {
		t.Fatal(sk, errs, err)
	}
	r.ID, r.Hosts = "none", "nonsense line one two three"
	if _, _, errs, _ := CreateWithSkipped(p, r, time.Now()); len(errs) == 0 || !strings.Contains(errs[0], "no usable hosts") {
		t.Fatal("nothing usable: refused", errs)
	}
	added, sk, errs, err := AddWithSkipped(p, "acme", Request{Hosts: "192.0.2.77\nnas 192.0.2.11\n???"})
	if err != nil || len(errs) != 0 || len(added) != 1 || len(sk) != 2 {
		t.Fatal(added, sk, errs, err)
	}
}

func TestParseSSHConfig(t *testing.T) {
	hs := ParseSSHConfig(`# comment
Host *
  User everyone
Host nas nas-2
  HostName 192.168.1.40
  User admin
  Port=2222
  IdentityFile "~/.ssh/nas_key"
  IdentityFile ~/.ssh/other
Host bastion
  HostName 203.0.113.10
  ProxyJump none
Host web-?? db
  ProxyJump bastion
Match host x
  User nobody
`)
	if len(hs) != 4 || hs[0] != (SSHHost{"nas", "192.168.1.40", "admin", 2222, "", "~/.ssh/nas_key"}) || hs[1].HostName != "192.168.1.40" ||
		hs[2].Jump != "" || hs[3] != (SSHHost{Alias: "db", Jump: "bastion"}) {
		t.Fatalf("%+v", hs)
	}
}

func TestDiscover(t *testing.T) {
	home := t.TempDir()
	old, oldAgent := homeDir, agentKeys
	t.Cleanup(func() { homeDir, agentKeys = old, oldAgent })
	homeDir = func() (string, error) { return home, nil }
	SetAgentKeys(func() int { return 2 })
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(home, ".ssh"), 0o700))
	must(os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host nas\n  HostName 192.168.1.40\n"), 0o600))
	must(os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600))
	must(os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), []byte("ssh-ed25519 AAAA"), 0o644))
	must(os.WriteFile(filepath.Join(home, ".ssh", "id_notakey"), []byte("hello"), 0o600))
	f := Discover()
	if f.User == "" || len(f.Hosts) != 1 || f.Hosts[0].HostName != "192.168.1.40" || len(f.Keys) != 1 || f.Keys[0] != "~/.ssh/id_ed25519" ||
		f.AgentKeys != 2 {
		t.Fatalf("%+v", f)
	}
	homeDir = func() (string, error) { return "", os.ErrNotExist }
	if f := Discover(); len(f.Hosts) != 0 || f.Keys == nil {
		t.Fatalf("no home: %+v", f)
	}
}

func req() Request {
	return Request{ID: "acme", Name: "ACME Corp", User: "audit", Hosts: "web-01 192.0.2.11\n192.0.2.12", Consent: "Contract 42",
		Confirmed: true}
}

func TestCreate(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	day := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	path, errs, err := Create(p, req(), day)
	if err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	b, _ := os.ReadFile(path)
	for _, want := range []string{"id: acme", "signed: 2026-11-08", "valid_until: 2027-11-08", "env: production", "exposure: 3",
		"web-01:", "192-0-2-12:", "ungrouped:"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("no %q in\n%s", want, b)
		}
	}
	l, err := config.NewLoader(p)
	if err != nil {
		t.Fatal(err)
	}
	if o, errs := l.LoadOrg(path); len(errs) > 0 || len(o.Hosts) != 2 || o.Hosts[0].Env != "production" {
		t.Fatal("the file loads as written:", errs)
	}
	if _, _, err := Create(p, req(), day); !errors.Is(err, ErrExists) {
		t.Fatal("never overwrites:", err)
	}
	// a key is copied into secrets/<id>/ and referenced
	key := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := req()
	r.ID, r.Key, r.Internet, r.Privilege, r.Port, r.Env = "beta", key, true, "sudo", 2222, "staging"
	path, errs, err = Create(p, r, day)
	if err != nil || len(errs) != 0 {
		t.Fatal(errs, err)
	}
	b, _ = os.ReadFile(path)
	if !strings.Contains(string(b), "key: beta/id_ed25519") || !strings.Contains(string(b), "exposure: 1") ||
		!strings.Contains(string(b), "port: 2222") || !strings.Contains(string(b), "privilege: sudo") {
		t.Fatal(string(b))
	}
	if st, err := os.Stat(filepath.Join(p.Secrets, "beta", "id_ed25519")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal("key copied 0600:", err)
	}
}

func TestCreateRefuses(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	for name, edit := range map[string]func(*Request){
		"id": func(r *Request) { r.ID = "Bad Id" }, "name": func(r *Request) { r.Name = " " }, "user": func(r *Request) { r.User = "root;" },
		"privilege": func(r *Request) { r.Privilege = "helper" }, "port": func(r *Request) { r.Port = 70000 },
		"env": func(r *Request) { r.Env = "Prod!" }, "consent": func(r *Request) { r.Consent = "" },
		"confirmed": func(r *Request) { r.Confirmed = false }, "hosts": func(r *Request) { r.Hosts = "" },
		"key": func(r *Request) { r.Key = "/nonexistent/key" },
	} {
		r := req()
		edit(&r)
		if _, errs, err := Create(p, r, time.Now()); err != nil || len(errs) == 0 {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if ents, _ := os.ReadDir(p.Orgs); len(ents) != 0 {
		t.Fatal("nothing written on a refusal")
	}
	notKey := filepath.Join(t.TempDir(), "k.pub")
	_ = os.WriteFile(notKey, []byte("ssh-ed25519 AAAA"), 0o644)
	r := req()
	r.Key = notKey
	if _, errs, _ := Create(p, r, time.Now()); len(errs) == 0 || !strings.Contains(errs[0], "not a private key") {
		t.Fatal(errs)
	}
}

type fakeConn struct{ fail map[string]string }

func (f fakeConn) Run(_ context.Context, h config.Host, _ string, _ time.Duration, _ bool) (string, error) {
	if e, ok := f.fail[h.Name]; ok {
		return "", errors.New(e)
	}
	return "Linux 6.1.0-18-amd64\n", nil
}
func (fakeConn) Close() error { return nil }

func TestCheck(t *testing.T) {
	o := &config.Org{Hosts: []config.Host{{Name: "b", Env: "production", Address: "192.0.2.2"}, {Name: "a", Env: "production", Address: "192.0.2.1"},
		{Name: "c", Env: "production"}, {Name: "s", Env: "staging"}}}
	rs := Check(context.Background(), o, "production", fakeConn{map[string]string{
		"b": "ssh: handshake failed: ssh: unable to authenticate", "c": "dial tcp 192.0.2.3:22: i/o timeout"}})
	if len(rs) != 3 || rs[0].Host != "a" || !rs[0].OK || rs[0].System != "Linux 6.1.0-18-amd64" || rs[1].OK ||
		!strings.Contains(rs[1].Hint, "authorized_keys") || !strings.Contains(rs[2].Hint, "firewall") {
		t.Fatalf("%+v", rs)
	}
	if hint("something else") != "" || !strings.Contains(hint("connection refused"), "sshd") ||
		!strings.Contains(hint("no such host"), "DNS") || !strings.Contains(hint("x: no access.key and no ssh-agent (SSH_AUTH_SOCK)"), "ssh-add") || !strings.Contains(hint("host key mismatch"), "known_hosts") {
		t.Fatal("hints")
	}
}

func TestBadIPv4Skipped(t *testing.T) {
	hosts, errs := ParseHosts("10.0.0.300\nadmin@10.0.0.5\n10.0.0\nweb-01 192.0.2.256:22\nnas")
	if len(hosts) != 2 || hosts[0].Address != "10.0.0.5" || hosts[1].Address != "nas" {
		t.Fatalf("%+v", hosts)
	}
	if len(errs) != 3 || !strings.Contains(errs[0], `"10.0.0.300" is not an IP address`) {
		t.Fatal(errs)
	}
}
