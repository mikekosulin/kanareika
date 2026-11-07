package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func mustT(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func pubKey(t *testing.T, rsaKey bool) string {
	t.Helper()
	var k any
	if rsaKey {
		r, err := rsa.GenerateKey(rand.Reader, 2048)
		mustT(t, err)
		k = &r.PublicKey
	} else {
		p, _, err := ed25519.GenerateKey(rand.Reader)
		mustT(t, err)
		k = p
	}
	pk, err := ssh.NewPublicKey(k)
	mustT(t, err)
	return base64.StdEncoding.EncodeToString(pk.Marshal())
}

// The org below is made up: the tool takes the names and addresses to replace from org files like it.
const orgYML = `org:
  id: zeta
  name: "Zeta Widgets"
  contacts: [{name: A, email: a@example.com}]
consent: {document: x, signed: 2026-01-01, valid_until: 2099-01-01, external_scan: true}
access:
  user: audit
  jumps: {gw: {address: 10.20.31.1}}
groups:
  db:
    role: internal
    jump: gw
    hosts:
      zeta-db-01: {address: 10.20.30.40}
external: [52.1.2.3]
`

func capture(ed, rsaKey string) string {
	return `inet 10.20.30.40/24 brd 10.20.30.255 scope global eth0
Accepted publickey for root from 52.1.2.3 port 22 ssh2: ED25519 SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ
neighbour 10.20.30.77 dev eth0 lladdr 52:54:00:12:34:56 REACHABLE
the gateway is 10.20.31.1 and an unrelated network 10.99.0.0/16 with 10.99.1.2 nowhere near an address word
openssl 4.16.1.3 is a version; pkg:deb/debian/lshw@02.19.git is not an e-mail
mail ops@zeta-widgets.net, keep admin@example.com; broadcast ff:ff:ff:ff:ff:ff
ssh-ed25519 ` + ed + ` root@zeta-db-01
ssh-rsa ` + rsaKey + ` backup
ssh-dss ` + ed + ` legacy
inet6 2a03:b0c0:3:d0::1/64 and fe80::5054:ff:fe12:3456/64
host zeta-db-01 of Zeta Widgets (zeta); zetaboy and unzeta stay; secret-project here
kept: 127.0.0.1 172.17.0.1 192.0.2.7 10.0.0.0 0.0.0.0
`
}

func gzBytes(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

func TestAnonymize(t *testing.T) {
	root := t.TempDir()
	mustT(t, os.MkdirAll(filepath.Join(root, "orgs"), 0o755))
	mustT(t, os.WriteFile(filepath.Join(root, "orgs", "zeta.yml"), []byte(orgYML), 0o644))
	data := filepath.Join(root, "pkg", "testdata")
	mustT(t, os.MkdirAll(filepath.Join(data, "local"), 0o755))
	ed, rk := pubKey(t, false), pubKey(t, true)
	in := capture(ed, rk)
	files := map[string][]byte{
		"cap.txt":        []byte(in),
		"report.json.gz": gzBytes(`{"ip": "10.20.30.40", "host": "zeta-db-01"}`),
		"local/raw.txt":  []byte(in),                     // local captures stay real
		"blob.bin":       {0xff, 0xfe, 0x00, 0x01},       // binary: reported, untouched
		"bad.gz":         []byte("not gzip"),             // not readable as gzip: binary too
		"image.tar":      []byte("plain but a tar name"), // tar headers carry checksums
	}
	for name, b := range files {
		mustT(t, os.WriteFile(filepath.Join(data, name), b, 0o644))
	}
	outside := filepath.Join(root, "pkg", "notes.txt") // not under testdata: never touched
	mustT(t, os.WriteFile(outside, []byte(in), 0o644))

	var log bytes.Buffer
	args := []string{"-orgs", filepath.Join(root, "orgs"), "-extra", "secret-project, codename=Project X,", filepath.Join(root, "pkg")}

	// dry run: counts, writes nothing
	if rc := run(append([]string{"-dry-run"}, args...), &log); rc != 0 {
		t.Fatalf("rc %d: %s", rc, &log)
	}
	if b, _ := os.ReadFile(filepath.Join(data, "cap.txt")); string(b) != in || !strings.Contains(log.String(), "changed: 2") {
		t.Fatalf("dry run wrote or miscounted: %s", &log)
	}

	log.Reset()
	if rc := run(args, &log); rc != 0 {
		t.Fatalf("rc %d: %s", rc, &log)
	}
	for _, want := range []string{"skipped (binary):", "blob.bin", "bad.gz", "image.tar", "files: 5, changed: 2"} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("%q not in the log:\n%s", want, &log)
		}
	}
	b, err := os.ReadFile(filepath.Join(data, "cap.txt"))
	mustT(t, err)
	out := string(b)
	for _, real := range []string{"10.20.30.40", "10.20.30.77", "10.20.30.255", "10.20.31.1", "52.1.2.3", "10.99.0.0", "zeta-db-01",
		"Zeta Widgets", "(zeta)", "ops@zeta-widgets.net", "52:54:00:12:34:56", ed, rk, "2a03:b0c0:3:d0::1", "fe80::5054:ff:fe12:3456",
		"SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", "secret-project", "ssh-dss"} {
		if strings.Contains(out, real) {
			t.Errorf("%q still there:\n%s", real, out)
		}
	}
	for _, kept := range []string{"4.16.1.3", "pkg:deb/debian/lshw@02.19.git", "admin@example.com", "ff:ff:ff:ff:ff:ff", "10.99.1.2",
		"zetaboy", "unzeta", "127.0.0.1 172.17.0.1 192.0.2.7 10.0.0.0 0.0.0.0", "host-01 of Example Org (org1)", "redacted here",
		"inet 10.77.", "from 100.21.", "/64 and fe80::", "2a10:77::"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q missing:\n%s", kept, out)
		}
	}
	// every key is a valid key of the type written before it
	for _, m := range regexp.MustCompile(`(ssh-[a-z0-9]+) (AAAA[0-9A-Za-z+/]+=*)`).FindAllStringSubmatch(out, -1) {
		raw, err := base64.StdEncoding.DecodeString(m[2])
		mustT(t, err)
		pk, err := ssh.ParsePublicKey(raw)
		if err != nil || pk.Type() != m[1] {
			t.Errorf("%s key: %v %v", m[1], pk, err)
		}
	}
	// the same address maps to the same fake one in every file, .gz included
	fake := regexp.MustCompile(`inet (10\.77\.\d+\.\d+)/24`).FindStringSubmatch(out)[1]
	r, err := gzip.NewReader(bytes.NewReader(mustRead(t, filepath.Join(data, "report.json.gz"))))
	mustT(t, err)
	var gz bytes.Buffer
	_, _ = gz.ReadFrom(r)
	if gz.String() != `{"ip": "`+fake+`", "host": "host-01"}` {
		t.Fatalf("gz: %s (want %s)", &gz, fake)
	}
	for _, untouched := range []string{filepath.Join(data, "local", "raw.txt"), outside} {
		if string(mustRead(t, untouched)) != in {
			t.Fatalf("%s changed", untouched)
		}
	}
	// again: its own fakes are left alone (only fake keys are swapped: they can't carry a mark); the 3 addresses
	// are the org file's, always loaded
	log.Reset()
	if rc := run(args, &log); rc != 0 || !strings.Contains(log.String(), "addresses 3, e-mails 0, ssh keys 2, fingerprints 0, MACs 0") {
		t.Fatalf("second pass: %s", &log)
	}
	keyLine := regexp.MustCompile(`(?m)^.*AAAA[0-9A-Za-z+/]+=*.*$`)
	if again := string(mustRead(t, filepath.Join(data, "cap.txt"))); keyLine.ReplaceAllString(again, "") != keyLine.ReplaceAllString(out, "") {
		t.Fatalf("second pass changed more than keys:\n%s", again)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	mustT(t, err)
	return b
}

func TestAnonymizeErrors(t *testing.T) {
	var log bytes.Buffer
	if rc := run([]string{"-nope"}, &log); rc != 2 {
		t.Fatal(rc)
	}
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	data := filepath.Join(t.TempDir(), "testdata")
	mustT(t, os.MkdirAll(data, 0o755))
	mustT(t, os.Symlink(filepath.Join(data, "gone"), filepath.Join(data, "dangling")))
	if rc := run([]string{"-orgs", filepath.Join(data, "none"), filepath.Dir(data)}, &log); rc != 1 {
		t.Fatalf("unreadable file: %d %s", rc, &log)
	}
	mustT(t, os.Remove(filepath.Join(data, "dangling")))
	ro := filepath.Join(data, "ro.txt")
	mustT(t, os.WriteFile(ro, []byte("from 52.1.2.3"), 0o444))
	mustT(t, os.Chmod(data, 0o555))
	t.Cleanup(func() { _ = os.Chmod(data, 0o755) })
	if os.Getuid() != 0 {
		if rc := run([]string{"-orgs", filepath.Join(data, "none"), filepath.Dir(data)}, &log); rc != 1 {
			t.Fatalf("read-only file: %d %s", rc, &log)
		}
	}
}
