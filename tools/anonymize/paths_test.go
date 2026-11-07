package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newMapper() *mapper {
	return &mapper{ips: map[string]string{}, emails: map[string]string{}, keys: map[string]string{},
		fps: map[string]string{}, macs: map[string]string{}}
}

func TestMainExitCode(t *testing.T) {
	dir := t.TempDir()
	oldArgs, oldExit := os.Args, exit
	t.Cleanup(func() { os.Args, exit = oldArgs, oldExit })
	code := -1
	exit = func(c int) { code = c }
	os.Args = []string{"anonymize", "-dry-run", "-orgs", filepath.Join(dir, "orgs"), dir}
	main()
	if code != 0 {
		t.Errorf("exit %d, want 0", code)
	}
	os.Args = []string{"anonymize", "-unknown-flag"}
	main()
	if code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
}

func TestFakeIPIgnores(t *testing.T) {
	m := newMapper()
	for _, x := range []string{"not an address", "127.0.0.1", "192.0.2.7", "10.77.0.5"} {
		m.fakeIP(x)
	}
	if len(m.ips) != 0 {
		t.Errorf("mapped %v", m.ips)
	}
}

// ECDSA keys of every curve become fresh keys of the same type; the same key twice gets the same fake.
func TestRewriteECDSA(t *testing.T) {
	m := newMapper()
	for _, kind := range []string{"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"} {
		blob := "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY" + kind[len(kind)-3:]
		out := m.rewrite(kind + " " + blob + " root@web-01\n" + kind + " " + blob + " again")
		g := regexp.MustCompile(`^(\S+) (\S+) root@web-01\n(\S+) (\S+) again$`).FindStringSubmatch(out)
		if g == nil || g[1] != kind || g[2] == blob || g[4] != g[2] {
			t.Fatalf("%s: %q", kind, out)
		}
		raw, err := base64.StdEncoding.DecodeString(g[2])
		mustT(t, err)
		pk, err := ssh.ParsePublicKey(raw)
		if err != nil || pk.Type() != kind {
			t.Fatalf("%s: %v %v", kind, pk, err)
		}
		if _, ok := pk.(ssh.CryptoPublicKey).CryptoPublicKey().(*ecdsa.PublicKey); !ok {
			t.Errorf("%s: not an ECDSA key", kind)
		}
	}
}

// Fingerprints, MACs and e-mails seen twice get the same fake both times.
func TestRewriteRepeats(t *testing.T) {
	m := newMapper()
	fp := "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	in := fp + " " + fp + "\n52:54:00:aa:bb:cc 52:54:00:AA:BB:CC\nops@acme-corp.net OPS@acme-corp.net"
	out := strings.Fields(m.rewrite(in))
	if len(out) != 6 || out[0] != out[1] || !strings.HasPrefix(out[0], fakeFP) || len(out[0]) != len(fp) ||
		out[2] != out[3] || !strings.HasPrefix(out[2], fakeMAC) || out[4] != "user1@example.com" || out[5] != out[4] {
		t.Errorf("%q", out)
	}
}

// Something@domain followed by more name characters is no e-mail and stays.
func TestRewriteEmailInsideWord(t *testing.T) {
	m := newMapper()
	in := "backup ops@acme-corp.net_old and ops@acme-corp.net"
	if out := m.rewrite(in); out != "backup ops@acme-corp.net_old and user1@example.com" {
		t.Errorf("%q", out)
	}
}

// ss prints an IPv6 address and port without brackets: the port form is not collected as an address of its own
// and is rewritten as the fake address with the same port; ::1:25 is loopback with a port, never collected.
func TestIPv6WithPort(t *testing.T) {
	m := newMapper()
	in := "fe80::1234:5678 listens on fe80::1234:5678:443 and ::1:25"
	m.collect(in)
	f, ok := m.ips["fe80::1234:5678"]
	if len(m.ips) != 1 || !ok || !strings.HasPrefix(f, fakeLinkLocal) {
		t.Fatalf("collected %v", m.ips)
	}
	if out := m.rewrite(in); out != f+" listens on "+f+":443 and ::1:25" {
		t.Errorf("%q", out)
	}
}

func TestReplaceFoldEmpty(t *testing.T) {
	if got := replaceFold("acme web-01", "", "x"); got != "acme web-01" {
		t.Errorf("%q", got)
	}
}

// A .gz whose content is cut off is reported as binary, not an error.
func TestReadTruncatedGzip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cut.txt.gz")
	mustT(t, os.WriteFile(p, gzBytes(strings.Repeat("from 10.20.30.40\n", 50))[:30], 0o644))
	if s, ok, err := read(p); s != "" || ok || err != nil {
		t.Errorf("%q %v %v", s, ok, err)
	}
}

// A directory argument that does not exist contributes no files.
func TestMissingRoot(t *testing.T) {
	var log strings.Builder
	dir := t.TempDir()
	if rc := run([]string{"-orgs", filepath.Join(dir, "orgs"), filepath.Join(dir, "gone")}, &log); rc != 0 ||
		!strings.Contains(log.String(), "files: 0, changed: 0") {
		t.Errorf("rc %d: %s", rc, log.String())
	}
}
