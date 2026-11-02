package sshx

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/mikekosulin/kanareika/internal/config"
)

var ctx = context.Background()

// setup: one modern server, user key in secrets/t1/id (access.key).
func setup(t *testing.T, access map[string]any) (config.Paths, *testServer, *OrgSSH, config.Host) {
	t.Helper()
	p := config.PathsAt(t.TempDir())
	user, pemb := edKey(t)
	writeSecret(t, p, "t1/id", pemb)
	hk, _ := edKey(t)
	s := newServer(t, "srv1", hk, user.PublicKey())
	acc := map[string]any{"user": "audit", "key": "t1/id"}
	for k, v := range access {
		acc[k] = v
	}
	org := loadOrg(t, p, acc, map[string]any{"h1": hostEntry(s)})
	o, err := New(org, p)
	must(t, err)
	t.Cleanup(func() { o.Close() })
	return p, s, o, host(org, "h1")
}

func TestKeyFileRunAndLearn(t *testing.T) {
	p, s, o, h := setup(t, nil)
	out, err := o.Run(ctx, h, "echo hello; echo $KN_NAME", 10*time.Second, true)
	must(t, err)
	if out != "hello\nsrv1\n" {
		t.Fatalf("out %q", out)
	}
	b, err := os.ReadFile(learnedFile(p))
	must(t, err)
	if !strings.HasPrefix(string(b), knownName(s)+" ssh-ed25519 ") || strings.Count(string(b), "\n") != 1 {
		t.Fatalf("known_hosts %q", b)
	}
	// the connection is reused: a second command does not log in again
	_, err = o.Run(ctx, h, "true", 10*time.Second, true)
	must(t, err)
	if n, _ := s.stats(); n != 1 {
		t.Fatalf("logins %d, want 1", n)
	}
}

func TestExitStatus(t *testing.T) {
	_, _, o, h := setup(t, nil)
	_, err := o.Run(ctx, h, "echo out; echo boom >&2; exit 3", 10*time.Second, true)
	if err == nil || err.Error() != "h1: exit 3: boom" {
		t.Fatalf("err %v", err)
	}
	out, err := o.Run(ctx, h, "echo out; exit 3", 10*time.Second, false)
	if err != nil || out != "out\n" {
		t.Fatalf("check=false: %q %v", out, err)
	}
	long := strings.Repeat("x", 600) + "END"
	_, err = o.Run(ctx, h, "printf '"+long+"' >&2; exit 1", 10*time.Second, true)
	if err == nil || !strings.HasSuffix(err.Error(), "END") || len(err.Error()) != len("h1: exit 1: ")+500 {
		t.Fatalf("stderr tail: %v", err)
	}
}

func TestTimeoutKillsSession(t *testing.T) {
	_, _, o, h := setup(t, nil)
	start := time.Now()
	_, err := o.Run(ctx, h, "sleep 5", 300*time.Millisecond, true)
	if err == nil || err.Error() != "h1: timeout" || time.Since(start) > 3*time.Second {
		t.Fatalf("err %v after %s", err, time.Since(start))
	}
	// the connection survives a killed session
	out, err := o.Run(ctx, h, "echo ok", 10*time.Second, true)
	if err != nil || out != "ok\n" {
		t.Fatalf("after timeout: %q %v", out, err)
	}
	cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if _, err := o.Run(cctx, h, "sleep 5", 0, true); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("ctx: %v", err)
	}
}

func TestStream(t *testing.T) {
	_, _, o, h := setup(t, nil)
	var buf bytes.Buffer
	n, err := o.Stream(ctx, h, "head -c 3000000 /dev/zero", &buf, 10<<20, 10*time.Second, nil)
	if err != nil || n != 3000000 || buf.Len() != 3000000 {
		t.Fatalf("n=%d len=%d err=%v", n, buf.Len(), err)
	}
	buf.Reset()
	start := time.Now()
	n, err = o.Stream(ctx, h, "cat /dev/zero", &buf, 1<<20, 10*time.Second, nil)
	if err == nil || err.Error() != "h1: output exceeds 1 MB, aborted" || n > 1<<20 || time.Since(start) > 5*time.Second {
		t.Fatalf("limit: n=%d err=%v", n, err)
	}
	// non-zero exit is an error only without output
	n, err = o.Stream(ctx, h, "echo partial; exit 1", &buf, 1<<20, 10*time.Second, nil)
	if err != nil || n != 8 {
		t.Fatalf("partial: %d %v", n, err)
	}
	_, err = o.Stream(ctx, h, "echo nope >&2; exit 2", &buf, 1<<20, 10*time.Second, nil)
	if err == nil || err.Error() != "h1: exit 2: nope" {
		t.Fatalf("empty: %v", err)
	}
	_, err = o.Stream(ctx, h, "sleep 5", &buf, 1<<20, 300*time.Millisecond, nil)
	if err == nil || err.Error() != "h1: timeout" {
		t.Fatalf("timeout: %v", err)
	}
	old := ProgressEvery
	ProgressEvery = 0
	defer func() { ProgressEvery = old }()
	var mbs []int64
	_, err = o.Stream(ctx, h, "head -c 2200000 /dev/zero", &bytes.Buffer{}, 10<<20, 10*time.Second,
		func(mb int64) { mbs = append(mbs, mb) })
	if err != nil || len(mbs) == 0 || mbs[len(mbs)-1] != 2 {
		t.Fatalf("progress %v %v", mbs, err)
	}
}

func TestChangedHostKeyRejected(t *testing.T) {
	p, s, o, h := setup(t, nil)
	_, err := o.Run(ctx, h, "true", 10*time.Second, true)
	must(t, err)
	o.Close()
	before, _ := os.ReadFile(learnedFile(p))

	// a fresh run trusts the learned key
	o2, err := New(o.org, p)
	must(t, err)
	defer o2.Close()
	_, err = o2.Run(ctx, h, "true", 10*time.Second, true)
	must(t, err)
	o2.Close()

	// the host is "reinstalled": a new key of the same type is never accepted, and nothing is learned
	nk, _ := edKey(t)
	s.hostKey.Store(nk)
	o3, err := New(o.org, p)
	must(t, err)
	defer o3.Close()
	_, err = o3.Run(ctx, h, "true", 10*time.Second, true)
	if err == nil || !strings.Contains(err.Error(), "REMOTE HOST IDENTIFICATION HAS CHANGED") ||
		!strings.Contains(err.Error(), "Host key verification failed") {
		t.Fatalf("err %v", err)
	}
	after, _ := os.ReadFile(learnedFile(p))
	if !bytes.Equal(before, after) {
		t.Fatalf("known_hosts changed:\n%s\n%s", before, after)
	}
}

func TestStrict(t *testing.T) {
	p, s, o, h := setup(t, map[string]any{"host_key_checking": "strict", "known_hosts": "t1/known_hosts"})
	_, err := o.Run(ctx, h, "true", 10*time.Second, true)
	if err == nil || !strings.Contains(err.Error(), "Host key verification failed") {
		t.Fatalf("unknown host in strict mode: %v", err)
	}
	// pinned in secrets/: accepted, and the learned file stays empty
	line := knownhosts.Line([]string{knownName(s)}, s.hostKey.Load().(ssh.Signer).PublicKey())
	writeSecret(t, p, "t1/known_hosts", []byte(line+"\n"))
	o2, err := New(o.org, p)
	must(t, err)
	defer o2.Close()
	_, err = o2.Run(ctx, h, "true", 10*time.Second, true)
	must(t, err)
	if b, _ := os.ReadFile(learnedFile(p)); len(b) != 0 {
		t.Fatalf("learned %q", b)
	}
}

func TestAgentAuthAndErrors(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	user, _ := edKey(t)
	_, other := edKey(t)
	hk, _ := edKey(t)
	s := newServer(t, "srv1", hk, user.PublicKey())
	org := loadOrg(t, p, map[string]any{"user": "audit"}, map[string]any{"h1": hostEntry(s)})

	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := New(org, p); err == nil || !strings.Contains(err.Error(), "no access.key and no ssh-agent") {
		t.Fatalf("no agent: %v", err)
	}

	otherKey, err := ssh.ParseRawPrivateKey(other)
	must(t, err)
	userRaw := rawKey(t, user)
	startAgent(t, otherKey, userRaw) // the right key is not the first one
	o, err := New(org, p)
	must(t, err)
	defer o.Close()
	out, err := o.Run(ctx, host(org, "h1"), "echo $KN_NAME", 10*time.Second, true)
	if err != nil || out != "srv1\n" {
		t.Fatalf("agent: %q %v", out, err)
	}

	// IdentitiesOnly: with access.key set, the agent's (right) key is not offered
	writeSecret(t, p, "t1/wrong", other)
	org2 := loadOrg(t, p, map[string]any{"user": "audit", "key": "t1/wrong"}, map[string]any{"h1": hostEntry(s)})
	o2, err := New(org2, p)
	must(t, err)
	defer o2.Close()
	if _, err := o2.Run(ctx, host(org2, "h1"), "true", 10*time.Second, true); err == nil ||
		!strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("identities only: %v", err)
	}

	org3 := loadOrg(t, p, map[string]any{"user": "audit", "key": "t1/missing"}, map[string]any{"h1": hostEntry(s)})
	if _, err := New(org3, p); err == nil || err.Error() != "t1: SSH key not found: secrets/t1/missing" {
		t.Fatalf("missing key: %v", err)
	}
}

// rawKey: the private key behind a test signer (generated by edKey), for the agent keyring.
var rawKeys sync.Map

func rawKey(t *testing.T, s ssh.Signer) any {
	t.Helper()
	k, ok := rawKeys.Load(string(s.PublicKey().Marshal()))
	if !ok {
		t.Fatal("unknown test key")
	}
	return k
}

func TestJumpChain(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	user, pemb := edKey(t)
	writeSecret(t, p, "t1/id", pemb)
	k1, _ := edKey(t)
	k2, _ := edKey(t)
	k3, _ := edKey(t)
	outer := newServer(t, "outer", k1, user.PublicKey())
	inner := newServer(t, "inner", k2, user.PublicKey())
	target := newServer(t, "target", k3, user.PublicKey())
	org := loadOrg(t, p, map[string]any{"user": "audit", "key": "t1/id", "jumps": map[string]any{
		"outer": map[string]any{"address": "127.0.0.1", "port": outer.port},
		"inner": map[string]any{"address": "127.0.0.1", "port": inner.port, "user": "bastion", "jump": "outer"},
	}}, map[string]any{
		"a": hostEntry(target, "jump", "inner"),
		"b": hostEntry(target, "jump", "inner", "user", "root"),
	})
	o, err := New(org, p)
	must(t, err)
	defer o.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := []string{"a", "b"}[i%2]
			out, err := o.Run(ctx, host(org, name), "echo $KN_NAME", 10*time.Second, true)
			if err == nil && out != "target\n" {
				err = os.ErrInvalid
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		must(t, err)
	}
	if n, fw := outer.stats(); n != 1 || len(fw) != 1 || fw[0] != inner.ln.Addr().String() {
		t.Fatalf("outer: logins %d forwards %v", n, fw)
	}
	if n, fw := inner.stats(); n != 1 || len(fw) != 2 { // one bastion login, one channel per host
		t.Fatalf("inner: logins %d forwards %v", n, fw)
	}
	b, _ := os.ReadFile(learnedFile(p))
	for _, s := range []*testServer{outer, inner, target} {
		if !strings.Contains(string(b), knownName(s)+" ") {
			t.Fatalf("%s not learned under its address:\n%s", s.name, b)
		}
	}

	// a dead bastion connection is replaced on the next command
	outer.drop()
	time.Sleep(100 * time.Millisecond)
	out, err := o.Run(ctx, host(org, "a"), "echo $KN_NAME", 10*time.Second, true)
	if err != nil || out != "target\n" {
		t.Fatalf("reconnect: %q %v", out, err)
	}
}

func TestLegacy(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	user, pemb := rsaKey(t)
	writeSecret(t, p, "t1/id", pemb)
	hk, _ := rsaKey(t)
	c6 := newServer(t, "centos6", hk, user.PublicKey(), centos6(false))
	c6sha1 := newServer(t, "centos6-sha1", hk, user.PublicKey(), centos6(true))
	mhk, _ := edKey(t)
	sigOnly := newServer(t, "rsa-sig", mhk, user.PublicKey(), func(s *testServer) { s.rsaSig = true })
	modern := newServer(t, "modern", mhk, user.PublicKey())
	hosts := map[string]any{"modern": hostEntry(modern)}
	for name, s := range map[string]*testServer{"c6": c6, "c6sha1": c6sha1, "sig": sigOnly} {
		hosts[name] = hostEntry(s)
		hosts[name+"-legacy"] = hostEntry(s, "legacy_ssh", true)
	}
	org := loadOrg(t, p, map[string]any{"user": "root", "key": "t1/id"}, hosts)
	o, err := New(org, p)
	must(t, err)
	defer o.Close()
	for name, want := range map[string]string{"c6": "host key", "c6sha1": "key exchange", "sig": "signature algorithm"} {
		_, err := o.Run(ctx, host(org, name), "true", 10*time.Second, true)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s without legacy_ssh: want %q, got %v", name, want, err)
		}
		out, err := o.Run(ctx, host(org, name+"-legacy"), "echo $KN_NAME", 10*time.Second, true)
		if err != nil || out == "" {
			t.Fatalf("%s with legacy_ssh: %q %v", name, out, err)
		}
	}
	if _, err := o.Run(ctx, host(org, "modern"), "true", 10*time.Second, true); err != nil {
		t.Fatalf("modern next to legacy: %v", err)
	}
	// SHA-1 is offered for the legacy host only
	cfg, cleanup, err := o.clientConfig(hostTarget(host(org, "modern")))
	must(t, err)
	cleanup()
	for _, a := range append(cfg.HostKeyAlgorithms, cfg.KeyExchanges...) {
		if a == ssh.KeyAlgoRSA || strings.HasSuffix(a, "-sha1") {
			t.Fatalf("modern host offers %s", a)
		}
	}
}

func TestGuardAndClose(t *testing.T) {
	_, _, o, h := setup(t, nil)
	other := h
	other.Org = "evil"
	if _, err := o.Run(ctx, other, "true", time.Second, true); err == nil ||
		err.Error() != "host h1 belongs to evil, not t1" {
		t.Fatalf("guard: %v", err)
	}
	if _, err := o.Stream(ctx, other, "true", &bytes.Buffer{}, 1, time.Second, nil); err == nil {
		t.Fatal("guard: stream")
	}
	_, err := o.Run(ctx, h, "true", 10*time.Second, true)
	must(t, err)
	must(t, o.Close())
	if _, err := o.Run(ctx, h, "true", 10*time.Second, true); err == nil {
		t.Fatal("run after close")
	}
}

func TestKeepaliveDropsDeadConnection(t *testing.T) {
	oldEvery, oldMax := KeepaliveInterval, KeepaliveCountMax
	KeepaliveInterval, KeepaliveCountMax = 50*time.Millisecond, 2
	defer func() { KeepaliveInterval, KeepaliveCountMax = oldEvery, oldMax }()
	p := config.PathsAt(t.TempDir())
	user, pemb := edKey(t)
	writeSecret(t, p, "t1/id", pemb)
	hk, _ := edKey(t)
	s := newServer(t, "srv1", hk, user.PublicKey(), func(s *testServer) { s.hang = true })
	org := loadOrg(t, p, map[string]any{"user": "audit", "key": "t1/id"}, map[string]any{"h1": hostEntry(s)})
	o, err := New(org, p)
	must(t, err)
	defer o.Close()
	h := host(org, "h1")
	_, err = o.Run(ctx, h, "true", 10*time.Second, true)
	must(t, err)
	time.Sleep(400 * time.Millisecond) // > interval * (count+1)
	_, err = o.Run(ctx, h, "true", 10*time.Second, true)
	must(t, err)
	if n, _ := s.stats(); n != 2 {
		t.Fatalf("logins %d, want 2 (the unanswered connection is replaced)", n)
	}
}

// A host known by its RSA key that also has an ed25519 key: the known type is asked for first, so strict mode
// connects instead of treating the ed25519 key as unknown.
func TestKnownKeyTypePreferred(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	user, pemb := edKey(t)
	writeSecret(t, p, "t1/id", pemb)
	ed, _ := edKey(t)
	rk, _ := rsaKey(t)
	s := newServer(t, "srv1", ed, user.PublicKey(), func(s *testServer) { s.extra = rk })
	writeSecret(t, p, "t1/known_hosts", []byte(knownhosts.Line([]string{knownName(s)}, rk.PublicKey())+"\n"))
	org := loadOrg(t, p, map[string]any{"user": "audit", "key": "t1/id", "known_hosts": "t1/known_hosts",
		"host_key_checking": "strict"}, map[string]any{"h1": hostEntry(s)})
	o, err := New(org, p)
	must(t, err)
	defer o.Close()
	_, err = o.Run(ctx, host(org, "h1"), "true", 10*time.Second, true)
	must(t, err)
}
