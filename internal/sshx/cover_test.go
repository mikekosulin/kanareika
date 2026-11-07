package sshx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/mikekosulin/kanareika/internal/config"
)

// setupWith: like setup, with server options.
func setupWith(t *testing.T, opts ...func(*testServer)) (*testServer, *OrgSSH, config.Host) {
	t.Helper()
	p := config.PathsAt(t.TempDir())
	user, pemb := edKey(t)
	writeSecret(t, p, "t1/id", pemb)
	hk, _ := edKey(t)
	s := newServer(t, "srv1", hk, user.PublicKey(), opts...)
	org := loadOrg(t, p, map[string]any{"user": "audit", "key": "t1/id"}, map[string]any{"h1": hostEntry(s)})
	o, err := New(org, p)
	must(t, err)
	t.Cleanup(func() { o.Close() })
	return s, o, host(org, "h1")
}

func shortConnectTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := ConnectTimeout
	ConnectTimeout = d
	t.Cleanup(func() { ConnectTimeout = old })
}

// silentListener accepts TCP connections and never says anything, like a host whose sshd hangs.
func silentListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
		for _, c := range conns {
			c.Close()
		}
	})
	return ln.Addr().String()
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestNewErrors(t *testing.T) {
	_, pemb := edKey(t)
	hosts := map[string]any{"h1": map[string]any{"address": "192.0.2.10"}}

	// reports/ is a file: the learned known_hosts cannot be created
	p := config.PathsAt(t.TempDir())
	writeSecret(t, p, "t1/id", pemb)
	org := loadOrg(t, p, map[string]any{"user": "audit", "key": "t1/id"}, hosts)
	must(t, os.WriteFile(p.Reports, nil, 0o644))
	if _, err := New(org, p); err == nil || !strings.Contains(err.Error(), errNotDir) {
		t.Fatalf("reports is a file: %v", err)
	}

	// the learned known_hosts points into a directory that does not exist
	p = config.PathsAt(t.TempDir())
	writeSecret(t, p, "t1/id", pemb)
	org = loadOrg(t, p, map[string]any{"user": "audit", "key": "t1/id"}, hosts)
	must(t, os.MkdirAll(filepath.Dir(learnedFile(p)), 0o755))
	if err := os.Symlink(filepath.Join(p.Home, "missing", "known_hosts"), learnedFile(p)); err != nil {
		t.Skip("no symlinks here:", err)
	}
	if _, err := New(org, p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling known_hosts: %v", err)
	}

	// secret paths that escape secrets/
	p = config.PathsAt(t.TempDir())
	writeSecret(t, p, "t1/id", pemb)
	org = loadOrg(t, p, map[string]any{"user": "audit", "key": "t1/id"}, hosts)
	org.Access()["known_hosts"] = "../known_hosts"
	if _, err := New(org, p); err == nil || !strings.Contains(err.Error(), "escapes secrets/") {
		t.Fatalf("known_hosts escape: %v", err)
	}
	org.Access()["known_hosts"] = "t1/absent" // a missing pinned file is skipped
	org.Access()["key"] = "../../id"
	if _, err := New(org, p); err == nil || !strings.Contains(err.Error(), "escapes secrets/") {
		t.Fatalf("key escape: %v", err)
	}

	// a key that is not a key
	org.Access()["key"] = "t1/garbage"
	writeSecret(t, p, "t1/garbage", []byte("not a key\n"))
	if _, err := New(org, p); err == nil || !strings.HasPrefix(err.Error(), "t1: SSH key secrets/t1/garbage: ") {
		t.Fatalf("garbage key: %v", err)
	}

	// a key that exists but cannot be read
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("file modes do not stop this user from reading")
	}
	org.Access()["key"] = "t1/locked"
	writeSecret(t, p, "t1/locked", pemb)
	must(t, os.Chmod(filepath.Join(p.Secrets, "t1", "locked"), 0))
	if _, err := New(org, p); err == nil || !strings.Contains(err.Error(), "permission denied") ||
		strings.Contains(err.Error(), "not found") {
		t.Fatalf("unreadable key: %v", err)
	}
}

func TestTargets(t *testing.T) {
	tg := hostTarget(config.Host{Name: "web-01", Address: "192.0.2.10"})
	if tg.port != 22 || tg.hostport() != "192.0.2.10:22" || tg.key != "h:web-01" {
		t.Fatalf("%+v", tg)
	}
	if jumpPort(map[string]any{"port": float64(2222)}) != 2222 || jumpPort(map[string]any{}) != 22 ||
		jumpPort(map[string]any{"port": "x"}) != 22 || jumpPort(map[string]any{"port": 2200}) != 2200 {
		t.Fatal("jumpPort")
	}
	if fixedAddr("192.0.2.10:22").Network() != "tcp" {
		t.Fatal("fixedAddr network")
	}
}

// TestJumpErrors: an unknown jump (hand-built host), a cycle (hand-built org), and an unreachable bastion.
func TestJumpErrors(t *testing.T) {
	_, o, h := setupWith(t)
	bad := h
	bad.Jump = "nope"
	if _, err := o.Run(ctx, bad, "true", time.Second, true); err == nil || err.Error() != "t1: unknown jump 'nope'" {
		t.Fatalf("unknown jump: %v", err)
	}
	// a jump through itself is a cycle: an error at once, not a deadlock on its own lock
	o.jumps["loop"] = jump{name: "loop", address: "192.0.2.1", port: 22, user: "audit", via: "loop"}
	bad.Jump = "loop"
	done := make(chan error, 1)
	go func() { _, err := o.Run(ctx, bad, "true", time.Second, true); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "jump chain cycle") {
			t.Fatalf("cycle: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a jump through itself hangs")
	}
	// a chain longer than any config allows stops before connecting anything
	for i := range 20 {
		o.jumps[fmt.Sprint("j", i)] = jump{name: fmt.Sprint("j", i), address: "192.0.2.1", port: 22, user: "audit", via: fmt.Sprint("j", i+1)}
	}
	bad.Jump = "j0"
	if _, err := o.Run(ctx, bad, "true", time.Second, true); err == nil || !strings.Contains(err.Error(), "jump j16: jump chain too long") ||
		!strings.HasPrefix(err.Error(), "h1: via ") {
		t.Fatalf("long chain: %v", err)
	}
	o.jumps["dead"] = jump{name: "dead", address: "127.0.0.1", port: closedPort(t), user: "audit"}
	bad.Jump = "dead"
	if _, err := o.Run(ctx, bad, "true", time.Second, true); err == nil || !strings.Contains(err.Error(), "h1: via jump dead: connect to 127.0.0.1:") {
		t.Fatalf("dead bastion: %v", err)
	}
}

// TestBastionStopsForwarding: a bastion connection that no longer opens channels (neither accepts nor refuses) is
// dropped and replaced once; then the dial fails.
func TestBastionStopsForwarding(t *testing.T) {
	shortConnectTimeout(t, 300*time.Millisecond)
	p := config.PathsAt(t.TempDir())
	user, pemb := edKey(t)
	writeSecret(t, p, "t1/id", pemb)
	k1, _ := edKey(t)
	b := newServer(t, "bastion", k1, user.PublicKey(), func(s *testServer) { s.hangForward = true })
	org := loadOrg(t, p, map[string]any{"user": "audit", "key": "t1/id", "jumps": map[string]any{
		"bastion": map[string]any{"address": "127.0.0.1", "port": b.port},
	}}, map[string]any{"web-01": map[string]any{"address": "192.0.2.10", "jump": "bastion"}})
	o, err := New(org, p)
	must(t, err)
	defer o.Close()
	_, err = o.Run(ctx, host(org, "web-01"), "true", 5*time.Second, true)
	if err == nil || !strings.Contains(err.Error(), "web-01: connect to 192.0.2.10:22") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if n, _ := b.stats(); n != 2 {
		t.Fatalf("bastion logins %d, want 2 (the stuck connection is replaced once)", n)
	}
}

func TestDirectConnectErrors(t *testing.T) {
	_, o, h := setupWith(t)
	dead := h
	dead.Port = closedPort(t)
	if _, err := o.Run(ctx, dead, "true", time.Second, true); err == nil || !strings.Contains(err.Error(), "h1: connect to 127.0.0.1:") {
		t.Fatalf("refused: %v", err)
	}

	// an sshd that never answers: the handshake times out
	host, port, _ := net.SplitHostPort(silentListener(t))
	silent := h
	silent.Address = host
	silent.Port = atoi(t, port)
	shortConnectTimeout(t, 200*time.Millisecond)
	start := time.Now()
	if _, err := o.Run(ctx, silent, "true", time.Second, true); err == nil || !strings.Contains(err.Error(), "handshake timed out after 200ms") {
		t.Fatalf("handshake timeout: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("handshake timeout too slow")
	}

	// the same, cancelled by the caller first
	ConnectTimeout = 10 * time.Second
	cctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if _, err := o.Run(cctx, silent, "true", time.Second, true); err == nil || !errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "handshake timed out") {
		t.Fatalf("cancelled handshake: %v", err)
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("not a port: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// TestCloseWhileConnecting: Close during a handshake; the new connection is thrown away, not cached.
func TestCloseWhileConnecting(t *testing.T) {
	inAuth, release := make(chan struct{}, 8), make(chan struct{})
	s, o, h := setupWith(t, func(s *testServer) {
		s.onAuth = func() { inAuth <- struct{}{}; <-release }
	})
	res := make(chan error, 1)
	go func() { _, err := o.Run(ctx, h, "true", 5*time.Second, true); res <- err }()
	<-inAuth
	closed := make(chan struct{})
	go func() { o.Close(); close(closed) }()
	for {
		o.mu.Lock()
		c := o.closed
		o.mu.Unlock()
		if c {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	if err := <-res; err == nil || err.Error() != "ssh: connections closed" {
		t.Fatalf("err %v", err)
	}
	<-closed
	// the server counts the login on its own goroutine, possibly after the client has its answer
	for i := 0; ; i++ {
		if n, _ := s.stats(); n == 1 {
			break
		} else if i == 500 {
			t.Fatalf("logins %d", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSessionRefused: a server that opens no sessions; the connection is replaced once, then it is an error.
func TestSessionRefused(t *testing.T) {
	s, o, h := setupWith(t, func(s *testServer) { s.noSession = true })
	_, err := o.Run(ctx, h, "true", time.Second, true)
	if err == nil || !strings.HasPrefix(err.Error(), "h1: ") || !strings.Contains(err.Error(), "no sessions") {
		t.Fatalf("err %v", err)
	}
	if n, _ := s.stats(); n != 2 {
		t.Fatalf("logins %d, want 2", n)
	}
	o.mu.Lock()
	e := o.conns["h:h1"]
	o.mu.Unlock()
	if e == nil || e.client != nil {
		t.Fatal("refusing connection still cached")
	}
}

func TestExecRefused(t *testing.T) {
	_, o, h := setupWith(t, func(s *testServer) { s.noExec = true })
	if _, err := o.Run(ctx, h, "true", time.Second, true); err == nil || !strings.HasPrefix(err.Error(), "h1: ") {
		t.Fatalf("err %v", err)
	}
}

// TestKilledBySignal: a command that dies of a signal exits 255, like ssh(1).
func TestKilledBySignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test sshd kills a sh process: Unix")
	}
	_, o, h := setupWith(t)
	_, err := o.Run(ctx, h, "echo before; kill -9 $$", 5*time.Second, true)
	if err == nil || !strings.HasPrefix(err.Error(), "h1: exit 255") {
		t.Fatalf("err %v", err)
	}
	out, err := o.Run(ctx, h, "echo before; kill -9 $$", 5*time.Second, false)
	if err != nil || out != "before\n" {
		t.Fatalf("check=false: %q %v", out, err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestStreamWriteError(t *testing.T) {
	_, o, h := setupWith(t)
	n, err := o.Stream(ctx, h, "echo data", failWriter{}, 1<<20, 5*time.Second, nil)
	if err == nil || err.Error() != "h1: write: disk full" || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestLimitWriterStaysFailed(t *testing.T) {
	l := &limitWriter{w: failWriter{}, max: 10, over: make(chan struct{})}
	if _, err := l.Write([]byte("0123456789x")); !errors.Is(err, errTooBig) {
		t.Fatal(err)
	}
	if n, err := l.Write([]byte("a")); n != 0 || !errors.Is(err, errTooBig) {
		t.Fatalf("after failure: %d %v", n, err)
	}
	select {
	case <-l.over:
	default:
		t.Fatal("over not closed")
	}
}

// TestForgetUnknown: forgetting a connection that is not cached only closes it.
func TestForgetUnknown(t *testing.T) {
	_, o, h := setupWith(t)
	_, err := o.Run(ctx, h, "true", 5*time.Second, true)
	must(t, err)
	o.mu.Lock()
	c := o.conns["h:h1"].client
	o.mu.Unlock()
	o.forget("h:other", c)
	if _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err == nil {
		t.Fatal("forgotten connection still open")
	}
	o.mu.Lock()
	cached := o.conns["h:h1"]
	o.mu.Unlock()
	if cached == nil {
		t.Fatal("cache entry of another key dropped")
	}
}

// --- known_hosts ------------------------------------------------------------------------------------------------

func TestKnownHostsErrors(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage")
	must(t, os.WriteFile(garbage, []byte("[127.0.0.1]:22 ssh-ed25519 !!!notbase64\n"), 0o644))
	key, _ := edKey(t)
	k := &knownHosts{learned: filepath.Join(dir, "learned"), files: []string{garbage}}
	if _, err := k.lookup("127.0.0.1:22"); err == nil {
		t.Fatal("lookup: broken file accepted")
	}
	if _, err := k.algorithms("127.0.0.1:22", false); err == nil {
		t.Fatal("algorithms: broken file accepted")
	}
	if err := k.callback("127.0.0.1:22")("", nil, key.PublicKey()); err == nil {
		t.Fatal("callback: broken file accepted")
	}

	// an address without a port is not a known_hosts error but an error all the same
	k = &knownHosts{learned: filepath.Join(dir, "learned"), files: []string{filepath.Join(dir, "learned")}}
	must(t, os.WriteFile(k.learned, nil, 0o644))
	if _, err := k.lookup("no-port"); err == nil || errors.As(err, new(*knownhosts.KeyError)) {
		t.Fatalf("lookup no port: %v", err)
	}
	if err := k.callback("no-port")("", nil, key.PublicKey()); err == nil || errors.As(err, new(*HostKeyError)) {
		t.Fatalf("callback no port: %v", err)
	}

	// a host that knows the probe key: nothing to prefer
	must(t, os.WriteFile(k.learned, []byte(knownhosts.Line([]string{"[127.0.0.1]:2222"}, probeKey)+"\n"), 0o644))
	if known, err := k.lookup("127.0.0.1:2222"); err != nil || known != nil {
		t.Fatalf("probe key known: %v %v", known, err)
	}

	// revoked key
	must(t, os.WriteFile(k.learned, []byte("@revoked "+knownhosts.Line([]string{"*"}, key.PublicKey())+"\n"), 0o644))
	err := k.callback("127.0.0.1:22")("", nil, key.PublicKey())
	var hk *HostKeyError
	if !errors.As(err, &hk) || hk.Changed || !strings.Contains(err.Error(), "is revoked") ||
		!strings.Contains(err.Error(), "Host key verification failed") || hk.Host != "127.0.0.1" {
		t.Fatalf("revoked: %v", err)
	}

	// the learned file cannot be appended to
	k = &knownHosts{learned: dir, files: []string{filepath.Join(dir, "learned")}}
	must(t, os.WriteFile(filepath.Join(dir, "learned"), nil, 0o644))
	if err := k.callback("127.0.0.1:22")("", nil, key.PublicKey()); err == nil || errors.As(err, new(*HostKeyError)) {
		t.Fatalf("learn into a directory: %v", err)
	}
}

// TestBrokenPinnedFile: a broken pinned known_hosts stops the connection before any key is offered.
func TestBrokenPinnedFile(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	user, pemb := edKey(t)
	writeSecret(t, p, "t1/id", pemb)
	writeSecret(t, p, "t1/known_hosts", []byte("[127.0.0.1]:22 ssh-ed25519 !!!notbase64\n"))
	hk, _ := edKey(t)
	s := newServer(t, "srv1", hk, user.PublicKey())
	org := loadOrg(t, p, map[string]any{"user": "audit", "key": "t1/id", "known_hosts": "t1/known_hosts"},
		map[string]any{"h1": hostEntry(s)})
	o, err := New(org, p)
	must(t, err)
	defer o.Close()
	if _, err := o.Run(ctx, host(org, "h1"), "true", time.Second, true); err == nil || !strings.Contains(err.Error(), "knownhosts") {
		t.Fatalf("err %v", err)
	}
	if n, _ := s.stats(); n != 0 {
		t.Fatalf("logins %d", n)
	}
}

// onlySigner hides the AlgorithmSigner methods of a key.
type onlySigner struct{ s ssh.Signer }

func (o onlySigner) PublicKey() ssh.PublicKey                              { return o.s.PublicKey() }
func (o onlySigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) { return o.s.Sign(r, data) }

func TestRestrictSigners(t *testing.T) {
	ed, _ := edKey(t)
	rs, _ := rsaKey(t)
	got := restrictSigners([]ssh.Signer{ed, onlySigner{rs}, rs}, false)
	if len(got) != 2 || got[0] != ed {
		t.Fatalf("got %d signers", len(got))
	}
	if _, ok := got[1].(ssh.MultiAlgorithmSigner); !ok {
		t.Fatal("RSA signer not restricted to SHA-2")
	}
}

// --- agent --------------------------------------------------------------------------------------------------------

// brokenAgent lists no keys but an error.
type brokenAgent struct{ agent.Agent }

func (brokenAgent) List() ([]*agent.Key, error) { return nil, errors.New("agent locked") }

func serveAgent(t *testing.T, a agent.Agent) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the test agent listens on a unix socket")
	}
	dir, err := os.MkdirTemp("", "kna")
	must(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	must(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { agent.ServeAgent(a, c); c.Close() }()
		}
	}()
	return sock
}

func TestAgentErrors(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	user, _ := edKey(t)
	hk, _ := edKey(t)
	s := newServer(t, "srv1", hk, user.PublicKey())
	org := loadOrg(t, p, map[string]any{"user": "audit"}, map[string]any{"h1": hostEntry(s)})

	t.Setenv("SSH_AUTH_SOCK", serveAgent(t, brokenAgent{agent.NewKeyring()}))
	o, err := New(org, p)
	must(t, err)
	defer o.Close()
	if _, err := o.Run(ctx, host(org, "h1"), "true", time.Second, true); err == nil || !strings.Contains(err.Error(), "agent: failed to list keys") {
		t.Fatalf("listing fails: %v", err)
	}

	// the agent went away after New
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "gone.sock"))
	if _, err := o.Run(ctx, host(org, "h1"), "true", time.Second, true); err == nil || !strings.HasPrefix(err.Error(), "t1: ssh-agent: ") {
		t.Fatalf("agent gone: %v", err)
	}
}

// --- keepalive ----------------------------------------------------------------------------------------------------

// dialRaw: a plain client to s, without OrgSSH's own keepalive.
func dialRaw(t *testing.T, s *testServer, user ssh.Signer) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", s.ln.Addr().String(), &ssh.ClientConfig{User: "audit", Auth: []ssh.AuthMethod{ssh.PublicKeys(user)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	must(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}

func runKeepalive(c *ssh.Client, done <-chan struct{}, every time.Duration, maxMisses int) <-chan struct{} {
	ret := make(chan struct{})
	go func() { keepalive(c, done, every, maxMisses); close(ret) }()
	return ret
}

func TestKeepaliveAnswered(t *testing.T) {
	user, _ := edKey(t)
	hk, _ := edKey(t)
	s := newServer(t, "srv1", hk, user.PublicKey())
	c := dialRaw(t, s, user)
	done := make(chan struct{})
	ret := runKeepalive(c, done, 20*time.Millisecond, 1)
	time.Sleep(150 * time.Millisecond) // several answered rounds; one miss would close the connection
	if _, _, err := c.SendRequest("ping@example.com", true, nil); err != nil {
		t.Fatal("answered keepalives closed the connection:", err)
	}
	close(done)
	<-ret
}

func TestKeepaliveOnClosedConnection(t *testing.T) {
	user, _ := edKey(t)
	hk, _ := edKey(t)
	s := newServer(t, "srv1", hk, user.PublicKey())
	c := dialRaw(t, s, user)
	c.Close()
	select {
	case <-runKeepalive(c, make(chan struct{}), 10*time.Millisecond, 100):
	case <-time.After(3 * time.Second):
		t.Fatal("keepalive kept running on a closed connection")
	}
}

func TestKeepaliveStopsWhileWaiting(t *testing.T) {
	asked := make(chan struct{}, 16)
	user, _ := edKey(t)
	hk, _ := edKey(t)
	s := newServer(t, "srv1", hk, user.PublicKey(), func(s *testServer) {
		s.hang = true
		s.onGlobal = func() { asked <- struct{}{} }
	})
	c := dialRaw(t, s, user)
	done := make(chan struct{})
	ret := runKeepalive(c, done, 200*time.Millisecond, 100)
	<-asked // a keepalive is waiting for its reply
	close(done)
	select {
	case <-ret:
	case <-time.After(3 * time.Second):
		t.Fatal("keepalive did not stop")
	}
}
