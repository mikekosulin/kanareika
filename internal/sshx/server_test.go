package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"

	"github.com/mikekosulin/kanareika/internal/config"
)

// testServer: a minimal sshd on 127.0.0.1. exec runs the command with the local sh (KN_NAME set to the server's
// name), direct-tcpip forwards like a bastion does, everything else is refused.
type testServer struct {
	t       *testing.T
	name    string
	ln      net.Listener
	port    int
	hostKey atomic.Value // ssh.Signer, swappable to simulate a reinstalled host
	authKey ssh.PublicKey
	rsaHost bool       // host key offered as ssh-rsa (SHA-1) only
	rsaSig  bool       // user keys accepted as ssh-rsa (SHA-1) signatures only
	extra   ssh.Signer // a second host key (servers usually have ed25519 + RSA + ECDSA)
	hang    bool       // never answer global requests (keepalives), like a peer behind a dead network path
	kex     []string   // server key exchanges; nil = x/crypto defaults

	mu       sync.Mutex
	conns    []*ssh.ServerConn
	logins   int
	forwards []string
}

func newServer(t *testing.T, name string, hostKey ssh.Signer, authKey ssh.PublicKey, opts ...func(*testServer)) *testServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	s := &testServer{t: t, name: name, ln: ln, port: ln.Addr().(*net.TCPAddr).Port, authKey: authKey}
	s.hostKey.Store(hostKey)
	for _, f := range opts {
		f(s)
	}
	t.Cleanup(func() { ln.Close(); s.drop() })
	go s.serve()
	return s
}

func (s *testServer) config() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) == string(s.authKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	hk := s.hostKey.Load().(ssh.Signer)
	cfg.KeyExchanges = s.kex
	if s.rsaSig {
		cfg.PublicKeyAuthAlgorithms = []string{ssh.KeyAlgoRSA}
	}
	if s.rsaHost {
		m, err := ssh.NewSignerWithAlgorithms(hk.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
		if err != nil {
			s.t.Error(err)
		}
		hk = m
	}
	cfg.AddHostKey(hk)
	if s.extra != nil {
		cfg.AddHostKey(s.extra)
	}
	return cfg
}

func (s *testServer) serve() {
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			sc, chans, reqs, err := ssh.NewServerConn(nc, s.config())
			if err != nil {
				nc.Close()
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, sc)
			s.logins++
			s.mu.Unlock()
			if s.hang {
				go func() {
					for range reqs {
					}
				}()
			} else {
				go ssh.DiscardRequests(reqs) // keepalives get a refusal, which still proves the server is alive
			}
			for nch := range chans {
				switch nch.ChannelType() {
				case "session":
					go s.session(nch)
				case "direct-tcpip":
					go s.forward(nch)
				default:
					nch.Reject(ssh.UnknownChannelType, "no")
				}
			}
		}()
	}
}

func (s *testServer) session(nch ssh.NewChannel) {
	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := false
	for req := range reqs {
		switch req.Type {
		case "exec":
			var p struct{ Command string }
			ssh.Unmarshal(req.Payload, &p)
			req.Reply(!started, nil)
			if started {
				continue
			}
			started = true
			go func() {
				cmd := exec.CommandContext(ctx, "sh", "-c", p.Command)
				cmd.Env = append(os.Environ(), "KN_NAME="+s.name)
				cmd.Stdout, cmd.Stderr = ch, ch.Stderr()
				cmd.WaitDelay = 100 * time.Millisecond
				code := 0
				if err := cmd.Run(); err != nil {
					var ee *exec.ExitError
					if errors.As(err, &ee) && ee.ExitCode() >= 0 {
						code = ee.ExitCode()
					} else {
						code = 255
					}
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
				ch.Close()
			}()
		case "signal":
			cancel()
		default:
			req.Reply(false, nil)
		}
	}
	cancel() // channel closed by the client
}

func (s *testServer) forward(nch ssh.NewChannel) {
	var p struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(nch.ExtraData(), &p); err != nil {
		nch.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	addr := net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port)))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		nch.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nch.Accept()
	if err != nil {
		c.Close()
		return
	}
	s.mu.Lock()
	s.forwards = append(s.forwards, addr)
	s.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	go func() { io.Copy(ch, c); ch.CloseWrite() }()
	io.Copy(c, ch)
	c.Close()
}

// drop closes every connection, as a reboot or a network cut would.
func (s *testServer) drop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = nil
}

func (s *testServer) stats() (logins int, forwards []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins, append([]string(nil), s.forwards...)
}

// centos6: what OpenSSH 5.3 offers; with sha1Only the server has no SHA-2 key exchange at all.
func centos6(sha1Only bool) func(*testServer) {
	return func(s *testServer) {
		s.rsaHost, s.rsaSig = true, true
		s.kex = []string{ssh.KeyExchangeDHGEXSHA256, ssh.InsecureKeyExchangeDHGEXSHA1, ssh.InsecureKeyExchangeDH14SHA1}
		if sha1Only {
			s.kex = []string{ssh.InsecureKeyExchangeDH14SHA1}
		}
	}
}

// --- keys, agent, org files ------------------------------------------------------------------------------------

func edKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	return signerPEM(t, priv)
}

func rsaKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	return signerPEM(t, priv)
}

func signerPEM(t *testing.T, priv any) (ssh.Signer, []byte) {
	t.Helper()
	blk, err := ssh.MarshalPrivateKey(priv, "")
	must(t, err)
	b := pem.EncodeToMemory(blk)
	s, err := ssh.ParsePrivateKey(b)
	must(t, err)
	rawKeys.Store(string(s.PublicKey().Marshal()), priv)
	return s, b
}

// startAgent serves an in-memory keyring at a fresh SSH_AUTH_SOCK. The socket lives under $TMPDIR, not
// t.TempDir(): unix socket paths are limited to ~100 bytes on macOS.
func startAgent(t *testing.T, keys ...any) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kna")
	must(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	must(t, err)
	t.Cleanup(func() { ln.Close() })
	kr := agent.NewKeyring()
	for _, k := range keys {
		must(t, kr.Add(agent.AddedKey{PrivateKey: k}))
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { agent.ServeAgent(kr, c); c.Close() }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
}

// loadOrg writes orgs/t1.yml into a fresh home and loads it with the real loader, so Secret and Jumps behave as
// in production.
func loadOrg(t *testing.T, p config.Paths, access map[string]any, hosts map[string]any) *config.Org {
	t.Helper()
	doc := map[string]any{
		"org":     map[string]any{"id": "t1", "name": "Test"},
		"consent": map[string]any{"document": "test", "signed": "2026-01-01", "valid_until": "2099-01-01"},
		"access":  access,
		"groups":  map[string]any{"app": map[string]any{"role": "app", "hosts": hosts}},
	}
	b, err := yaml.Marshal(doc)
	must(t, err)
	must(t, os.MkdirAll(p.Orgs, 0o755))
	must(t, os.WriteFile(filepath.Join(p.Orgs, "t1.yml"), b, 0o644))
	l, err := config.NewLoader(p)
	must(t, err)
	org, errs := l.LoadOrg(filepath.Join(p.Orgs, "t1.yml"))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	return org
}

func host(o *config.Org, name string) config.Host {
	for _, h := range o.Hosts {
		if h.Name == name {
			return h
		}
	}
	panic("no host " + name)
}

func hostEntry(s *testServer, extra ...any) map[string]any {
	m := map[string]any{"address": "127.0.0.1", "port": s.port}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i].(string)] = extra[i+1]
	}
	return m
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func writeSecret(t *testing.T, p config.Paths, rel string, b []byte) {
	t.Helper()
	path := filepath.Join(p.Secrets, rel)
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, b, 0o644)) // deliberately not 0600: bind mounts often get it wrong
}

func learnedFile(p config.Paths) string { return filepath.Join(p.Reports, "t1", "known_hosts") }

func knownName(s *testServer) string { return fmt.Sprintf("[127.0.0.1]:%d", s.port) }
