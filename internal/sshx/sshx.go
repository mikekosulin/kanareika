// Package sshx is SSH access to one organization's hosts, natively on golang.org/x/crypto/ssh.
// It replaces kanareika/ssh.py, which wrote a per-run ssh_config and shelled out to OpenSSH; the behaviour is the
// same: per-org keys, jump chains and known_hosts never mix between orgs, one connection per host is reused for the
// whole run (ControlMaster), and only read-only commands are sent; nothing is copied to the hosts.
package sshx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
)

var _ check.Runner = (*OrgSSH)(nil)

// The ssh_config values ssh.py used: ConnectTimeout 15, ServerAliveInterval 15, ServerAliveCountMax 4.
var (
	ConnectTimeout    = 15 * time.Second
	KeepaliveInterval = 15 * time.Second
	KeepaliveCountMax = 4
)

// OrgSSH holds the connections of one org. Safe for concurrent use: hosts are scanned in parallel.
type OrgSSH struct {
	org    *config.Org
	user   string            // access.user, the default for jumps
	jumps  map[string]jump   // access.jumps
	signer ssh.Signer        // access.key from secrets/; nil = ssh-agent
	known  *knownHosts       // learned + pinned host keys
	mu     sync.Mutex        // guards conns and closed
	conns  map[string]*entry // "h:<host>" / "j:<jump>" -> connection
	closed bool
}

type jump struct {
	name, address, user, via string
	port                     int
}

// entry: one cached client. Its own lock serializes connecting, so parallel hosts behind one bastion share it.
type entry struct {
	mu     sync.Mutex
	client *ssh.Client
}

// New prepares access for one org. learned host keys go to <reports>/<org>/known_hosts. Like ssh.py it fails early
// when there is neither access.key nor an ssh-agent.
func New(org *config.Org, p config.Paths) (*OrgSSH, error) {
	acc := org.Access()
	o := &OrgSSH{org: org, user: str(acc, "user"), jumps: map[string]jump{}, conns: map[string]*entry{}}
	for name, j := range org.Jumps() {
		u := str(j, "user")
		if u == "" {
			u = o.user
		}
		o.jumps[name] = jump{name: name, address: str(j, "address"), port: intOr(j, "port", 22), user: u,
			via: str(j, "jump")}
	}

	learned := filepath.Join(p.Reports, org.ID, "known_hosts")
	if err := os.MkdirAll(filepath.Dir(learned), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(learned, os.O_CREATE|os.O_RDONLY, 0o644)
	if err != nil {
		return nil, err
	}
	f.Close()
	files := []string{learned}
	pinned, err := org.Secret(str(acc, "known_hosts"))
	if err != nil {
		return nil, err
	}
	if pinned != "" {
		if _, err := os.Stat(pinned); err == nil { // a missing pinned file is skipped, as in ssh.py
			files = append(files, pinned)
		}
	}
	o.known = &knownHosts{learned: learned, files: files, strict: str(acc, "host_key_checking") == "strict"}

	key, err := org.Secret(str(acc, "key"))
	if err != nil {
		return nil, err
	}
	if key == "" {
		if agentPath() == "" {
			return nil, fmt.Errorf("%s: no access.key and no ssh-agent (%s): start it and ssh-add your key", org.ID, agentHint)
		}
		return o, nil
	}
	b, err := os.ReadFile(key)
	if err != nil {
		if st, serr := os.Stat(key); serr != nil || !st.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: SSH key not found: secrets/%s", org.ID, str(acc, "key"))
		}
		return nil, fmt.Errorf("%s: SSH key secrets/%s: %w", org.ID, str(acc, "key"), err)
	}
	// parsed once; unlike OpenSSH the file mode does not matter, so ssh.py's 0600 copy is not needed
	if o.signer, err = ssh.ParsePrivateKey(b); err != nil {
		return nil, fmt.Errorf("%s: SSH key secrets/%s: %w", org.ID, str(acc, "key"), err)
	}
	return o, nil
}

// Close closes every connection (hosts first, then the jumps they ran through). Later calls fail.
func (o *OrgSSH) Close() error {
	o.mu.Lock()
	o.closed = true
	conns := o.conns
	o.conns = map[string]*entry{}
	o.mu.Unlock()
	keys := make([]string, 0, len(conns))
	for k := range conns {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return strings.Compare(b, a) }) // "j:" after "h:"
	for _, k := range keys {
		e := conns[k]
		e.mu.Lock()
		if e.client != nil {
			e.client.Close()
			e.client = nil
		}
		e.mu.Unlock()
	}
	return nil
}

// guard: an OrgSSH never talks to another org's host (as _cmd in ssh.py; should never trigger).
func (o *OrgSSH) guard(h config.Host) error {
	if h.Org != o.org.ID {
		return fmt.Errorf("host %s belongs to %s, not %s", h.Name, h.Org, o.org.ID)
	}
	return nil
}

// target: what to connect to; host and jump look the same here.
type target struct {
	key, label, address, user, via string
	port                           int
	legacy                         bool
}

func (t target) hostport() string { return net.JoinHostPort(t.address, fmt.Sprint(t.port)) }

func hostTarget(h config.Host) target {
	port := h.Port
	if port == 0 {
		port = 22
	}
	return target{key: "h:" + h.Name, label: h.Name, address: h.Address, port: port, user: h.User, via: h.Jump,
		legacy: h.LegacySSH}
}

func (o *OrgSSH) jumpTarget(name string) (target, error) {
	j, ok := o.jumps[name]
	if !ok {
		return target{}, fmt.Errorf("%s: unknown jump '%s'", o.org.ID, name)
	}
	// jumps get modern algorithms only: legacy_ssh is a per-host switch, as in the generated ssh_config
	return target{key: "j:" + name, label: "jump " + name, address: j.address, port: j.port, user: j.user, via: j.via}, nil
}

// client returns the cached connection for t, connecting (through its jump chain) when there is none or it died.
func (o *OrgSSH) client(ctx context.Context, t target, depth int) (*ssh.Client, error) {
	if depth > 16 { // config rejects cycles; this only stops a hand-built Org from recursing forever
		return nil, fmt.Errorf("%s: jump chain too long", t.label)
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil, errors.New("ssh: connections closed")
	}
	e := o.conns[t.key]
	if e == nil {
		e = &entry{}
		o.conns[t.key] = e
	}
	o.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.client != nil {
		return e.client, nil
	}
	c, err := o.dial(ctx, t, depth)
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	closed := o.closed
	o.mu.Unlock()
	if closed { // Close ran while we were connecting
		c.Close()
		return nil, errors.New("ssh: connections closed")
	}
	e.client = c
	done := make(chan struct{})
	go func() { // forget a dead connection so the next command reconnects (as a new ControlMaster would)
		c.Wait()
		close(done)
		e.mu.Lock()
		if e.client == c {
			e.client = nil
		}
		e.mu.Unlock()
	}()
	go keepalive(c, done, KeepaliveInterval, KeepaliveCountMax)
	return c, nil
}

// dial opens the TCP connection (directly or as a direct-tcpip channel of the previous hop, like ProxyJump) and
// runs the SSH handshake and auth within ConnectTimeout.
func (o *OrgSSH) dial(ctx context.Context, t target, depth int) (*ssh.Client, error) {
	addr := t.hostport()
	var conn net.Conn
	var err error
	if t.via != "" {
		jt, jerr := o.jumpTarget(t.via)
		if jerr != nil {
			return nil, jerr
		}
		for attempt := 0; attempt < 2; attempt++ {
			jc, jerr := o.client(ctx, jt, depth+1)
			if jerr != nil {
				return nil, fmt.Errorf("%s: via %w", t.label, jerr)
			}
			dctx, cancel := context.WithTimeout(ctx, ConnectTimeout)
			conn, err = jc.DialContext(dctx, "tcp", addr)
			cancel()
			var refused *ssh.OpenChannelError
			if err == nil || errors.As(err, &refused) || ctx.Err() != nil {
				break // a refusal comes from a live bastion; anything else means its connection is gone
			}
			o.forget(jt.key, jc)
		}
	} else {
		d := net.Dialer{Timeout: ConnectTimeout}
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: connect to %s: %w", t.label, addr, err)
	}

	cfg, cleanup, err := o.clientConfig(t)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer cleanup()
	// channel conns have no deadlines, so the handshake timeout closes the conn instead
	timer := time.AfterFunc(ConnectTimeout, func() { conn.Close() })
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	stop()
	if !timer.Stop() && err != nil {
		err = fmt.Errorf("handshake timed out after %s", ConnectTimeout)
	} else if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s: %s@%s: %w", t.label, t.user, addr, err)
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

// clientConfig: auth, host key checking and algorithms for one target. cleanup closes the agent connection.
func (o *OrgSSH) clientConfig(t target) (*ssh.ClientConfig, func(), error) {
	cleanup := func() {}
	var signers func() ([]ssh.Signer, error)
	if o.signer != nil {
		// IdentitiesOnly: with access.key only that key is offered, never the agent's
		signers = func() ([]ssh.Signer, error) { return []ssh.Signer{o.signer}, nil } //nolint:unparam // ssh.PublicKeysCallback's signature
	} else {
		ac, err := dialAgent(agentPath())
		if err != nil {
			return nil, nil, fmt.Errorf("%s: ssh-agent: %w", o.org.ID, err)
		}
		cleanup = func() { ac.Close() }
		signers = agent.NewClient(ac).Signers
	}
	auth := ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		ss, err := signers()
		if err != nil {
			return nil, err
		}
		return restrictSigners(ss, t.legacy), nil
	})
	hostAlgos, err := o.known.algorithms(t.hostport(), t.legacy)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	cfg := &ssh.ClientConfig{
		User:              t.user,
		Auth:              []ssh.AuthMethod{auth},
		HostKeyCallback:   o.known.callback(t.hostport()),
		HostKeyAlgorithms: hostAlgos,
		Timeout:           ConnectTimeout,
	}
	cfg.KeyExchanges = kexAlgorithms(t.legacy)
	cfg.Ciphers = ssh.SupportedAlgorithms().Ciphers
	cfg.MACs = ssh.SupportedAlgorithms().MACs
	return cfg, cleanup, nil
}

// keepalive is ServerAliveInterval/ServerAliveCountMax: a connection that misses KeepaliveCountMax replies in a row
// is closed, so commands on it fail instead of hanging on a dead network path.
func keepalive(c *ssh.Client, done <-chan struct{}, every time.Duration, maxMisses int) {
	t := time.NewTicker(every)
	defer t.Stop()
	misses := 0
	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		res := make(chan error, 1)
		go func() {
			_, _, err := c.SendRequest("keepalive@openssh.com", true, nil) // any reply, even a refusal, is alive
			res <- err
		}()
		select {
		case <-done:
			return
		case err := <-res:
			if err != nil {
				c.Close()
				return
			}
			misses = 0
		case <-time.After(every):
			if misses++; misses >= maxMisses {
				c.Close()
				return
			}
		}
	}
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func intOr(m map[string]any, k string, def int) int {
	switch v := m[k].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return def
}
