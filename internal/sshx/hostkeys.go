package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyError: the host key was not accepted. The message carries OpenSSH's wording, which scan code matches on
// ("REMOTE HOST IDENTIFICATION HAS CHANGED" / "Host key verification failed").
type HostKeyError struct {
	Host    string // address as recorded in known_hosts: addr or [addr]:port
	Changed bool   // a different key of the same type is known (reinstall or man-in-the-middle)
	msg     string
}

func (e *HostKeyError) Error() string { return e.msg }

// knownHosts: the learned file (reports/<org>/known_hosts, appended to) plus the pinned one (read-only).
// The files are re-read on every check, so keys learned by one connection are seen by the next, and the lock
// keeps two parallel first connections from appending the same host twice.
type knownHosts struct {
	learned string
	files   []string
	strict  bool // host_key_checking: strict = only keys already known
	mu      sync.Mutex
}

// probeKey never matches anything: checking it returns every key known for a host.
var probeKey = func() ssh.PublicKey {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return k
}()

// fixedAddr: knownhosts wants a remote address; through a jump it is meaningless, so the configured one is used
// (OpenSSH records hosts behind ProxyJump under their HostName too; CheckHostIP is off by default).
type fixedAddr string

func (a fixedAddr) Network() string { return "tcp" }
func (a fixedAddr) String() string  { return string(a) }

// lookup: keys known for hostport in all files.
func (k *knownHosts) lookup(hostport string) ([]knownhosts.KnownKey, error) {
	cb, err := knownhosts.New(k.files...)
	if err != nil {
		return nil, err
	}
	var ke *knownhosts.KeyError
	if err := cb(hostport, fixedAddr(hostport), probeKey); errors.As(err, &ke) {
		return ke.Want, nil
	} else if err != nil {
		return nil, err
	}
	return nil, nil
}

func (k *knownHosts) callback(hostport string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		k.mu.Lock()
		defer k.mu.Unlock()
		name := knownhosts.Normalize(hostport)
		fp := ssh.FingerprintSHA256(key)
		cb, err := knownhosts.New(k.files...)
		if err != nil {
			return err
		}
		err = cb(hostport, fixedAddr(hostport), key)
		var ke *knownhosts.KeyError
		var re *knownhosts.RevokedError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &re):
			return &HostKeyError{Host: name, msg: fmt.Sprintf("%s key %s for %s is revoked (%s:%d). "+
				"Host key verification failed.", key.Type(), fp, name, re.Revoked.Filename, re.Revoked.Line)}
		case !errors.As(err, &ke):
			return err
		}
		// only a known key of the same type counts as "changed"; another type is a new key, as in OpenSSH
		for _, w := range ke.Want {
			if w.Key.Type() == key.Type() {
				return &HostKeyError{Host: name, Changed: true, msg: fmt.Sprintf("WARNING: REMOTE HOST "+
					"IDENTIFICATION HAS CHANGED! %s key for %s is now %s, known %s in %s:%d. "+
					"Host key verification failed.", key.Type(), name, fp, ssh.FingerprintSHA256(w.Key),
					w.Filename, w.Line)}
			}
		}
		if k.strict {
			return &HostKeyError{Host: name, msg: fmt.Sprintf("no %s host key known for %s (%s) and "+
				"host_key_checking is strict. Host key verification failed.", key.Type(), name, fp)}
		}
		f, err := os.OpenFile(k.learned, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = fmt.Fprintln(f, knownhosts.Line([]string{name}, key))
		return err
	}
}

// algorithms: host key algorithms for a target. Types already known for the host go first (as OpenSSH orders
// them), so a server with several keys presents the one we can verify instead of looking like a new host.
// Modern defaults exclude ssh-rsa (SHA-1) and ssh-dss; legacy_ssh adds ssh-rsa for that host only.
func (k *knownHosts) algorithms(hostport string, legacy bool) ([]string, error) {
	base := slices.Clone(modernHostKeys)
	if legacy {
		base = append(base, ssh.KeyAlgoRSA)
	}
	k.mu.Lock()
	known, err := k.lookup(hostport)
	k.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var first []string
	for _, w := range known {
		for _, a := range algosFor(w.Key.Type()) {
			if slices.Contains(base, a) && !slices.Contains(first, a) {
				first = append(first, a)
			}
		}
	}
	out := first
	for _, a := range base {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out, nil
}

// modernHostKeys: OpenSSH's default order (ed25519, ECDSA, RSA with SHA-2). x/crypto's own default puts RSA first
// and still includes ssh-rsa and ssh-dss. Certificates are not offered: org files pin plain keys only.
var modernHostKeys = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}

func algosFor(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

// kexAlgorithms: x/crypto's default list still includes diffie-hellman-group14-sha1, so normal hosts get the
// secure set explicitly (as OpenSSH 8.x+ defaults). Legacy hosts (OpenSSH 5.3) also accept the SHA-1 exchanges.
func kexAlgorithms(legacy bool) []string {
	out := slices.Clone(ssh.SupportedAlgorithms().KeyExchanges)
	if legacy {
		out = append(out, ssh.InsecureKeyExchangeDH14SHA1, ssh.InsecureKeyExchangeDHGEXSHA1)
	}
	return out
}

// restrictSigners is PubkeyAcceptedAlgorithms: RSA keys sign with rsa-sha2-* only, plus ssh-rsa (SHA-1) on legacy
// hosts, whose sshd predates server-sig-algs and accepts nothing else.
func restrictSigners(ss []ssh.Signer, legacy bool) []ssh.Signer {
	algos := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	if legacy {
		algos = append(algos, ssh.KeyAlgoRSA)
	}
	out := make([]ssh.Signer, 0, len(ss))
	for _, s := range ss {
		if s.PublicKey().Type() != ssh.KeyAlgoRSA {
			out = append(out, s)
			continue
		}
		// an RSA signer that cannot choose its algorithm would sign ssh-rsa: not offered
		if as, ok := s.(ssh.AlgorithmSigner); !ok {
			continue
		} else if m, err := ssh.NewSignerWithAlgorithms(as, algos); err == nil {
			out = append(out, m)
		}
	}
	return out
}
