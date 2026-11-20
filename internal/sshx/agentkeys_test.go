package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestAgentKeys: the keys an agent holds come back with their type, SHA256 fingerprint and comment; no agent is no
// keys and no error.
func TestAgentKeys(t *testing.T) {
	if runtime.GOOS != "windows" { // there, no SSH_AUTH_SOCK still means the OpenSSH agent's pipe
		t.Setenv("SSH_AUTH_SOCK", "")
		if keys, err := AgentKeys(); keys != nil || err != nil {
			t.Fatal("no agent:", keys, err)
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	pub, err := ssh.NewPublicKey(priv.Public())
	must(t, err)
	kr := agent.NewKeyring()
	must(t, kr.Add(agent.AddedKey{PrivateKey: priv, Comment: "alice@example.com"}))
	t.Setenv("SSH_AUTH_SOCK", serveAgent(t, kr))
	keys, err := AgentKeys()
	if err != nil || len(keys) != 1 ||
		keys[0] != (AgentKey{Type: ssh.KeyAlgoED25519, Fingerprint: ssh.FingerprintSHA256(pub), Comment: "alice@example.com"}) {
		t.Fatalf("%+v %v", keys, err)
	}
	if !strings.HasPrefix(keys[0].Fingerprint, "SHA256:") {
		t.Fatal(keys[0].Fingerprint)
	}
	t.Setenv("SSH_AUTH_SOCK", serveAgent(t, agent.NewKeyring()))
	if keys, err := AgentKeys(); err != nil || keys == nil || len(keys) != 0 { // an empty list, not null
		t.Fatalf("an agent without keys: %#v %v", keys, err)
	}
}

// TestAgentKeysErrors: an agent that can't list its keys, and a socket nobody listens on any more, are errors.
func TestAgentKeysErrors(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", serveAgent(t, brokenAgent{agent.NewKeyring()}))
	if keys, err := AgentKeys(); err == nil || keys != nil {
		t.Fatal("listing fails:", keys, err)
	}
	dir, err := os.MkdirTemp("", "kna") // short: unix socket paths are limited to ~100 bytes on macOS
	must(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "gone.sock")
	ln, err := net.Listen("unix", sock)
	must(t, err)
	ln.(*net.UnixListener).SetUnlinkOnClose(false) // the socket file stays, nobody answers
	must(t, ln.Close())
	t.Setenv("SSH_AUTH_SOCK", sock)
	if keys, err := AgentKeys(); err == nil || keys != nil {
		t.Fatal("dead socket:", keys, err)
	}
}
