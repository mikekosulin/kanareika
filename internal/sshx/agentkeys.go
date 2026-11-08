package sshx

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AgentKey: a key the ssh-agent holds.
type AgentKey struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"` // SHA256:...
	Comment     string `json:"comment,omitempty"`
}

// AgentKeys: the keys in the ssh-agent (none when there is no agent).
func AgentKeys() ([]AgentKey, error) {
	p := agentPath()
	if p == "" {
		return nil, nil
	}
	c, err := dialAgent(p)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	keys, err := agent.NewClient(c).List()
	if err != nil {
		return nil, err
	}
	out := make([]AgentKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, AgentKey{Type: k.Format, Fingerprint: ssh.FingerprintSHA256(k), Comment: k.Comment})
	}
	return out, nil
}
