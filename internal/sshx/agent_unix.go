//go:build !windows

package sshx

import (
	"net"
	"os"
)

const agentHint = "SSH_AUTH_SOCK"

// agentPath: the ssh-agent's socket, "" when there is none.
func agentPath() string {
	p := os.Getenv("SSH_AUTH_SOCK")
	if st, err := os.Stat(p); p == "" || err != nil || st.Mode()&os.ModeSocket == 0 {
		return ""
	}
	return p
}

func dialAgent(p string) (net.Conn, error) { return net.Dial("unix", p) }
