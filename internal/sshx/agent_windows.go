//go:build windows

package sshx

import (
	"net"
	"os"
	"strings"

	"github.com/Microsoft/go-winio"
)

// The Windows OpenSSH agent (service "ssh-agent", "OpenSSH Authentication Agent") listens on this pipe.
const openSSHPipe = `\\.\pipe\openssh-ssh-agent`

const agentHint = `the OpenSSH Authentication Agent service, or SSH_AUTH_SOCK`

// agentPath: SSH_AUTH_SOCK when set (a pipe or a unix socket), else the OpenSSH agent's pipe; "" when it isn't there.
func agentPath() string {
	p := os.Getenv("SSH_AUTH_SOCK")
	if p == "" {
		p = openSSHPipe
	}
	if _, err := os.Stat(p); err != nil && !isPipe(p) {
		return ""
	}
	return p
}

func isPipe(p string) bool { return strings.HasPrefix(p, `\\.\pipe\`) && pipeExists(p) }

func pipeExists(p string) bool {
	c, err := winio.DialPipe(p, nil)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func dialAgent(p string) (net.Conn, error) {
	if strings.HasPrefix(p, `\\.\pipe\`) {
		return winio.DialPipe(p, nil)
	}
	return net.Dial("unix", p)
}
