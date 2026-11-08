package onboard

import (
	"bufio"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// SSHHost: a Host block of ~/.ssh/config without wildcards.
type SSHHost struct {
	Alias    string `json:"alias"`
	HostName string `json:"hostname,omitempty"`
	User     string `json:"user,omitempty"`
	Port     int    `json:"port,omitempty"`
	Jump     string `json:"jump,omitempty"`     // ProxyJump
	Identity string `json:"identity,omitempty"` // IdentityFile
}

// Found: what this machine already knows about SSH, to fill the setup form.
type Found struct {
	User      string    `json:"user"`       // the local login, the usual guess for the remote one
	Keys      []string  `json:"keys"`       // private keys in ~/.ssh
	AgentKeys int       `json:"agent_keys"` // keys loaded in the ssh-agent
	Hosts     []SSHHost `json:"hosts"`      // from ~/.ssh/config
}

// ParseSSHConfig: Host blocks with a concrete alias (no * or ?); Match blocks and Include are skipped. Keywords are
// case-insensitive, values may be quoted, `Key=value` works too.
func ParseSSHConfig(text string) []SSHHost {
	var out []SSHHost
	var cur []int // the blocks the next keywords apply to
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, " ")
		if k, v, eq := strings.Cut(line, "="); eq && (!ok || len(k) < len(key)) {
			key, val, ok = k, v, true
		}
		if !ok {
			continue
		}
		key, val = strings.ToLower(strings.TrimSpace(key)), strings.Trim(strings.TrimSpace(val), `"`)
		switch key {
		case "host":
			cur = nil
			for _, a := range strings.Fields(val) {
				if !strings.ContainsAny(a, "*?!") {
					out = append(out, SSHHost{Alias: a})
					cur = append(cur, len(out)-1)
				}
			}
		case "match":
			cur = nil
		default:
			for _, i := range cur {
				h := &out[i]
				switch key {
				case "hostname":
					h.HostName = val
				case "user":
					h.User = val
				case "port":
					h.Port, _ = strconv.Atoi(val)
				case "proxyjump":
					if val != "none" {
						h.Jump = val
					}
				case "identityfile":
					if h.Identity == "" {
						h.Identity = val
					}
				}
			}
		}
	}
	return out
}

// homeDir: the user's home; tests replace it.
var homeDir = os.UserHomeDir

// agentKeys: how many keys the ssh-agent holds; set by the caller (sshx), tests replace it.
var agentKeys = func() int { return 0 }

// SetAgentKeys: how Discover counts the agent's keys (sshx.AgentKeys underneath, set by the server).
func SetAgentKeys(f func() int) { agentKeys = f }

// Discover: the local SSH setup, read-only: ~/.ssh/config hosts, private keys in ~/.ssh, keys in the agent.
func Discover() Found {
	f := Found{Keys: []string{}, Hosts: []SSHHost{}}
	if u := os.Getenv("USER"); u != "" { // what a shell shows; Windows and odd setups fall back to the account
		f.User = u
	} else if u, err := user.Current(); err == nil {
		f.User = u.Username
		if i := strings.LastIndexAny(f.User, `\`); i >= 0 { // DOMAIN\user on Windows
			f.User = f.User[i+1:]
		}
	}
	home, err := homeDir()
	if err != nil {
		return f
	}
	dir := filepath.Join(home, ".ssh")
	if b, err := os.ReadFile(filepath.Join(dir, "config")); err == nil {
		f.Hosts = ParseSSHConfig(string(b))
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, "id_") && !strings.HasSuffix(n, ".pub") && !e.IsDir() {
			if b, err := os.ReadFile(filepath.Join(dir, n)); err == nil && strings.Contains(string(b), "PRIVATE KEY") {
				f.Keys = append(f.Keys, "~/.ssh/"+n)
			}
		}
	}
	slices.Sort(f.Keys)
	f.AgentKeys = agentKeys()
	return f
}
