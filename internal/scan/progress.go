package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Heartbeat keeps status.json fresh so a killed scan shows up as stale on the dashboard.
var Heartbeat = 5 * time.Second

type hostStatus struct {
	State  string  `json:"state"` // pending | running | ok | warn | failed | skipped
	Module *string `json:"module"`
	Last   string  `json:"last"`
	Errors int     `json:"errors"`
}

// Progress: live state of a running scan in <run>/status.json + run.log, read by the dashboard.
type Progress struct {
	mu   sync.Mutex
	path string
	logf *os.File
	tail []string
	data map[string]any
	// typed parts of data, kept in sync on write
	hosts      map[string]*hostStatus
	orgModules map[string]string
	stop       chan struct{}
	done       chan struct{}
}

func now() string { return time.Now().UTC().Format("2006-01-02T15:04:05+00:00") }

func NewProgress(runDir, org, env, runID string, hosts, orgModules []string) (*Progress, error) {
	f, err := os.OpenFile(filepath.Join(runDir, "run.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	p := &Progress{path: filepath.Join(runDir, "status.json"), logf: f, hosts: map[string]*hostStatus{},
		orgModules: map[string]string{}, stop: make(chan struct{}), done: make(chan struct{})}
	for _, h := range hosts {
		p.hosts[h] = &hostStatus{State: "pending"}
	}
	for _, m := range orgModules {
		p.orgModules[m] = "pending"
	}
	p.data = map[string]any{"state": "running", "org": org, "env": env, "run_id": runID, "started": now(),
		"pid": os.Getpid()}
	p.mu.Lock()
	p.write()
	p.mu.Unlock()
	go p.heartbeat()
	return p, nil
}

func (p *Progress) heartbeat() {
	defer close(p.done)
	t := time.NewTicker(Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.mu.Lock()
			p.write()
			p.mu.Unlock()
		}
	}
}

// write: callers hold mu. Written via a temp file + rename so the dashboard never reads half a file.
func (p *Progress) write() {
	p.data["updated"] = now()
	tail := p.tail
	if len(tail) > 60 {
		tail = tail[len(tail)-60:]
	}
	p.data["log_tail"] = append([]string{}, tail...)
	p.data["hosts"] = p.hosts
	p.data["org_modules"] = p.orgModules
	b, err := json.Marshal(p.data)
	if err != nil {
		return
	}
	tmp := strings.TrimSuffix(p.path, ".json") + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, p.path)
	}
}

// Line: one log line ("[HH:MM:SS] host: text"); the host's last message is updated.
func (p *Progress) Line(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tail = append(p.tail, msg)
	if len(p.tail) > 200 {
		p.tail = p.tail[len(p.tail)-200:]
	}
	_, _ = p.logf.WriteString(msg + "\n")
	rest := msg
	if i := strings.Index(msg, "] "); i >= 0 {
		rest = msg[i+2:]
	}
	host, _, _ := strings.Cut(rest, ":")
	if h, ok := p.hosts[host]; ok {
		last := rest[len(host):]
		if i := strings.Index(msg, host+": "); i >= 0 {
			last = msg[i+len(host)+2:]
		}
		if r := []rune(last); len(r) > 200 {
			last = string(r[:200])
		}
		h.Last = last
	}
}

// HostUpdate: state/module/errors of one host; nil leaves a field unchanged ("" module = none).
type HostUpdate struct {
	State  string
	Module *string
	Errors *int
}

func (p *Progress) Host(name string, u HostUpdate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.hosts[name]
	if h == nil {
		return
	}
	if u.State != "" {
		h.State = u.State
	}
	if u.Module != nil {
		if *u.Module == "" {
			h.Module = nil
		} else {
			m := *u.Module
			h.Module = &m
		}
	}
	if u.Errors != nil {
		h.Errors = *u.Errors
	}
	p.write()
}

func (p *Progress) OrgModule(name, state string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.orgModules[name] = state
	p.write()
}

// Finish: final state (done | failed | interrupted) plus extra fields (counts, error).
func (p *Progress) Finish(state string, extra map[string]any) {
	close(p.stop)
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	p.data["state"] = state
	p.data["finished"] = now()
	for k, v := range extra {
		p.data[k] = v
	}
	for _, h := range p.hosts {
		if h.State == "pending" || h.State == "running" {
			h.State = "skipped"
		}
		h.Module = nil
	}
	p.write()
	_ = p.logf.Close()
}

func ptr[T any](v T) *T { return &v }
