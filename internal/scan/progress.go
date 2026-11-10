package scan

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
)

// Heartbeat keeps status.json fresh so a killed scan shows up as stale on the dashboard.
var Heartbeat = 5 * time.Second

type hostStatus struct {
	State  string  `json:"state"` // pending | running | ok | warn | failed | skipped
	Module *string `json:"module"`
	Last   string  `json:"last"`
	Errors int     `json:"errors"`
	Step   int     `json:"step,omitempty"`  // modules started on the host so far
	Steps  int     `json:"steps,omitempty"` // modules planned for it
	// Seconds: how long the host took, once done; the next scan starts its longest hosts first
	Seconds float64 `json:"seconds,omitempty"`
	start   time.Time
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
	State       string
	Module      *string
	Errors      *int
	Step, Steps int // 0: unchanged
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
		switch {
		case u.State == "running" && h.start.IsZero():
			h.start = time.Now()
		case u.State != "running" && !h.start.IsZero() && h.Seconds == 0:
			h.Seconds = math.Round(time.Since(h.start).Seconds()*10) / 10
		}
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
	if u.Step > 0 {
		h.Step = u.Step
	}
	if u.Steps > 0 {
		h.Steps = u.Steps
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
		} else if h.Steps > 0 {
			h.Step = h.Steps
		}
		h.Module = nil
	}
	p.write()
	_ = p.logf.Close()
}

func ptr[T any](v T) *T { return &v }

// hostSeconds: how long each host took in the latest runs of envDir that timed it (newest first, five runs with a
// status.json looked at at most); hosts never timed are absent.
func hostSeconds(envDir string) map[string]float64 {
	out := map[string]float64{}
	ents, _ := os.ReadDir(envDir) // sorted by name: run IDs are timestamps
	seen := 0
	for i := len(ents) - 1; i >= 0 && seen < 5; i-- {
		b, err := os.ReadFile(filepath.Join(envDir, ents[i].Name(), "status.json"))
		if err != nil {
			continue
		}
		seen++
		var st struct {
			Hosts map[string]struct {
				Seconds float64 `json:"seconds"`
			} `json:"hosts"`
		}
		if json.Unmarshal(b, &st) != nil {
			continue
		}
		for h, v := range st.Hosts {
			if _, ok := out[h]; !ok && v.Seconds > 0 {
				out[h] = v.Seconds
			}
		}
	}
	return out
}

// longestFirst: hosts in the order to start them, so the slowest do not start last and set the wall clock alone:
// hosts never timed first (in the given order), then by the time they took before, longest first.
func longestFirst(hosts []config.Host, secs map[string]float64) []config.Host {
	out := slices.Clone(hosts)
	slices.SortStableFunc(out, func(a, b config.Host) int {
		sa, oka := secs[a.Name]
		sb, okb := secs[b.Name]
		switch {
		case oka != okb:
			if !oka {
				return -1
			}
			return 1
		case sa > sb:
			return -1
		case sa < sb:
			return 1
		}
		return 0
	})
	return out
}
