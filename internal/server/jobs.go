package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mikekosulin/kanareika/internal/config"
)

// ScanRequest: what the dashboard asks to scan (the same choices as `kanareika scan`).
type ScanRequest struct {
	Org          string   `json:"org"`
	Env          string   `json:"env"`
	Hosts        []string `json:"hosts,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	Modules      []string `json:"modules,omitempty"`
	DryRun       bool     `json:"dry_run,omitempty"`
	IgnoreWindow bool     `json:"ignore_window,omitempty"`
	Offline      bool     `json:"offline,omitempty"`
}

// ScanFunc runs one scan of org/env (scan.Scanner.Org underneath) writing its plan, log and summary to out, and
// returns its exit code; cancelling ctx interrupts it. Passed in by the CLI, so this package stays free of SSH.
type ScanFunc func(ctx context.Context, o *config.Org, req ScanRequest, out io.Writer) int

// Job states.
const (
	JobRunning   = "running"
	JobDone      = "done"      // exit code 0
	JobFailed    = "failed"    // non-zero exit code: refused, hosts failed, ...
	JobCancelled = "cancelled" // stopped from the dashboard or by the server shutting down
)

// maxJobs kept in memory (finished ones beyond that are forgotten, oldest first); maxLines of output per job.
const (
	maxJobs  = 20
	maxLines = 400
)

type job struct {
	ID       string      `json:"id"`
	Request  ScanRequest `json:"request"`
	State    string      `json:"state"`
	Code     int         `json:"code"`
	Started  time.Time   `json:"started"`
	Finished *time.Time  `json:"finished"`
	Output   []string    `json:"output"`  // the last maxLines lines
	Dropped  int         `json:"dropped"` // lines before those

	cancel    context.CancelFunc
	cancelled bool
	done      chan struct{}
	partial   []byte // an unfinished last line
}

// jobs: the scans started from this dashboard. One per org/env at a time (the env lock in reports/ also keeps
// a CLI scan of the same env out).
type jobs struct {
	mu   sync.Mutex
	scan ScanFunc
	// before: what a scan waits for first (a DB update started from the page: two trivy downloads at once break
	// each other); nil: nothing
	before func(ctx context.Context, out io.Writer)
	list   []*job
	wg     sync.WaitGroup
	now    func() time.Time
}

// write: a job's output; complete lines are kept, the last maxLines of them.
func (js *jobs) writer(j *job) io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		js.mu.Lock()
		defer js.mu.Unlock()
		data := append(slices.Clip(j.partial), p...)
		lines := strings.Split(string(data), "\n")
		j.partial = []byte(lines[len(lines)-1])
		for _, l := range lines[:len(lines)-1] {
			j.Output = append(j.Output, strings.TrimRight(l, "\r"))
		}
		if over := len(j.Output) - maxLines; over > 0 {
			j.Output = slices.Clone(j.Output[over:])
			j.Dropped += over
		}
		return len(p), nil
	})
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// errBusy: a scan of that org/env is already running here.
var errBusy = errors.New("a scan of this org/env is already running")

func (js *jobs) start(o *config.Org, req ScanRequest) (*job, error) {
	js.mu.Lock()
	defer js.mu.Unlock()
	for _, j := range js.list {
		if j.State == JobRunning && j.Request.Org == req.Org && j.Request.Env == req.Env {
			return nil, errBusy
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{ID: newID(), Request: req, State: JobRunning, Started: js.now().UTC(), Output: []string{},
		cancel: cancel, done: make(chan struct{})}
	js.list = append(js.list, j)
	js.trim()
	js.wg.Add(1)
	go func() {
		defer js.wg.Done()
		defer close(j.done)
		defer cancel()
		code := js.run(ctx, o, req, j)
		js.mu.Lock()
		defer js.mu.Unlock()
		if len(j.partial) > 0 {
			j.Output = append(j.Output, string(j.partial))
			j.partial = nil
		}
		fin := js.now().UTC()
		j.Finished, j.Code = &fin, code
		switch {
		case j.cancelled:
			j.State = JobCancelled
		case code == 0:
			j.State = JobDone
		default:
			j.State = JobFailed
		}
	}()
	return j, nil
}

// run: the scan, with a panic turned into a failed job instead of a dead dashboard.
func (js *jobs) run(ctx context.Context, o *config.Org, req ScanRequest, j *job) (code int) {
	out := js.writer(j)
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(out, "\n! internal error: %v\n", r)
			code = 70
		}
	}()
	if js.before != nil {
		js.before(ctx, out)
		if ctx.Err() != nil {
			return 130
		}
	}
	return js.scan(ctx, o, req, out)
}

// trim forgets the oldest finished jobs beyond maxJobs (running ones always stay).
func (js *jobs) trim() {
	for len(js.list) > maxJobs {
		i := slices.IndexFunc(js.list, func(j *job) bool { return j.State != JobRunning })
		if i < 0 {
			return
		}
		js.list = slices.Delete(js.list, i, i+1)
	}
}

func (js *jobs) cancel(id string) bool {
	js.mu.Lock()
	defer js.mu.Unlock()
	for _, j := range js.list {
		if j.ID == id {
			if j.State == JobRunning {
				j.cancelled = true
				j.cancel()
			}
			return true
		}
	}
	return false
}

// snapshot: copies of the jobs, newest first.
func (js *jobs) snapshot() []job {
	js.mu.Lock()
	defer js.mu.Unlock()
	out := make([]job, 0, len(js.list))
	for _, j := range js.list {
		c := *j
		c.Output = slices.Clone(j.Output)
		out = append(out, c)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Started.After(out[b].Started) })
	return out
}

// stop cancels every running job and waits for them to finish (they mark their runs interrupted).
func (js *jobs) stop() {
	js.mu.Lock()
	for _, j := range js.list {
		if j.State == JobRunning {
			j.cancelled = true
			j.cancel()
		}
	}
	js.mu.Unlock()
	js.wg.Wait()
}

// --- API ----------------------------------------------------------------------------------------------------------

// validate a request against the org config: the same rules as `kanareika scan`.
func validate(st *orgState, req *ScanRequest) (*config.Org, error) {
	if len(st.errors) > 0 {
		return nil, errors.New("config errors block scans: fix them first (kanareika validate)")
	}
	o := st.byID[req.Org]
	if o == nil {
		return nil, fmt.Errorf("unknown org %q", req.Org)
	}
	if !slices.Contains(o.Envs(), req.Env) {
		return nil, fmt.Errorf("unknown env %q of %s", req.Env, req.Org)
	}
	hosts, groups := map[string]bool{}, map[string]bool{}
	for _, h := range o.Hosts {
		if h.Env == req.Env {
			hosts[h.Name], groups[h.Group] = true, true
		}
	}
	for _, h := range req.Hosts {
		if !hosts[h] {
			return nil, fmt.Errorf("unknown host %q in %s/%s", h, req.Org, req.Env)
		}
	}
	for _, g := range req.Groups {
		if !groups[g] {
			return nil, fmt.Errorf("unknown group %q in %s/%s", g, req.Org, req.Env)
		}
	}
	for _, m := range req.Modules {
		if !slices.Contains(config.Modules, m) {
			return nil, fmt.Errorf("unknown module %q", m)
		}
	}
	return o, nil
}

func sendJSON(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	send(w, code, "application/json; charset=utf-8", b)
}

func sendErr(w http.ResponseWriter, code int, msg string) {
	sendJSON(w, code, map[string]string{"error": msg})
}

// apiScan: POST /api/scan {org, env, hosts, groups, modules, dry_run, ignore_window, offline} -> 202 {job}.
func (s *Server) apiScan(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil {
		sendErr(w, http.StatusForbidden, "scans are disabled on this dashboard")
		return
	}
	var req ScanRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		sendErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	s.reload()
	o, err := validate(s.state.Load(), &req)
	if err != nil {
		sendErr(w, http.StatusBadRequest, err.Error())
		return
	}
	j, err := s.jobs.start(o, req)
	if errors.Is(err, errBusy) {
		sendErr(w, http.StatusConflict, err.Error())
		return
	}
	s.log.Printf("dashboard: scan %s/%s started (job %s)", req.Org, req.Env, j.ID)
	sendJSON(w, http.StatusAccepted, map[string]any{"id": j.ID})
}

// apiJobs: GET /api/jobs -> {enabled, modules, jobs: newest first}.
func (s *Server) apiJobs(w http.ResponseWriter, _ *http.Request) {
	list := []job{}
	if s.jobs != nil {
		list = s.jobs.snapshot()
	}
	sendJSON(w, http.StatusOK, map[string]any{"enabled": s.jobs != nil, "modules": config.Modules, "jobs": list})
}

// apiCancel: POST /api/jobs/{id}/cancel -> 202.
func (s *Server) apiCancel(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil || !s.jobs.cancel(chi.URLParam(r, "id")) {
		sendErr(w, http.StatusNotFound, "no such job")
		return
	}
	sendJSON(w, http.StatusAccepted, map[string]string{"state": "cancelling"})
}

// apiScanOptions: GET /api/scan-options?org=&env= -> the hosts and groups a scan of org/env can be narrowed to.
func (s *Server) apiScanOptions(q query) (any, error) {
	o, env, err := s.orgEnv(q)
	if err != nil {
		return nil, err
	}
	hosts, groups := []string{}, []string{}
	for _, h := range o.Hosts {
		if h.Env != env {
			continue
		}
		hosts = append(hosts, h.Name)
		if !slices.Contains(groups, h.Group) {
			groups = append(groups, h.Group)
		}
	}
	return map[string]any{"hosts": hosts, "groups": groups, "modules": config.Modules}, nil
}

// apiSession: GET /api/session -> {csrf, scans} for API clients other than the page (kanareika tui). Same-origin
// only, like the page that carries the same token: other sites can't read it (no CORS, Host checked on localhost,
// the access token when set).
func (s *Server) apiSession(w http.ResponseWriter, _ *http.Request) {
	sendJSON(w, http.StatusOK, map[string]any{"csrf": s.csrf, "scans": s.jobs != nil})
}
