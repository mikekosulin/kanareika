package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
)

// testHome: org acme (production: web-01, web-02, app-01, ...; staging) from the parity fixture.
func testHome(t *testing.T) config.Paths {
	t.Helper()
	home := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(home, "orgs"), 0o755))
	b, err := os.ReadFile("testdata/parity/org.yml")
	must(t, err)
	must(t, os.WriteFile(filepath.Join(home, "orgs", "acme.yml"), b, 0o644))
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(home, "no-feeds"))
	return config.PathsAt(home)
}

// fakeScan records requests; each scan prints two lines and waits for release (or cancellation).
type fakeScan struct {
	mu      sync.Mutex
	reqs    []ScanRequest
	release chan struct{}
	code    int
	panics  bool
}

func (f *fakeScan) run(ctx context.Context, o *config.Org, req ScanRequest, out io.Writer) int {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	panics := f.panics
	f.mu.Unlock()
	if panics {
		panic("boom")
	}
	fmt.Fprintf(out, "== %s / %s\n  plan", o.ID, req.Env)
	fmt.Fprint(out, "ned\n")
	select {
	case <-ctx.Done():
		fmt.Fprint(out, "interrupted") // no newline: kept at the end
		return 130
	case <-f.release:
		return f.code
	}
}

// requests: a copy of what was asked so far.
func (f *fakeScan) requests() []ScanRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ScanRequest(nil), f.reqs...)
}

func newTest(t *testing.T, opts Options) (*Server, http.Handler) {
	t.Helper()
	if opts.Paths.Home == "" {
		opts.Paths = testHome(t)
	}
	opts.Log = log.New(io.Discard, "", 0)
	s, err := New(opts)
	must(t, err)
	return s, s.Handler()
}

type resp struct {
	code int
	body string
	h    http.Header
}

func do(h http.Handler, method, path string, body any, hdr map[string]string) resp {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return resp{rec.Code, rec.Body.String(), rec.Header()}
}

func (s *Server) postHdr() map[string]string {
	return map[string]string{"Content-Type": "application/json", "X-Kanareika-CSRF": s.csrf}
}

func jobsOf(t *testing.T, h http.Handler) (bool, []job) {
	t.Helper()
	r := do(h, "GET", "/api/jobs", nil, nil)
	var d struct {
		Enabled bool  `json:"enabled"`
		Jobs    []job `json:"jobs"`
	}
	must(t, json.Unmarshal([]byte(r.body), &d))
	return d.Enabled, d.Jobs
}

func waitState(t *testing.T, h http.Handler, id, state string) job {
	t.Helper()
	for i := 0; i < 200; i++ {
		_, list := jobsOf(t, h)
		for _, j := range list {
			if j.ID == id && j.State == state {
				return j
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s never got %s", id, state)
	return job{}
}

func TestScanFromDashboard(t *testing.T) {
	f := &fakeScan{release: make(chan struct{})}
	s, h := newTest(t, Options{Scan: f.run})
	if !strings.Contains(string(s.page), `csrf: "`+s.csrf+`"`) || len(s.csrf) != 32 {
		t.Fatal("CSRF token not in the page")
	}
	req := ScanRequest{Org: "acme", Env: "production", Hosts: []string{"web-01"}, Modules: []string{"os_packages"},
		DryRun: true, Offline: true}

	// the CSRF defences
	for name, hdr := range map[string]map[string]string{
		"no token":     {"Content-Type": "application/json"},
		"wrong token":  {"Content-Type": "application/json", "X-Kanareika-CSRF": "x"},
		"form post":    {"Content-Type": "application/x-www-form-urlencoded", "X-Kanareika-CSRF": s.csrf},
		"other origin": {"Content-Type": "application/json", "X-Kanareika-CSRF": s.csrf, "Origin": "https://evil.example"},
		"bad origin":   {"Content-Type": "application/json", "X-Kanareika-CSRF": s.csrf, "Origin": "%%"},
	} {
		if r := do(h, "POST", "/api/scan", req, hdr); r.code != 403 {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
	}
	if len(f.requests()) != 0 {
		t.Fatal("a refused request started a scan")
	}

	hdr := s.postHdr()
	hdr["Origin"] = "http://example.com" // httptest's Host: the page's own origin
	r := do(h, "POST", "/api/scan", req, hdr)
	if r.code != 202 {
		t.Fatal(r.code, r.body)
	}
	var started struct{ ID string }
	must(t, json.Unmarshal([]byte(r.body), &started))
	waitState(t, h, started.ID, JobRunning)
	if r := do(h, "POST", "/api/scan", req, s.postHdr()); r.code != 409 {
		t.Fatal("second scan of the same env:", r.code)
	}
	// another env runs alongside
	r = do(h, "POST", "/api/scan", ScanRequest{Org: "acme", Env: "staging"}, s.postHdr())
	if r.code != 202 {
		t.Fatal(r.code, r.body)
	}
	close(f.release)
	j := waitState(t, h, started.ID, JobDone)
	if j.Code != 0 || j.Finished == nil || strings.Join(j.Output, "|") != "== acme / production|  planned" {
		t.Fatalf("%+v", j)
	}
	if r0 := f.requests()[0]; r0.Org != "acme" || r0.Hosts[0] != "web-01" || !r0.DryRun || !r0.Offline {
		t.Fatalf("%+v", r0)
	}
	enabled, list := jobsOf(t, h)
	if !enabled || len(list) != 2 || list[0].Request.Env != "staging" { // newest first
		t.Fatal(enabled, list)
	}
}

func TestScanValidation(t *testing.T) {
	f := &fakeScan{release: make(chan struct{})}
	s, h := newTest(t, Options{Scan: f.run})
	for name, c := range map[string]struct {
		body any
		want string
	}{
		"unknown org":    {ScanRequest{Org: "nope", Env: "production"}, "unknown org"},
		"unknown env":    {ScanRequest{Org: "acme", Env: "qa"}, "unknown env"},
		"host elsewhere": {ScanRequest{Org: "acme", Env: "staging", Hosts: []string{"web-01"}}, "unknown host"},
		"unknown group":  {ScanRequest{Org: "acme", Env: "production", Groups: []string{"nope"}}, "unknown group"},
		"unknown module": {ScanRequest{Org: "acme", Env: "production", Modules: []string{"nope"}}, "unknown module"},
		"unknown field":  {map[string]any{"org": "acme", "env": "production", "rm": "-rf"}, "unknown field"},
		"not json":       {"just a string", "bad request"},
	} {
		if r := do(h, "POST", "/api/scan", c.body, s.postHdr()); r.code != 400 || !strings.Contains(r.body, c.want) {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
	}
	if r := do(h, "POST", "/api/scan", ScanRequest{Org: "acme", Env: "production", Groups: []string{"front"}}, s.postHdr()); r.code != 202 {
		t.Fatal(r.code, r.body)
	}
	close(f.release)
	// a broken org file blocks scans
	must(t, os.WriteFile(filepath.Join(s.paths.Orgs, "broken.yml"), []byte("org: ["), 0o644))
	if r := do(h, "POST", "/api/scan", ScanRequest{Org: "acme", Env: "staging"}, s.postHdr()); r.code != 400 ||
		!strings.Contains(r.body, "config errors") {
		t.Fatal(r.code, r.body)
	}
	if len(f.requests()) != 1 {
		t.Fatal(f.requests())
	}
}

func TestCancelAndStop(t *testing.T) {
	f := &fakeScan{release: make(chan struct{})}
	s, h := newTest(t, Options{Scan: f.run})
	r := do(h, "POST", "/api/scan", ScanRequest{Org: "acme", Env: "production"}, s.postHdr())
	var j struct{ ID string }
	must(t, json.Unmarshal([]byte(r.body), &j))
	waitState(t, h, j.ID, JobRunning)
	if r := do(h, "POST", "/api/jobs/nope/cancel", nil, s.postHdr()); r.code != 404 {
		t.Fatal(r.code)
	}
	if r := do(h, "POST", "/api/jobs/"+j.ID+"/cancel", nil, map[string]string{"Content-Type": "application/json"}); r.code != 403 {
		t.Fatal("cancel without CSRF:", r.code)
	}
	if r := do(h, "POST", "/api/jobs/"+j.ID+"/cancel", nil, s.postHdr()); r.code != 202 {
		t.Fatal(r.code)
	}
	got := waitState(t, h, j.ID, JobCancelled)
	if got.Code != 130 || got.Output[len(got.Output)-1] != "interrupted" {
		t.Fatalf("%+v", got)
	}
	if r := do(h, "POST", "/api/jobs/"+j.ID+"/cancel", nil, s.postHdr()); r.code != 202 { // finished: a no-op
		t.Fatal(r.code)
	}

	// failed and panicking scans
	f2 := &fakeScan{release: make(chan struct{}), code: 1}
	close(f2.release)
	s2, h2 := newTest(t, Options{Scan: f2.run})
	r = do(h2, "POST", "/api/scan", ScanRequest{Org: "acme", Env: "production"}, s2.postHdr())
	must(t, json.Unmarshal([]byte(r.body), &j))
	if got := waitState(t, h2, j.ID, JobFailed); got.Code != 1 {
		t.Fatal(got)
	}
	f2.mu.Lock()
	f2.panics = true
	f2.mu.Unlock()
	r = do(h2, "POST", "/api/scan", ScanRequest{Org: "acme", Env: "production"}, s2.postHdr())
	must(t, json.Unmarshal([]byte(r.body), &j))
	if got := waitState(t, h2, j.ID, JobFailed); got.Code != 70 || !strings.Contains(strings.Join(got.Output, "\n"), "internal error: boom") {
		t.Fatal(got)
	}

	// stop: running jobs are cancelled and waited for
	f3 := &fakeScan{release: make(chan struct{})}
	s3, h3 := newTest(t, Options{Scan: f3.run})
	r = do(h3, "POST", "/api/scan", ScanRequest{Org: "acme", Env: "staging"}, s3.postHdr())
	must(t, json.Unmarshal([]byte(r.body), &j))
	waitState(t, h3, j.ID, JobRunning)
	s3.jobs.stop()
	if _, list := jobsOf(t, h3); list[0].State != JobCancelled {
		t.Fatal(list[0].State)
	}
}

func TestJobLimits(t *testing.T) {
	js := &jobs{now: time.Now}
	j := &job{}
	w := js.writer(j)
	for i := 0; i < maxLines+50; i++ {
		fmt.Fprintf(w, "line %d\r\n", i)
	}
	if len(j.Output) != maxLines || j.Dropped != 50 || j.Output[0] != "line 50" {
		t.Fatal(len(j.Output), j.Dropped, j.Output[0])
	}
	// finished jobs beyond maxJobs are forgotten, oldest first; running ones stay
	js.list = []*job{{ID: "run", State: JobRunning}}
	for i := 0; i < maxJobs+5; i++ {
		js.list = append(js.list, &job{ID: fmt.Sprint(i), State: JobDone})
	}
	js.trim()
	if len(js.list) != maxJobs || js.list[0].ID != "run" || js.list[1].ID != "6" {
		t.Fatal(len(js.list), js.list[0].ID, js.list[1].ID)
	}
	js.list = make([]*job, maxJobs+1)
	for i := range js.list {
		js.list[i] = &job{State: JobRunning}
	}
	js.trim()
	if len(js.list) != maxJobs+1 {
		t.Fatal("dropped a running job")
	}
}

func TestScansDisabled(t *testing.T) {
	s, h := newTest(t, Options{})
	if r := do(h, "POST", "/api/scan", ScanRequest{Org: "acme", Env: "production"}, s.postHdr()); r.code != 403 ||
		!strings.Contains(r.body, "disabled") {
		t.Fatal(r.code, r.body)
	}
	if r := do(h, "POST", "/api/jobs/x/cancel", nil, s.postHdr()); r.code != 404 {
		t.Fatal(r.code)
	}
	if enabled, list := jobsOf(t, h); enabled || len(list) != 0 {
		t.Fatal(enabled, list)
	}
}

func TestScanOptions(t *testing.T) {
	_, h := newTest(t, Options{})
	r := do(h, "GET", "/api/scan-options?org=acme&env=production", nil, nil)
	var d struct{ Hosts, Groups, Modules []string }
	must(t, json.Unmarshal([]byte(r.body), &d))
	if r.code != 200 || len(d.Hosts) == 0 || d.Hosts[0] != "web-01" || len(d.Groups) == 0 || len(d.Modules) != len(config.Modules) {
		t.Fatal(r.code, r.body)
	}
	for _, h2 := range d.Hosts {
		if h2 == "stg-01" {
			t.Fatal("staging host in production")
		}
	}
	if r := do(h, "GET", "/api/scan-options?org=acme&env=qa", nil, nil); r.code != 404 {
		t.Fatal(r.code)
	}
}

func TestMethods(t *testing.T) {
	s, h := newTest(t, Options{})
	for _, c := range [][2]string{{"PUT", "/api/scan"}, {"POST", "/"}, {"POST", "/api/orgs"}, {"DELETE", "/api/jobs/x/cancel"},
		{"POST", "/api/jobs/x"}} {
		if r := do(h, c[0], c[1], nil, s.postHdr()); r.code != 501 {
			t.Errorf("%v: %d", c, r.code)
		}
	}
}

func TestLocalhostOnly(t *testing.T) {
	s, srv := newTest(t, Options{})
	s.local.Store(true)
	for host, want := range map[string]int{"127.0.0.1:8088": 200, "localhost:8088": 200, "LOCALHOST": 200,
		"[::1]:8088": 200, "127.1.2.3": 200, "evil.example:8088": 421, "192.0.2.1:8088": 421} {
		req := httptest.NewRequest("GET", "/api/jobs", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", host, rec.Code, want)
		}
	}
}

func TestToken(t *testing.T) {
	_, h := newTest(t, Options{Token: "s3cret"})
	if r := do(h, "GET", "/api/orgs", nil, nil); r.code != 401 {
		t.Fatal("no token:", r.code)
	}
	if r := do(h, "GET", "/?token=wrong", nil, nil); r.code != 401 {
		t.Fatal("wrong token:", r.code)
	}
	r := do(h, "GET", "/?token=s3cret", nil, nil)
	if r.code != 303 || r.h.Get("Location") != "/" || !strings.Contains(r.h.Get("Set-Cookie"), "kanareika_token=s3cret") ||
		!strings.Contains(r.h.Get("Set-Cookie"), "HttpOnly") || !strings.Contains(r.h.Get("Set-Cookie"), "SameSite=Strict") {
		t.Fatal(r.code, r.h)
	}
	if r := do(h, "GET", "/api/orgs", nil, map[string]string{"Cookie": "kanareika_token=s3cret"}); r.code != 200 {
		t.Fatal("cookie:", r.code)
	}
	if r := do(h, "GET", "/api/orgs", nil, map[string]string{"Authorization": "Bearer s3cret"}); r.code != 200 {
		t.Fatal("bearer:", r.code)
	}
	if r := do(h, "GET", "/api/orgs", nil, map[string]string{"Cookie": "kanareika_token=nope"}); r.code != 401 {
		t.Fatal("bad cookie:", r.code)
	}
}

func TestServe(t *testing.T) {
	f := &fakeScan{release: make(chan struct{})}
	s, _ := newTest(t, Options{Scan: f.run})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	done := make(chan error)
	go func() { done <- s.serve(ctx, ln, "127.0.0.1", &out) }()
	base := "http://" + ln.Addr().String()
	var r *http.Response
	for i := 0; i < 100; i++ {
		if r, err = http.Get(base + "/api/jobs"); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	must(t, err)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	// a scan is running when the server stops: it is cancelled and waited for
	body, _ := json.Marshal(ScanRequest{Org: "acme", Env: "production"})
	req, _ := http.NewRequest("POST", base+"/api/scan", bytes.NewReader(body))
	for k, v := range s.postHdr() {
		req.Header.Set(k, v)
	}
	r, err = http.DefaultClient.Do(req)
	must(t, err)
	r.Body.Close()
	if r.StatusCode != 202 {
		t.Fatal(r.StatusCode)
	}
	cancel()
	must(t, <-done)
	if list := s.jobs.snapshot(); list[0].State != JobCancelled {
		t.Fatal(list[0].State)
	}
	if !strings.Contains(out.String(), "on http://127.0.0.1:") || !strings.Contains(out.String(), "scans can be started") {
		t.Fatal(out.String())
	}

	// beyond localhost without a token: read-only, and said so
	s2, _ := newTest(t, Options{Scan: f.run})
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	ctx2, cancel2 := context.WithCancel(context.Background())
	out.Reset()
	go func() { done <- s2.serve(ctx2, ln2, "0.0.0.0", &out) }()
	time.Sleep(50 * time.Millisecond)
	cancel2()
	must(t, <-done)
	if s2.jobs != nil || !strings.Contains(out.String(), "read-only") || s2.local.Load() {
		t.Fatal(out.String())
	}
	// with a token: the printed link carries it
	s3, _ := newTest(t, Options{Scan: f.run, Token: "a b"})
	ln3, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	ctx3, cancel3 := context.WithCancel(context.Background())
	out.Reset()
	go func() { done <- s3.serve(ctx3, ln3, "192.0.2.1", &out) }()
	time.Sleep(50 * time.Millisecond)
	cancel3()
	must(t, <-done)
	if s3.jobs == nil || !strings.Contains(out.String(), "http://192.0.2.1:") || !strings.Contains(out.String(), "?token=a+b") {
		t.Fatal(out.String())
	}
	// Serve itself: a busy port is an error, returned at once
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer busy.Close()
	if err := s3.Serve(context.Background(), "127.0.0.1", busy.Addr().(*net.TCPAddr).Port, io.Discard); err == nil {
		t.Fatal("listened on a busy port")
	}
}

func TestSession(t *testing.T) {
	s, h := newTest(t, Options{Scan: (&fakeScan{}).run})
	r := do(h, "GET", "/api/session", nil, nil)
	var d struct {
		CSRF  string `json:"csrf"`
		Scans bool   `json:"scans"`
	}
	must(t, json.Unmarshal([]byte(r.body), &d))
	if r.code != 200 || d.CSRF != s.csrf || !d.Scans {
		t.Fatal(r.code, r.body)
	}
	_, h2 := newTest(t, Options{Token: "t"})
	if r := do(h2, "GET", "/api/session", nil, nil); r.code != 401 {
		t.Fatal("session without the access token:", r.code)
	}
}
