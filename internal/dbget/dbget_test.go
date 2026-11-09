package dbget

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// clock: a test clock moved by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestRunParallel: every job runs at once (none starts only when another ended); each ends done, cached or failed
// with its reason; Fatal leaves out optional and kept failures.
func TestRunParallel(t *testing.T) {
	const n = 4
	var started sync.WaitGroup
	started.Add(n)
	all := make(chan struct{})
	go func() { started.Wait(); close(all) }()
	wait := func() error {
		started.Done()
		select {
		case <-all:
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("not parallel")
		}
	}
	jobs := []Job{
		{Name: "db", Label: "DB", Run: func(ctx context.Context, p *Progress) error {
			if err := wait(); err != nil {
				return err
			}
			p.Start(10)
			_, err := io.Copy(io.Discard, p.Reader(strings.NewReader("0123456789")))
			return err
		}},
		{Name: "kev", Label: "KEV", Run: func(ctx context.Context, p *Progress) error {
			if err := wait(); err != nil {
				return err
			}
			p.Cached("already up to date (cached)")
			return nil
		}},
		{Name: "dbip-city", Label: "IP", Optional: true, Run: func(ctx context.Context, p *Progress) error {
			_ = wait()
			return &StatusError{Code: 404, Host: "x"}
		}},
		{Name: "epss", Label: "EPSS", Run: func(ctx context.Context, p *Progress) error {
			_ = wait()
			return Kept(&StatusError{Code: 429, Host: "x"}, "the copy from yesterday stays in use")
		}},
	}
	tr := NewTracker()
	var events []string
	var mu sync.Mutex
	tr.OnEvent = func(it Item) { mu.Lock(); events = append(events, it.Name+":"+it.State); mu.Unlock() }
	errs := tr.Run(context.Background(), jobs)
	if len(errs) != 2 || Fatal(jobs, errs) != nil {
		t.Fatal(errs, Fatal(jobs, errs))
	}
	s := tr.Snapshot()
	want := map[string][2]string{"db": {Done, "in 1 s"}, "kev": {Cached, "already up to date (cached)"},
		"dbip-city": {Failed, "not found (404)"}, "epss": {Failed, "too many requests (429); the copy from yesterday stays in use"}}
	for _, it := range s.Items {
		if w := want[it.Name]; it.State != w[0] || it.Note != w[1] {
			t.Errorf("%s: %s %q, want %v", it.Name, it.State, it.Note, w)
		}
	}
	if s.Running || s.Totals.Bytes != 10 || s.Totals.Total != 10 || s.Items[0].Total != 10 || s.Totals.ETA != nil {
		t.Fatalf("%+v", s)
	}
	if len(events) < 5 {
		t.Fatal(events)
	}
	// a needed download that failed: fatal, named by its label
	jobs[1].Run = func(context.Context, *Progress) error {
		return &TimeoutError{What: "timed out", After: 30 * time.Second}
	}
	if err := Fatal(jobs, NewTracker().Run(context.Background(), jobs[1:2])); err == nil || err.Error() != "KEV: timed out after 30 s" {
		t.Fatal(err)
	}
}

// TestProgressNumbers: bytes, a smoothed speed, the time left; totals over the downloads; a stalled download slows to 0.
func TestProgressNumbers(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)}
	tr := NewTracker()
	tr.now = c.now
	step := make(chan int64)
	ack := make(chan struct{})
	jobs := []Job{
		{Name: "db", Label: "DB", Run: func(_ context.Context, p *Progress) error {
			p.Start(1000)
			for n := range step {
				p.add(n)
				ack <- struct{}{}
			}
			return nil
		}},
		{Name: "kev", Label: "KEV", Run: func(_ context.Context, p *Progress) error { p.Start(0); return nil }},
	}
	done := make(chan struct{})
	go func() { tr.Run(context.Background(), jobs); close(done) }()
	for s := tr.Snapshot(); len(s.Items) == 0 || s.Items[0].State != Downloading; s = tr.Snapshot() {
		time.Sleep(time.Millisecond)
	}
	c.add(time.Second)
	step <- 100
	<-ack
	s := tr.Snapshot()
	it := s.Items[0]
	if it.Bytes != 100 || it.Speed != 100 || it.ETA == nil || *it.ETA != 9 {
		t.Fatalf("%+v eta %v", it, it.ETA)
	}
	c.add(time.Second)
	step <- 300
	<-ack
	it = tr.Snapshot().Items[0]
	if it.Speed != 160 { // 0.7*100 + 0.3*300
		t.Fatalf("speed %d", it.Speed)
	}
	// stalled: the speed decays on every look
	c.add(10 * time.Second)
	if it := tr.Snapshot().Items[0]; it.Speed >= 160 || it.Bytes != 400 {
		t.Fatal(it)
	}
	close(step)
	<-done
	s = tr.Snapshot()
	if s.Totals.Bytes != 400 || s.Totals.Total != 1000+0 || s.Items[1].State != Done {
		t.Fatalf("%+v", s)
	}
	// the JSON the interfaces read
	b, _ := json.Marshal(s)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	item := m["items"].([]any)[0].(map[string]any)
	for _, k := range []string{"name", "label", "bytes", "total", "speed", "eta_s", "state", "note"} {
		if _, ok := item[k]; !ok {
			t.Fatalf("item has no %s: %s", k, b)
		}
	}
	for _, k := range []string{"bytes", "total", "speed", "eta_s"} {
		if _, ok := m["totals"].(map[string]any)[k]; !ok {
			t.Fatalf("totals have no %s: %s", k, b)
		}
	}
}

// TestNilProgress: jobs run outside a tracker (Prepare) report to nil.
func TestNilProgress(t *testing.T) {
	var p *Progress
	p.Start(5)
	p.Note("x")
	p.Cached("y")
	if r := p.Reader(strings.NewReader("abc")); r == nil {
		t.Fatal("nil reader")
	}
	ctx := WithTracker(context.Background(), NewTracker())
	if TrackerFrom(ctx) == nil || TrackerFrom(context.Background()) != nil {
		t.Fatal("tracker in context")
	}
	jobs := []Job{{Name: "epss"}, {Name: "db"}, {Name: "dbip-asn"}}
	Sort(jobs)
	if strings.Join(Names(jobs), ",") != "db,dbip-asn,epss" {
		t.Fatal(Names(jobs))
	}
}

func reasonOf(t *testing.T, url string) string {
	t.Helper()
	resp, err := Get(context.Background(), url, nil)
	if err == nil {
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return Reason(err)
}

// TestReasons: what fails says why in words: statuses, timeouts, TLS, refused connections, full disks.
func TestReasons(t *testing.T) {
	oldT, oldI := Timeout, Idle
	Timeout, Idle = 200*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { Timeout, Idle = oldT, oldI })
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/429":
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(429)
		case "/429bare":
			w.WriteHeader(429)
		case "/401":
			w.WriteHeader(401)
		case "/403":
			w.WriteHeader(403)
		case "/502":
			w.WriteHeader(502)
		case "/418":
			w.WriteHeader(418)
		case "/slow-headers":
			<-release
		case "/stall":
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("first"))
			w.(http.Flusher).Flush()
			<-release
		case "/short":
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("first"))
		case "/ua":
			if r.UserAgent() != UserAgent || len(r.Header) > 2 { // User-Agent, Accept-Encoding: nothing else
				w.WriteHeader(400)
			}
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(tlsSrv.Close)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	refused := "http://" + ln.Addr().String()
	ln.Close()

	for path, want := range map[string]string{
		"/429":          "too many requests (429), retry after 2 min",
		"/429bare":      "too many requests (429)",
		"/401":          "unauthorized (401)",
		"/403":          "forbidden (403)",
		"/502":          "server error (502)",
		"/418":          "i'm a teapot (418)",
		"/slow-headers": "timed out after 200 ms",
		"/stall":        "no data for 200 ms",
		"/short":        "connection closed mid-download",
		"/ua":           "",
	} {
		if got := reasonOf(t, srv.URL+path); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
	if got := reasonOf(t, tlsSrv.URL); got != "TLS: certificate signed by unknown authority (a proxy?)" {
		t.Error(got)
	}
	if got := reasonOf(t, refused); got != "connection refused" {
		t.Error(got)
	}
	if got := reasonOf(t, "https://"+strings.TrimPrefix(srv.URL, "http://")); got != "TLS: the server does not speak TLS" {
		t.Error(got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if resp, err := Get(ctx, srv.URL+"/ua", nil); err == nil || Reason(err) != "cancelled" {
		if resp != nil {
			resp.Body.Close()
		}
		t.Error(Reason(err))
	}
	for err, want := range map[error]string{
		NoSpace(&os.PathError{Op: "write", Path: "/x", Err: syscall.ENOSPC}, 2_100_000_000): "no space left on device: 2.1 GB free needed",
		NoSpace(syscall.ENOSPC, 0):          "no space left on device",
		fmt.Errorf("x: %w", syscall.ENOSPC): "no space left on device",
		&ChecksumError{Want: "sha256:aaaaaaaaaaaaaaaa", Got: "sha256:bbbbbbbbbbbbbbbb"}: "sha256 mismatch: got bbbbbbbbbbbb, expected aaaaaaaaaaaa (corrupted download)",
		&net.DNSError{Name: "ghcr.io", Err: "no such host"}:                             "cannot resolve ghcr.io (offline? DNS?)",
		x509.HostnameError{Host: "ghcr.io", Certificate: &x509.Certificate{}}:           "TLS: the certificate is not for ghcr.io (a proxy?)",
		x509.CertificateInvalidError{Reason: x509.Expired}:                              "TLS: certificate expired or not yet valid (is the clock right?)",
		x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign}:                  "TLS: invalid certificate (a proxy?)",
		fmt.Errorf("x: %w", syscall.ECONNRESET):                                         "connection reset",
		fmt.Errorf("x: %w", syscall.ENETUNREACH):                                        "network unreachable (offline?)",
		context.DeadlineExceeded:                                                        "timed out",
		errors.New("something else"):                                                    "something else",
		&TimeoutError{What: "timed out", After: 90 * time.Second}:                       "timed out after 1 min 30 s",
		Kept(&StatusError{Code: 401}, "kept"):                                           "unauthorized (401); kept",
	} {
		if got := Reason(err); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
	if Reason(nil) != "" || Seconds(2*time.Minute) != "2 min" || Size(0) != "0 KB" || Size(12_300) != "12 KB" || Size(139e6) != "139 MB" {
		t.Fatal("formats")
	}
	if e := (&StatusError{Code: 404, Host: "h"}); e.Error() != "h: not found (404)" {
		t.Fatal(e.Error())
	}
	if e := (&StatusError{Code: 407}); e.Reason() != "proxy authentication required (407)" {
		t.Fatal(e.Reason())
	}
	if e := (&StatusError{Code: 299 + 300}); e.Reason() != "HTTP status (599)" && e.Reason() != "server error (599)" {
		t.Fatal(e.Reason())
	}
}
