package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestScanAll: "scan everything" queues a scan of each environment, one after another (the next starts when the
// one before has finished); an environment already being scanned is skipped with the reason; cancelling a queued
// one means it never runs; ?org limits it to one org.
func TestScanAll(t *testing.T) {
	f := &fakeScan{release: make(chan struct{})}
	s, h := newTest(t, Options{Scan: f.run})
	type answer struct {
		IDs     []string
		Skipped []map[string]string
	}
	post := func(body any) answer {
		t.Helper()
		r := do(h, "POST", "/api/scan/all", body, s.postHdr())
		if r.code != 202 {
			t.Fatal(r.code, r.body)
		}
		var a answer
		must(t, json.Unmarshal([]byte(r.body), &a))
		return a
	}
	a := post(map[string]string{})
	if len(a.IDs) != 2 || len(a.Skipped) != 0 { // acme: production and staging
		t.Fatalf("%+v", a)
	}
	waitState(t, h, a.IDs[0], JobRunning)
	waitState(t, h, a.IDs[1], JobQueued)
	for i := 0; i < 300 && len(f.requests()) == 0; i++ { // running: its scan starts a moment later
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(f.requests()); n != 1 {
		t.Fatalf("%d scans run at once", n)
	}
	// the env scanning and the one waiting are both busy
	if b := post(map[string]string{"org": "acme"}); len(b.IDs) != 0 || len(b.Skipped) != 2 || !strings.Contains(b.Skipped[0]["reason"], "already running") {
		t.Fatalf("%+v", b)
	}
	f.release <- struct{}{} // the first finishes, the second starts
	waitState(t, h, a.IDs[0], JobDone)
	waitState(t, h, a.IDs[1], JobRunning)
	close(f.release)
	waitState(t, h, a.IDs[1], JobDone)
	if n := len(f.requests()); n != 2 {
		t.Fatalf("%d scans", n)
	}

	// cancelled while queued: never runs
	f2 := &fakeScan{release: make(chan struct{})}
	s2, h2 := newTest(t, Options{Scan: f2.run})
	r := do(h2, "POST", "/api/scan/all", map[string]string{"org": "acme"}, s2.postHdr())
	var b answer
	must(t, json.Unmarshal([]byte(r.body), &b))
	waitState(t, h2, b.IDs[1], JobQueued)
	if r := do(h2, "POST", "/api/jobs/"+b.IDs[1]+"/cancel", nil, s2.postHdr()); r.code != 202 {
		t.Fatal(r.code, r.body)
	}
	close(f2.release)
	waitState(t, h2, b.IDs[1], JobCancelled)
	waitState(t, h2, b.IDs[0], JobDone)
	if n := len(f2.requests()); n != 1 {
		t.Fatalf("a cancelled queued scan ran: %d scans", n)
	}

	if r := do(h, "POST", "/api/scan/all", map[string]string{"org": "nope"}, s.postHdr()); r.code != 400 {
		t.Fatal(r.code, r.body)
	}
	if r := do(h, "POST", "/api/scan/all", map[string]string{"rm": "-rf"}, s.postHdr()); r.code != 400 {
		t.Fatal(r.code, r.body)
	}
	_, ro := newTest(t, Options{}) // scans off
	if r := do(ro, "POST", "/api/scan/all", map[string]string{}, s.postHdr()); r.code != 403 {
		t.Fatal(r.code, r.body)
	}
}
