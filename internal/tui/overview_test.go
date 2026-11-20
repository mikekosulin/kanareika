package tui

import (
	"testing"
	"time"
)

// TestOverview: with more than one org/env, 0 shows them all with their fixes by priority; enter opens one's fixes;
// s asks to scan everything, s again queues a scan of each (the first one runs).
func TestOverview(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	if !h.m.multiScope() {
		t.Fatal("the fixture has production and staging")
	}
	h.key("0")
	if h.m.view != vOverview {
		t.Fatal(h.m.view)
	}
	h.has("Overview[2]", "production", "staging", "0 Overview", "1 not reached")
	h.key("j", "enter")
	if h.m.view != vActions || h.m.env != "staging" {
		t.Fatalf("enter: %v %s", h.m.view, h.m.env)
	}
	h.key("0", "s")
	h.has("one after another?")
	if len(h.scan.requests()) != 0 {
		t.Fatal("one s started a scan")
	}
	h.key("s")
	for i := 0; i < 200 && len(h.scan.requests()) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(h.scan.requests()); n != 1 {
		t.Fatalf("%d scans running: they are queued one after another", n)
	}
	h.has("Scans queued: 2")
	close(h.scan.release)

	// one org/env: no Overview
	h.m.orgs.Orgs = h.m.orgs.Orgs[:1]
	h.m.orgs.Orgs[0].Envs = h.m.orgs.Orgs[0].Envs[:1]
	h.key("1", "0")
	if h.m.view == vOverview {
		t.Fatal("Overview with one org/env")
	}
}
