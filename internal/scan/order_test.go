package scan

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
)

func TestLongestFirst(t *testing.T) {
	env := t.TempDir()
	write := func(run, body string) {
		if err := os.MkdirAll(filepath.Join(env, run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(env, run, "status.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("2026-11-01_100000", `{"hosts": {"a": {"seconds": 5}, "b": {"seconds": 90}, "c": {"seconds": 30}}}`)
	write("2026-11-02_100000", `{"hosts": {"a": {"seconds": 60}, "b": {"state": "failed"}}}`) // newer: a took 60
	write("2026-11-03_100000", `not json`)
	secs := hostSeconds(env)
	if secs["a"] != 60 || secs["b"] != 90 || secs["c"] != 30 || len(secs) != 3 {
		t.Fatalf("seconds %v", secs)
	}
	var hosts []config.Host
	for _, n := range []string{"a", "new1", "c", "b", "new2"} {
		hosts = append(hosts, config.Host{Name: n})
	}
	var got []string
	for _, h := range longestFirst(hosts, secs) {
		got = append(got, h.Name)
	}
	if want := []string{"new1", "new2", "b", "a", "c"}; !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	if len(hostSeconds(filepath.Join(env, "missing"))) != 0 {
		t.Fatal("seconds from nothing")
	}
}

func TestProgressTimesHosts(t *testing.T) {
	p, err := NewProgress(t.TempDir(), "o", "e", "r", []string{"a", "b"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Host("a", HostUpdate{State: "running"})
	p.hosts["a"].start = time.Now().Add(-90 * time.Second)
	p.Host("a", HostUpdate{State: "ok"})
	p.Host("a", HostUpdate{State: "warn"}) // the first end counts
	p.Finish("done", nil)
	if s := p.hosts["a"].Seconds; s < 89.9 || s > 91 {
		t.Fatalf("a took %v s", s)
	}
	if p.hosts["b"].Seconds != 0 {
		t.Fatal("b never ran, yet timed")
	}
}
