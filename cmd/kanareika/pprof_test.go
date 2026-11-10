package main

import (
	"net"
	"net/http"
	"testing"
	"time"
)

// TestPprof: KANAREIKA_PPROF serves the profiles; unset, or in the trivy child, nothing listens.
func TestPprof(t *testing.T) {
	if servePprof("", []string{"kanareika"}) || servePprof("127.0.0.1:1", []string{"kanareika", "__trivy"}) {
		t.Fatal("served when not asked for")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	if !servePprof(addr, []string{"kanareika", "web"}) {
		t.Fatal("not served")
	}
	for range 50 {
		if r, err := http.Get("http://" + addr + "/debug/pprof/"); err == nil {
			_ = r.Body.Close()
			if r.StatusCode == 200 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no profiles on " + addr)
}
