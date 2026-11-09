package tui

import (
	"slices"
	"time"

	"github.com/mikekosulin/kanareika/internal/server"
)

// requests: the scans the fake scanner was asked for, once one came (a scan may wait for a DB update first).
func (s *scanner) requests() []server.ScanRequest {
	for range 300 {
		s.mu.Lock()
		n := len(s.reqs)
		s.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs)
}

// show: a view directly (the lenses of Servers, ToDo's and History's sub-views).
func (h *harness) show(v view) {
	h.m.setView(v)
	h.run(h.m.sync())
}
