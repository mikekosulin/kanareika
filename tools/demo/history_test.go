package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/server"
)

// TestHistory: /api/history lists the runs newest first with their totals and how many findings appeared and went
// since the run before.
func TestHistory(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	home := filepath.Join(t.TempDir(), "demo")
	if err := generate(home, time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC), 6); err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Options{Paths: config.PathsAt(home)})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/history?org=acme&env=production", nil))
	var h struct {
		Runs []struct {
			RunID     string         `json:"run_id"`
			State     string         `json:"state"`
			Prev      *string        `json:"prev"`
			NewN      int            `json:"new"`
			ResolvedN int            `json:"resolved"`
			Totals    *report.Totals `json:"totals"`
		}
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &h) != nil || len(h.Runs) != 6 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	first, last := h.Runs[len(h.Runs)-1], h.Runs[0]
	if first.Prev != nil || last.Prev == nil || last.RunID <= first.RunID || last.Totals == nil || last.Totals.Fixes == 0 {
		t.Fatalf("%+v / %+v", first, last)
	}
	changed := 0
	for _, r := range h.Runs {
		changed += r.NewN + r.ResolvedN
	}
	if changed == 0 {
		t.Error("no changes over six days")
	}
}
