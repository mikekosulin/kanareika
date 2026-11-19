package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/update"
)

// TestVersion: /api/version names a newer release only when there is one, and asks GitHub only when checks are on.
func TestVersion(t *testing.T) {
	t.Setenv("KANAREIKA_OFFLINE", "")
	t.Setenv("KANAREIKA_UPDATE_CHECK", "")
	hits := 0
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"tag_name": "v0.7.0", "html_url": "https://github.com/mikekosulin/kanareika/releases/tag/v0.7.0"}`))
	}))
	defer gh.Close()
	defer func(u string) { update.LatestURL = u }(update.LatestURL)
	update.LatestURL = gh.URL
	home := t.TempDir()
	type answer struct {
		Version, Latest, URL string
		Check                bool
	}
	get := func(version, path string) answer {
		t.Helper()
		s, err := New(Options{Paths: config.PathsAt(home), Version: version, UpdatePath: path})
		must(t, err)
		defer s.Close()
		var a answer
		must(t, json.Unmarshal([]byte(do(s.Handler(), "GET", "/api/version", nil, nil).body), &a))
		return a
	}
	path := filepath.Join(t.TempDir(), "update.json")
	if a := get("v0.6.1", path); a.Version != "v0.6.1" || a.Latest != "v0.7.0" || a.URL == "" || !a.Check || hits != 1 {
		t.Fatalf("older: %+v, %d requests", a, hits)
	}
	if a := get("v0.7.0", path); a.Latest != "" || a.URL != "" || hits != 1 {
		t.Fatalf("the latest: %+v, %d requests (the day's answer is kept)", a, hits)
	}
	if a := get("dev", filepath.Join(t.TempDir(), "u.json")); a.Check || a.Latest != "" || hits != 1 {
		t.Fatalf("a dev build: %+v, %d requests", a, hits)
	}
	if a := get("v0.6.1", ""); a.Check || a.Latest != "" || hits != 1 {
		t.Fatalf("no place to keep checks: %+v, %d requests", a, hits)
	}
}
