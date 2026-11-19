package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		cur, latest string
		want        bool
	}{
		{"v0.6.1", "v0.7.0", true},
		{"v0.6.1", "v0.6.2", true},
		{"v0.6.1", "v1.0.0", true},
		{"v0.6.1", "v0.6.1", false},
		{"v0.7.0", "v0.6.9", false},
		{"v0.10.0", "v0.9.0", false}, // numbers, not text
		{"v0.7.0-rc1", "v0.7.0", true},
		{"v0.7.0", "v0.7.0-rc1", false},
		{"0.6.1", "v0.7.0", true},
		{"dev", "v0.7.0", false},
		{"v0.6.1-3-gabc1234", "v0.7.0", false}, // a build after a tag
		{"v0.6.1-dirty", "v0.7.0", false},
		{"v0.6.1", "", false},
		{"v0.6.1", "latest", false},
	} {
		if got := (Info{Latest: c.latest}).Newer(c.cur) != ""; got != c.want {
			t.Errorf("Newer(%q → %q) = %v, want %v", c.cur, c.latest, got, c.want)
		}
	}
}

func TestEnabled(t *testing.T) {
	t.Setenv("KANAREIKA_OFFLINE", "")
	t.Setenv("KANAREIKA_UPDATE_CHECK", "")
	if !Enabled("v0.6.1") || Enabled("dev") || Enabled("v0.6.1-2-g1234567") {
		t.Fatal("by version")
	}
	for _, v := range []string{"off", "OFF", "0", "false", "no"} {
		t.Setenv("KANAREIKA_UPDATE_CHECK", v)
		if Enabled("v0.6.1") {
			t.Errorf("KANAREIKA_UPDATE_CHECK=%s", v)
		}
	}
	t.Setenv("KANAREIKA_UPDATE_CHECK", "")
	t.Setenv("KANAREIKA_OFFLINE", "1")
	if Enabled("v0.6.1") {
		t.Error("KANAREIKA_OFFLINE")
	}
}

// TestCheck: GitHub is asked once a day at most, a failure included; a failed check keeps what the last good one
// learned; disabled, nothing is asked.
func TestCheck(t *testing.T) {
	t.Setenv("KANAREIKA_OFFLINE", "")
	t.Setenv("KANAREIKA_UPDATE_CHECK", "")
	var hits atomic.Int32
	answer := `{"tag_name": "v0.7.0", "html_url": "https://github.com/mikekosulin/kanareika/releases/tag/v0.7.0", "body": "…"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("Accept %q", r.Header.Get("Accept"))
		}
		if answer == "" {
			http.Error(w, "rate limited", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()
	defer func(u string) { LatestURL = u }(LatestURL)
	LatestURL = srv.URL
	path := filepath.Join(t.TempDir(), "kanareika", "update.json")
	ctx, now := context.Background(), time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

	i := Check(ctx, path, "v0.6.1", now)
	if i.Newer("v0.6.1") != "v0.7.0" || i.URL == "" || hits.Load() != 1 {
		t.Fatalf("first check: %+v, %d requests", i, hits.Load())
	}
	if i = Check(ctx, path, "v0.6.1", now.Add(23*time.Hour)); hits.Load() != 1 || i.Latest != "v0.7.0" {
		t.Fatalf("within a day: %+v, %d requests", i, hits.Load())
	}
	answer = ""
	i = Check(ctx, path, "v0.6.1", now.Add(25*time.Hour))
	if hits.Load() != 2 || i.Error == "" || i.Latest != "v0.7.0" {
		t.Fatalf("a failed check: %+v, %d requests", i, hits.Load())
	}
	if Check(ctx, path, "v0.6.1", now.Add(30*time.Hour)); hits.Load() != 2 {
		t.Fatal("a failure is not asked again within a day")
	}
	if l := Load(path); l.Latest != "v0.7.0" || !l.Checked.Equal(now.Add(25*time.Hour)) {
		t.Fatalf("kept: %+v", l)
	}
	t.Setenv("KANAREIKA_UPDATE_CHECK", "off")
	if Check(ctx, path, "v0.6.1", now.Add(72*time.Hour)); hits.Load() != 2 {
		t.Fatal("asked while off")
	}
	if Check(ctx, "", "v0.6.1", now); hits.Load() != 2 {
		t.Fatal("asked without a place to keep the answer")
	}
}

func TestCheckRejectsOddAnswers(t *testing.T) {
	t.Setenv("KANAREIKA_OFFLINE", "")
	t.Setenv("KANAREIKA_UPDATE_CHECK", "")
	defer func(u string) { LatestURL = u }(LatestURL)
	for _, body := range []string{`not json`, `{"tag_name": "nightly"}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		LatestURL = srv.URL
		i := Check(context.Background(), filepath.Join(t.TempDir(), "u.json"), "v0.6.1", time.Now())
		srv.Close()
		if i.Error == "" || i.Latest != "" {
			t.Errorf("%s: %+v", body, i)
		}
	}
	// a page that is not on github.com is replaced by the release's own
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name": "v0.7.0", "html_url": "https://evil.example/x"}`))
	}))
	defer srv.Close()
	LatestURL = srv.URL
	i := Check(context.Background(), filepath.Join(t.TempDir(), "u.json"), "v0.6.1", time.Now())
	if i.URL != "https://github.com/mikekosulin/kanareika/releases/tag/v0.7.0" {
		t.Errorf("url %q", i.URL)
	}
}
