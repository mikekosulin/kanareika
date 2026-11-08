package scan

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFeedsWarn: no KEV / EPSS, or old ones, are said out loud; offline gets a week before it complains.
func TestFeedsWarn(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KANAREIKA_FEEDS_DIR", dir)
	var out bytes.Buffer
	s := &Scanner{Err: &out, Out: &out}
	s.feedsWarn(false)
	if !strings.Contains(out.String(), "no KEV / EPSS data") {
		t.Fatal(out.String())
	}
	write := func(age time.Duration) {
		t.Helper()
		out.Reset()
		stamp := time.Now().Add(-age).UTC().Format("2006-01-02T15:04:05.000000-07:00")
		for name, body := range map[string]string{"kev.json": `["CVE-1"]`, "epss.json": `{}`, "updated": stamp} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(2 * time.Hour)
	if s.feedsWarn(false); out.Len() != 0 {
		t.Fatal("fresh: quiet:", out.String())
	}
	write(3 * 24 * time.Hour)
	if s.feedsWarn(false); !strings.Contains(out.String(), "KEV / EPSS from") {
		t.Fatal("online, 3 days old:", out.String())
	}
	out.Reset()
	if s.feedsWarn(true); out.Len() != 0 {
		t.Fatal("offline, 3 days old: still fine:", out.String())
	}
	write(9 * 24 * time.Hour)
	if s.feedsWarn(true); !strings.Contains(out.String(), "old") {
		t.Fatal("offline, 9 days old:", out.String())
	}
}
