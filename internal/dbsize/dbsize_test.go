package dbsize

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/priority"
)

func TestCheck(t *testing.T) {
	t.Setenv("TRIVY_CACHE_DIR", t.TempDir())
	feeds := t.TempDir()
	t.Setenv("KANAREIKA_FEEDS_DIR", feeds)
	calls := 0
	old := Lookup
	t.Cleanup(func() { Lookup = old; Reset() })
	Reset()
	Lookup = func(context.Context, priority.Policy) map[string]int64 {
		calls++
		return map[string]int64{"db": 800e6, "java-db": 400e6, "kev": 1e6, "epss": 2e6, "dbip-city": 30e6, "dbip-asn": 8e6}
	}
	now := time.Now()
	r := Check(context.Background(), priority.Policy{}, now, true)
	if !slices.Equal(r.Need, []string{"kev", "epss", "dbip-city", "dbip-asn", "db", "java-db"}) || r.Total != 1241e6 {
		t.Fatal(r)
	}
	var b bytes.Buffer
	r.Print(&b)
	for _, want := range []string{"Linux packages", "800 MB", "Exploit data", "3 MB", "total", "1.2 GB"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("%q not in\n%s", want, b.String())
		}
	}
	// fresh feeds and IP DBs: not needed any more
	for f, body := range map[string]string{"dbip-city.mmdb": "", "dbip-asn.mmdb": "", "kev.json": `["CVE-2021-44228"]`,
		"epss.json": `{"CVE-2021-44228": 0.97}`} {
		if err := os.WriteFile(filepath.Join(feeds, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(feeds, "updated"), []byte(now.UTC().Format("2006-01-02T15:04:05.000000-07:00")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := Check(context.Background(), priority.Policy{}, now, true); !slices.Equal(r.Need, []string{"db", "java-db"}) || calls != 1 {
		t.Fatal(r, calls)
	}
	for n, want := range map[int64]string{0: "?", 400: "1 KB", 12e3: "12 KB", 85e6: "85 MB", 1.24e9: "1.2 GB"} {
		if Bytes(n) != want {
			t.Errorf("%d: %s", n, Bytes(n))
		}
	}
}
