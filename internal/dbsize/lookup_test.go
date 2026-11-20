package dbsize

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/dbget"
	"github.com/mikekosulin/kanareika/internal/priority"
)

// roundTrip: an http.RoundTripper from a function.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestLookup: the real lookup asks the registries for trivy's DBs and the feed servers for the rest (HEAD), and
// puts the sizes together. No network: every server is answered here.
func TestLookup(t *testing.T) {
	t.Setenv("TRIVY_DB_REPOSITORY", "")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "")
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", "registry.example/aquasecurity/trivy-db:2")
	t.Setenv("KANAREIKA_TRIVY_JAVA_DB_REPOS", "registry.example/aquasecurity/trivy-java-db:1")
	var mu sync.Mutex
	var asked []string
	answer := func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		asked = append(asked, r.Method+" "+r.URL.String())
		mu.Unlock()
		body, n := "", int64(0)
		switch {
		case strings.HasSuffix(r.URL.Path, "/trivy-db/manifests/2"):
			body = `{"layers":[{"size":800000000}]}`
		case strings.HasSuffix(r.URL.Path, "/trivy-java-db/manifests/1"):
			body = `{"layers":[{"size":400000000}]}`
		case r.URL.Path == "/kev.json":
			n = 1_000_000
		case r.URL.Path == "/epss.csv.gz":
			n = 2_000_000
		case strings.Contains(r.URL.Path, "dbip-city"):
			n = 30_000_000
		case strings.Contains(r.URL.Path, "dbip-asn"):
			n = 8_000_000
		default:
			return &http.Response{StatusCode: 404, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}
		if body != "" {
			n = int64(len(body))
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Length": {fmt.Sprint(n)}}, ContentLength: n,
			Body: io.NopCloser(bytes.NewReader([]byte(body))), Request: r}, nil
	}
	oldD, oldH := dbget.Transport, http.DefaultTransport
	t.Cleanup(func() { dbget.Transport, http.DefaultTransport = oldD, oldH })
	dbget.Transport, http.DefaultTransport = roundTrip(answer), roundTrip(answer)
	got := Lookup(context.Background(), priority.Policy{KEVURL: "https://feeds.example/kev.json", EPSSURL: "https://feeds.example/epss.csv.gz"})
	want := map[string]int64{"db": 800e6, "java-db": 400e6, "kev": 1e6, "epss": 2e6, "dbip-city": 30e6, "dbip-asn": 8e6}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %d, want %d", k, got[k], v)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, w := range []string{"GET https://registry.example/v2/aquasecurity/trivy-db/manifests/2", "HEAD https://feeds.example/kev.json"} {
		if !slices.Contains(asked, w) {
			t.Fatalf("no %q in %q", w, asked)
		}
	}
}

// TestCheckUpToDate: with everything fresh the CLI's lazy check needs nothing and looks up no size; the API's
// eager one still shows the sizes.
func TestCheckUpToDate(t *testing.T) {
	cache, feeds := t.TempDir(), t.TempDir()
	t.Setenv("TRIVY_CACHE_DIR", cache)
	t.Setenv("KANAREIKA_FEEDS_DIR", feeds)
	calls := 0
	old := Lookup
	t.Cleanup(func() { Lookup = old; Reset() })
	Reset()
	Lookup = func(context.Context, priority.Policy) map[string]int64 { calls++; return map[string]int64{"db": 800e6} }
	now := time.Now()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for f, body := range map[string]string{"dbip-city.mmdb": "", "dbip-asn.mmdb": "", "kev.json": `["CVE-2021-44228"]`,
		"epss.json": `{"CVE-2021-44228": 0.97}`} {
		write(filepath.Join(feeds, f), body)
	}
	write(filepath.Join(feeds, "updated"), now.UTC().Format("2006-01-02T15:04:05.000000-07:00"))
	write(filepath.Join(cache, "db", "metadata.json"), fmt.Sprintf(`{"UpdatedAt":%q,"NextUpdate":%q}`,
		now.Add(-time.Hour).UTC().Format(time.RFC3339), now.Add(time.Hour).UTC().Format(time.RFC3339)))
	r := Check(context.Background(), priority.Policy{}, now, true)
	if len(r.Need) != 0 || len(r.Sizes) != 0 || r.Total != 0 || calls != 0 {
		t.Fatal(r, calls)
	}
	if r := Check(context.Background(), priority.Policy{}, now, false); r.Sizes["db"] != 800e6 || r.Total != 0 || calls != 1 {
		t.Fatal(r, calls)
	}
}
