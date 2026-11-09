// Package dbsize says what a DB update would download and how big it is: the vulnerability DB (trivy-db; the Java
// DB only when a scan meets .jar files), CISA KEV and EPSS, and the DB-IP Lite IP databases. The web page and the TUI show it (GET
// /api/db/size) and the CLI asks with it before downloading: on a phone's mobile data a gigabyte matters.
package dbsize

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// Report: bytes per download ("db", "java-db", "kev", "epss", "dbip-city", "dbip-asn"; a missing one: the source
// did not say), which of them the next update needs, and the sum of those.
type Report struct {
	Sizes map[string]int64 `json:"sizes"`
	Need  []string         `json:"need"`
	Total int64            `json:"total"`
}

var (
	mu     sync.Mutex
	at     time.Time
	cached map[string]int64
	// TTL: how long looked-up sizes are kept
	TTL = time.Hour
	// Lookup: the sizes from the sources (manifests, HEAD requests: a few KB); tests replace it.
	Lookup = func(ctx context.Context, pol priority.Policy) map[string]int64 {
		out := trivy.DownloadSize(ctx)
		for k, v := range priority.DownloadSize(ctx, pol) {
			out[k] = v
		}
		return out
	}
)

// Reset forgets the looked-up sizes (tests).
func Reset() {
	mu.Lock()
	cached = nil
	mu.Unlock()
}

// Sizes: the download sizes, looked up at most once per TTL.
func Sizes(ctx context.Context, pol priority.Policy) map[string]int64 {
	mu.Lock()
	defer mu.Unlock()
	if cached == nil || time.Since(at) > TTL {
		cached, at = Lookup(ctx, pol), time.Now()
	}
	return cached
}

// Need: what the next update downloads: trivy DBs missing or outdated, KEV/EPSS missing or older than a scan
// accepts, IP databases missing. Empty: everything is up to date.
func Need(now time.Time) []string {
	need := []string{}
	feeds, _ := priority.LoadFeeds()
	if t, err := priority.FeedsTime(feeds.Updated); err != nil || now.Sub(t) > priority.FeedsMaxAge {
		need = append(need, "kev", "epss")
	}
	for _, k := range []string{"city", "asn"} {
		if _, err := os.Stat(filepath.Join(priority.FeedsDir(), "dbip-"+k+".mmdb")); err != nil {
			need = append(need, "dbip-"+k)
		}
	}
	for _, d := range trivy.DBStatus() {
		if d.Outdated(now) {
			need = append(need, d.Name)
		}
	}
	return need
}

// Optional: a download a scan does without (the IP databases: only the country and network of addresses).
func Optional(name string) bool { return strings.HasPrefix(name, "dbip-") }

// Required: need without the optional downloads: what is worth asking about.
func Required(need []string) []string {
	var out []string
	for _, k := range need {
		if !Optional(k) {
			out = append(out, k)
		}
	}
	return out
}

// Check: the report for now. lazy: the sizes are only looked up when something is needed (the CLI); else always
// (the API shows them).
func Check(ctx context.Context, pol priority.Policy, now time.Time, lazy bool) Report {
	r := Report{Need: Need(now), Sizes: map[string]int64{}}
	if lazy && len(r.Need) == 0 {
		return r
	}
	r.Sizes = Sizes(ctx, pol)
	for _, k := range r.Need {
		r.Total += r.Sizes[k]
	}
	return r
}

// Bytes: 1.2 GB, 85 MB, 12 KB; "?" when unknown.
func Bytes(n int64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%d MB", (n+5e5)/1e6)
	case n > 0:
		return fmt.Sprintf("%d KB", max(1, (n+500)/1e3))
	}
	return "?"
}
