// Package update: whether a newer kanareika is released. At most once a day one request to GitHub's releases API
// (what it sees: the address and the User-Agent with the running version; nothing else is sent), the answer kept
// in the user's cache dir. Nothing is downloaded or installed: the interfaces only say that a release is out.
//
// Off with KANAREIKA_UPDATE_CHECK=off (or 0, false, no), with KANAREIKA_OFFLINE, and for builds that are not a
// release (dev, a commit after a tag, local changes).
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/dbget"
)

// LatestURL: the latest release of the repository (drafts and pre-releases are never "latest"). Tests point it at
// their server.
var LatestURL = "https://api.github.com/repos/mikekosulin/kanareika/releases/latest"

// Every: how often GitHub is asked at most; a failed request counts too, so a network without GitHub is not
// asked again for a day.
const Every = 24 * time.Hour

// Timeout: the whole request; a check never holds anything up for longer.
var Timeout = 5 * time.Second

// Info: what the last check learned. Latest and URL are kept when a later check fails.
type Info struct {
	Checked time.Time `json:"checked"`
	Latest  string    `json:"latest,omitempty"` // "v0.7.0"
	URL     string    `json:"url,omitempty"`    // the release page
	Error   string    `json:"error,omitempty"`  // the last check's failure
}

// Newer: the release to tell about ("" when current is the latest, or newer, or not a release).
func (i Info) Newer(current string) string {
	if newer(current, i.Latest) {
		return i.Latest
	}
	return ""
}

// release: vX.Y.Z, an optional -suffix (rc1). A build with commits after the tag (v0.6.1-3-gabc1234) or local
// changes (-dirty) is not one.
var release = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.]+))?$`)

func parse(v string) (n [3]int, pre string, ok bool) {
	m := release.FindStringSubmatch(v)
	if m == nil || m[4] == "dirty" {
		return n, "", false
	}
	for i := range n {
		n[i], _ = strconv.Atoi(m[i+1])
	}
	return n, m[4], true
}

// newer: latest is a later release than current. A pre-release is older than its release (v0.7.0-rc1 < v0.7.0).
func newer(current, latest string) bool {
	c, cp, ok1 := parse(current)
	l, lp, ok2 := parse(latest)
	if !ok1 || !ok2 {
		return false
	}
	for i := range c {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return cp != "" && (lp == "" || lp > cp)
}

// Enabled: checks are on for this build and environment.
func Enabled(version string) bool {
	if _, _, ok := parse(version); !ok {
		return false
	}
	if os.Getenv("KANAREIKA_OFFLINE") != "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("KANAREIKA_UPDATE_CHECK"))) {
	case "off", "0", "false", "no":
		return false
	}
	return true
}

// DefaultPath: <user cache dir>/kanareika/update.json ("" when there is no such dir: nothing is kept, and nothing
// is asked, so a machine without one is never asked on every start).
func DefaultPath() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "kanareika", "update.json")
}

// Load: what the last check left at path (zero Info when nothing).
func Load(path string) Info {
	var i Info
	if path == "" {
		return i
	}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &i)
	}
	return i
}

func save(path string, i Info) error {
	b, _ := json.MarshalIndent(i, "", "  ") // a time and strings: always encodes
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var mu sync.Mutex // one check at a time in this process (the server's loop and a page's request)

// Check: the release info, asking GitHub only when the last check at path is older than Every. Disabled (see
// Enabled) or without a path: what is kept, never a request.
func Check(ctx context.Context, path, version string, now time.Time) Info {
	mu.Lock()
	defer mu.Unlock()
	i := Load(path)
	if path == "" || !Enabled(version) || now.Sub(i.Checked) < Every && !i.Checked.After(now) {
		return i
	}
	latest, url, err := fetch(ctx)
	i.Checked, i.Error = now.UTC(), ""
	if err != nil {
		i.Error = err.Error()
	} else {
		i.Latest, i.URL = latest, url
	}
	_ = save(path, i) // a cache that can't be written only means asking again next time
	return i
}

func fetch(parent context.Context) (tag, page string, err error) {
	ctx, cancel := context.WithTimeout(parent, Timeout)
	defer cancel()
	resp, err := dbget.Get(ctx, LatestURL, http.Header{"Accept": {"application/vnd.github+json"}})
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var r struct {
		Tag  string `json:"tag_name"`
		Page string `json:"html_url"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return "", "", fmt.Errorf("the releases answer: %w", err)
	}
	if _, _, ok := parse(r.Tag); !ok {
		return "", "", errors.New("the latest release has no version tag")
	}
	if !strings.HasPrefix(r.Page, "https://github.com/") {
		r.Page = "https://github.com/mikekosulin/kanareika/releases/tag/" + r.Tag
	}
	return r.Tag, r.Page, nil
}
