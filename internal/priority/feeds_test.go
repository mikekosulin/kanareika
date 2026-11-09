package priority

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

// feedServer: KEV, EPSS and DB-IP as the real sites serve them; files maps a path to its body (missing: 404).
func feedServer(t *testing.T, files map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != UserAgent {
			http.Error(w, "no UA", http.StatusForbidden)
			return
		}
		b, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	old := ipdbURL
	ipdbURL = srv.URL + "/dbip-%s-%s.mmdb.gz"
	t.Cleanup(func() { ipdbURL = old })
	return srv
}

const kevJSON = `{"vulnerabilities":[{"cveID":"CVE-2026-0002"},{"cveID":"CVE-2026-0001"},{"cveID":"CVE-2026-0002"}]}`

const epssCSV = "#model_version:v2025.03.14,score_date:2026-11-07T00:00:00+0000\r\ncve,epss,percentile\r\nCVE-2026-0001,0.5,0.99\r\nCVE-2026-0003,0.00012,0.1\r\n"

// TestUpdateFeeds: KEV and EPSS stored and read back; this month's DB-IP file missing, so last month's is taken.
func TestUpdateFeeds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "feeds")
	t.Setenv("KANAREIKA_FEEDS_DIR", dir)
	now := time.Now()
	last := now.AddDate(0, 0, -now.Day()).Format("2006-01")
	srv := feedServer(t, map[string][]byte{
		"/kev.json": []byte(kevJSON), "/epss.csv.gz": gz(epssCSV),
		"/dbip-city-" + last + ".mmdb.gz": gz("CITY"), "/dbip-asn-" + now.Format("2006-01") + ".mmdb.gz": gz("ASN"),
	})
	st, err := UpdateFeeds(context.Background(), &Policy{KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz"})
	must(t, err)
	if st.KEV != 2 || st.EPSS != 2 || st.IPDBCity != last || st.IPDBASN != now.Format("2006-01") {
		t.Fatalf("%+v", st)
	}
	f, err := LoadFeeds()
	must(t, err)
	if !f.KEV["CVE-2026-0001"] || len(f.KEV) != 2 || f.EPSS["CVE-2026-0001"] != 0.5 || f.EPSS["CVE-2026-0003"] != 0.00012 {
		t.Fatalf("%+v", f)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "dbip-city.mmdb")); string(b) != "CITY" {
		t.Fatalf("city db %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "updated")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "dbip-city.mmdb.tmp")); err == nil {
		t.Fatal("tmp file left")
	}
}

func TestUpdateFeedsErrors(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(t.TempDir(), "feeds"))
	srv := feedServer(t, map[string][]byte{
		"/kev.json": []byte(kevJSON), "/epss.csv.gz": gz(epssCSV), "/bad.json": []byte("{"), "/plain": []byte("cve,epss"),
		"/nocols.gz": gz("a,b\n1,2\n"), "/short.gz": gz("cve,epss\nCVE-1\n"), "/nan.gz": gz("cve,epss\nCVE-1,x\n"),
		"/empty.gz": gz(""), "/quote.gz": gz("cve,epss\n\"CVE-1,0.1\n"), "/dbip-city-x.mmdb.gz": []byte("not gzip"),
	})
	u := func(p string) string { return srv.URL + p }
	cases := []struct {
		kev, epss, want string
	}{
		{"", u("/epss.csv.gz"), "required"},
		{u("/missing"), u("/epss.csv.gz"), "404"},
		{u("/bad.json"), u("/epss.csv.gz"), "KEV"},
		{u("/kev.json"), u("/missing"), "404"},
		{u("/kev.json"), u("/plain"), "EPSS"},
		{u("/kev.json"), u("/nocols.gz"), "no cve/epss columns"},
		{u("/kev.json"), u("/short.gz"), "short row"},
		{u("/kev.json"), u("/nan.gz"), "EPSS"},
		{u("/kev.json"), u("/empty.gz"), "bad CSV"},
		{u("/kev.json"), u("/quote.gz"), "bad CSV"},
		{"http://bad host/", u("/epss.csv.gz"), "invalid"},
		{"http://127.0.0.1:1/kev.json", u("/epss.csv.gz"), "refused"},
	}
	for _, c := range cases {
		_, err := UpdateFeeds(context.Background(), &Policy{KEVURL: c.kev, EPSSURL: c.epss})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s: %v, want %q", c.kev, c.epss, err, c.want)
		}
	}
	// not gzip, or nowhere to write: the IP DB is skipped, the rest goes on
	if err := download(context.Background(), u("/dbip-city-x.mmdb.gz"), filepath.Join(t.TempDir(), "x"), nil); err == nil {
		t.Fatal("not gzip accepted")
	}
	if err := download(context.Background(), u("/epss.csv.gz"), filepath.Join(t.TempDir(), "no", "x"), nil); err == nil {
		t.Fatal("missing dir accepted")
	}

	// the feeds dir can't be made, or a file in it can't be written
	blocker := filepath.Join(t.TempDir(), "file")
	must(t, os.WriteFile(blocker, nil, 0o600))
	t.Setenv("KANAREIKA_FEEDS_DIR", blocker)
	if _, err := UpdateFeeds(context.Background(), &Policy{KEVURL: u("/kev.json"), EPSSURL: u("/epss.csv.gz")}); err == nil {
		t.Fatal("feeds dir is a file")
	}
	if err := writeFile(filepath.Join(blocker, "x"), nil); err == nil {
		t.Fatal("write under a file")
	}
}

// TestIdleTimeout: a download may be long but must keep flowing; a stalled one is cut.
func TestIdleTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("first"))
		w.(http.Flusher).Flush()
		<-release
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	r, err := get(context.Background(), srv.URL, 50*time.Millisecond)
	must(t, err)
	defer r.Close()
	buf := make([]byte, 5)
	if _, err := r.Read(buf); err != nil || string(buf) != "first" {
		t.Fatal(err, string(buf))
	}
	if _, err := r.Read(buf); !errors.Is(err, context.Canceled) {
		t.Fatalf("stalled read: %v", err)
	}
}

func TestFeedsDirDefault(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", "")
	if d := FeedsDir(); !strings.HasSuffix(d, filepath.Join("kanareika", "feeds")) {
		t.Fatal(d)
	}
}

// TestLoadFeedsPartial: each file may be missing (an older or interrupted update); broken ones are errors.
func TestLoadFeedsPartial(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KANAREIKA_FEEDS_DIR", dir)
	write := func(name, s string) { must(t, os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644)) }
	if f, err := LoadFeeds(); err != nil || len(f.KEV) != 0 {
		t.Fatal(f, err)
	}
	write("kev.json", `["CVE-1"]`)
	if f, err := LoadFeeds(); err != nil || !f.KEV["CVE-1"] || len(f.EPSS) != 0 {
		t.Fatal(f, err)
	}
	write("epss.json", `{"CVE-1": 0.3}`)
	if f, err := LoadFeeds(); err != nil || f.EPSS["CVE-1"] != 0.3 || f.Updated != "" {
		t.Fatal(f, err)
	}
	write("updated", "2026-11-07T00:00:00\n")
	if f, err := LoadFeeds(); err != nil || f.Updated != "2026-11-07T00:00:00" {
		t.Fatal(f, err)
	}
	for _, c := range [][2]string{{"epss.json", "["}, {"kev.json", "{"}} {
		write(c[0], c[1])
		if _, err := LoadFeeds(); err == nil || !strings.Contains(err.Error(), c[0]) {
			t.Fatalf("%s: %v", c[0], err)
		}
	}
	for _, name := range []string{"kev.json", "epss.json", "updated"} { // a directory where a file should be
		d := t.TempDir()
		t.Setenv("KANAREIKA_FEEDS_DIR", d)
		if name != "kev.json" {
			must(t, os.WriteFile(filepath.Join(d, "kev.json"), []byte(`[]`), 0o644))
		}
		if name == "updated" {
			must(t, os.WriteFile(filepath.Join(d, "epss.json"), []byte(`{}`), 0o644))
		}
		must(t, os.Mkdir(filepath.Join(d, name), 0o755))
		if _, err := LoadFeeds(); err == nil {
			t.Fatalf("%s as a directory", name)
		}
	}
}

func TestTruthy(t *testing.T) {
	for v, want := range map[any]bool{nil: false, true: true, false: false, "": false, "x": true, 0.0: false, 2.0: true, 3: true} {
		if truthy(v) != want {
			t.Errorf("%#v", v)
		}
	}
	if truthy([]any{}) || !truthy([]any{1}) || truthy(map[string]any{}) || !truthy(map[string]any{"a": 1}) {
		t.Fatal("collections")
	}
}

func TestUserAgentVersion(t *testing.T) {
	old := UserAgent
	t.Cleanup(func() { UserAgent = old })
	SetVersion("v0.3.0")
	if UserAgent != "github.com/mikekosulin/kanareika/0.3.0 (+vulnerability audit)" {
		t.Fatal(UserAgent)
	}
}
