package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mikekosulin/kanareika/internal/dbget"
	"github.com/mikekosulin/kanareika/internal/trivy/ocitest"
)

// quirky: a plain-HTTP registry whose repositories each misbehave in their own way (see serve). cancel, when set,
// is called by the "cancel" repository before it answers.
type quirky struct {
	*httptest.Server
	layer  []byte
	mu     sync.Mutex
	paths  []string
	cancel context.CancelFunc
}

func newQuirky(t *testing.T, layer []byte) *quirky {
	t.Helper()
	q := &quirky{layer: layer}
	q.Server = httptest.NewServer(http.HandlerFunc(q.serve))
	t.Cleanup(q.Close)
	old := registryScheme
	registryScheme = "http"
	t.Cleanup(func() { registryScheme = old })
	return q
}

// host: host:port, as a repository reference starts.
func (q *quirky) host() string { return strings.TrimPrefix(q.URL, "http://") }

// requested: the paths asked for, with their queries.
func (q *quirky) requested() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return slices.Clone(q.paths)
}

// manifest: an OCI manifest of trivy-db layers, digested as given ("": their own digests).
func manifest(digest string, layers ...[]byte) string {
	ls := []map[string]any{}
	for _, l := range layers {
		d := digest
		if d == "" {
			d = ocitest.Digest(l)
		}
		ls = append(ls, map[string]any{"mediaType": dbKinds[0].mediaType, "digest": d, "size": len(l)})
	}
	b, _ := json.Marshal(map[string]any{"schemaVersion": 2, "layers": ls})
	return string(b)
}

func (q *quirky) serve(w http.ResponseWriter, r *http.Request) {
	q.mu.Lock()
	q.paths = append(q.paths, r.URL.RequestURI())
	cancel := q.cancel
	q.mu.Unlock()
	// the token endpoints a challenge points to
	if tok, ok := strings.CutPrefix(r.URL.Path, "/token/"); ok {
		switch tok {
		case "down":
			w.WriteHeader(http.StatusInternalServerError)
		case "junk":
			fmt.Fprint(w, "not json")
		case "access": // as Docker Hub answers: access_token, no token
			fmt.Fprint(w, `{"access_token":"a0k"}`)
		}
		return
	}
	rest, _ := strings.CutPrefix(r.URL.Path, "/v2/")
	repo, _, _ := strings.Cut(rest, "/")
	challenge := func(c string) {
		w.Header().Set("WWW-Authenticate", c)
		w.WriteHeader(http.StatusUnauthorized)
	}
	blob := strings.Contains(r.URL.Path, "/blobs/")
	switch repo {
	case "basic":
		challenge(`Basic realm="registry"`)
	case "norealm":
		challenge(`Bearer service="registry"`)
	case "badrealm":
		challenge(`Bearer realm="::"`)
	case "tokendown":
		challenge(`Bearer realm="` + q.URL + `/token/down"`)
	case "tokenjunk":
		challenge(`Bearer realm="` + q.URL + `/token/junk"`)
	case "access":
		if r.Header.Get("Authorization") != "Bearer a0k" {
			challenge(`Bearer realm="` + q.URL + `/token/access",service="registry",scope="repository:access/db:pull"`)
			return
		}
		if blob {
			_, _ = w.Write(q.layer)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/manifests/latest") {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, manifest("", q.layer))
	case "junk":
		fmt.Fprint(w, "not json")
	case "empty":
		fmt.Fprint(w, manifest(""))
	case "two":
		fmt.Fprint(w, manifest("", q.layer, q.layer))
	case "md5":
		fmt.Fprint(w, manifest("md5:0123456789abcdef", q.layer))
	case "noblob":
		if blob {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, manifest("", q.layer))
	case "short": // the connection closes before the blob is whole
		if blob {
			w.Header().Set("Content-Length", fmt.Sprint(len(q.layer)))
			_, _ = w.Write(q.layer[:len(q.layer)/2])
			return
		}
		fmt.Fprint(w, manifest("", q.layer))
	case "cancel": // the user presses Ctrl-C while the registry thinks
		if cancel != nil {
			cancel()
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		http.NotFound(w, r)
	}
}

// TestMirrorReasons: each way a registry can refuse or break a download is named in the error, mirror by mirror,
// in the order tried; nothing of the attempts is left in the cache.
func TestMirrorReasons(t *testing.T) {
	cache := fetchEnv(t)
	q := newQuirky(t, dbLayer(t))
	h := q.host()
	cases := []struct{ ref, reason string }{ // the reason after "<host>: "
		{"nohost", "nohost: not host/name:tag"},
		{h + "/basic/db:2", "registry asks for Basic auth"},
		{h + "/norealm/db:2", "registry gave no token realm"},
		{h + "/badrealm/db:2", "missing protocol scheme"},
		{h + "/tokendown/db:2", "server error (500)"},
		{h + "/tokenjunk/db:2", "token: invalid character"},
		{h + "/junk/db:2", "manifest: invalid character"},
		{h + "/empty/db:2", "0 layers, expected one"},
		{h + "/two/db:2", "2 layers, expected one"},
		{h + "/md5/db:2", `unexpected layer digest "md5:0123456789abcdef"`},
		{h + "/noblob/db:2", "not found (404)"},
		{h + "/short/db:2", "connection closed mid-download"},
	}
	var refs []string
	for _, c := range cases {
		refs = append(refs, c.ref)
	}
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", strings.Join(refs, ","))
	it, err := runJob(t, "db")
	var me *MirrorError
	if !errors.As(err, &me) || it.State != dbget.Failed || len(me.Fails) != len(cases) {
		t.Fatalf("%+v %v", it, err)
	}
	for i, c := range cases {
		if !strings.HasPrefix(me.Fails[i], hostOf(c.ref)+": ") || !strings.Contains(me.Fails[i], c.reason) {
			t.Errorf("%s: %q, want %q", c.ref, me.Fails[i], c.reason)
		}
	}
	if err.Error() != "trivy db: no mirror worked: "+strings.Join(me.Fails, "; ") {
		t.Fatal(err.Error())
	}
	if ents, _ := os.ReadDir(cache); len(ents) != 0 {
		t.Fatalf("leftovers: %v", ents)
	}
}

// TestAccessToken: a registry that hands out access_token (Docker Hub's field) instead of token works; a reference
// without a tag asks for "latest".
func TestAccessToken(t *testing.T) {
	cache := fetchEnv(t)
	q := newQuirky(t, dbLayer(t))
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", q.host()+"/access/db")
	if it, err := runJob(t, "db"); err != nil || it.State != dbget.Done {
		t.Fatalf("%+v %v", it, err)
	}
	if _, err := os.Stat(filepath.Join(cache, "db", "trivy.db")); err != nil {
		t.Fatal(err)
	}
	want := []string{"/v2/access/db/manifests/latest", "/token/access?scope=repository%3Aaccess%2Fdb%3Apull&service=registry",
		"/v2/access/db/manifests/latest"}
	if got := q.requested(); len(got) < 4 || !slices.Equal(got[:3], want) || !strings.HasPrefix(got[3], "/v2/access/db/blobs/sha256:") {
		t.Fatal(got)
	}
}

// TestFetchCancelled: Ctrl-C during a download returns the cancellation as it is: no other mirror is tried, the
// cached copy is not offered as "kept", and the next attempt is not held back as a remembered failure.
func TestFetchCancelled(t *testing.T) {
	cache := fetchEnv(t)
	q := newQuirky(t, dbLayer(t))
	// a copy trivy would download again (past NextUpdate and the hour)
	must(t, os.MkdirAll(filepath.Join(cache, "db"), 0o755))
	must(t, os.WriteFile(filepath.Join(cache, "db", "trivy.db"), []byte("x"), 0o644))
	must(t, os.WriteFile(filepath.Join(cache, "db", "metadata.json"),
		[]byte(`{"Version":2,"NextUpdate":"2026-11-08T00:00:00Z","UpdatedAt":"2026-11-07T00:00:00Z","DownloadedAt":"2026-11-07T01:00:00Z"}`), 0o644))
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", q.host()+"/cancel/db:2,"+q.host()+"/access/db")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.mu.Lock()
	q.cancel = cancel
	q.mu.Unlock()
	tr := dbget.NewTracker()
	err := tr.Run(ctx, []dbget.Job{Job("db", nil)})["db"]
	var kept *dbget.KeptError
	if !errors.Is(err, context.Canceled) || errors.As(err, &kept) || tr.Snapshot().Items[0].Note != "cancelled" {
		t.Fatal(err, tr.Snapshot().Items[0])
	}
	if got := q.requested(); !slices.Equal(got, []string{"/v2/cancel/db/manifests/2"}) {
		t.Fatal("another mirror tried after Ctrl-C:", got)
	}
	failMu.Lock()
	_, remembered := failed["db"]
	failMu.Unlock()
	if remembered {
		t.Fatal("a cancelled download remembered as a failure")
	}
}

// roundTrip: an http.RoundTripper from a function.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestDownloadSizeQuirks: a reference that is not one, a registry asking for credentials, a manifest without layers
// or with an access_token: the size comes from the first repository that tells it.
func TestDownloadSizeQuirks(t *testing.T) {
	q := newQuirky(t, []byte("0123456789"))
	h := q.host()
	t.Setenv("TRIVY_DB_REPOSITORY", "")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "")
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", "nohost,"+h+"/basic/db:2,"+h+"/empty/db:2,"+h+"/junk/db:2,"+h+"/access/db")
	t.Setenv("KANAREIKA_TRIVY_JAVA_DB_REPOS", "nohost,"+h+"/empty/db:1")
	got := DownloadSize(context.Background())
	if got["db"] != 10 || len(got) != 1 {
		t.Fatal(got)
	}
	if _, err := manifestSize(context.Background(), h+"/empty/db:1"); err == nil || err.Error() != h+"/empty/db:1: no layers" {
		t.Fatal(err)
	}
}

// TestDownloadSizeTrivysRepos: with trivy's own repository setting (TRIVY_DB_REPOSITORY), which trivy reads and
// kanareika does not, the size is the one of the default repositories, GitHub's first.
func TestDownloadSizeTrivysRepos(t *testing.T) {
	t.Setenv("TRIVY_DB_REPOSITORY", "registry.example/mirror/trivy-db:2")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "registry.example/mirror/trivy-java-db:1")
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", "registry.example/ours/trivy-db:2")
	var mu sync.Mutex
	var asked []string
	old := dbget.Transport
	t.Cleanup(func() { dbget.Transport = old })
	dbget.Transport = roundTrip(func(r *http.Request) (*http.Response, error) { // no network: every registry is this one
		mu.Lock()
		asked = append(asked, r.URL.String())
		mu.Unlock()
		size := 7
		if strings.Contains(r.URL.Path, "java") {
			size = 9
		}
		body := fmt.Sprintf(`{"layers":[{"size":%d}]}`, size)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader([]byte(body))), Request: r}, nil
	})
	got := DownloadSize(context.Background())
	if got["db"] != 7 || got["java-db"] != 9 {
		t.Fatal(got)
	}
	want := []string{"https://ghcr.io/v2/aquasecurity/trivy-db/manifests/2", "https://ghcr.io/v2/aquasecurity/trivy-java-db/manifests/1"}
	if !slices.Equal(asked, want) {
		t.Fatal(asked)
	}
}
