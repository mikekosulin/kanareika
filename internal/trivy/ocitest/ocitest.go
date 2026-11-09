// Package ocitest: a registry as ghcr.io serves trivy's DBs (anonymous token, OCI manifest, blobs), for tests of
// the downloads without the network.
package ocitest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/dbget"
)

// ModTime: the time stamped on the files of a Layer.
var ModTime = time.Date(2026, 11, 8, 6, 0, 0, 0, time.UTC)

// Layer: a tar.gz of files (mode 0644, ModTime), in name order.
func Layer(files map[string][]byte) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), ModTime: ModTime, Typeflag: tar.TypeReg})
		_, _ = tw.Write(files[n])
	}
	_ = tw.Close()
	_ = gz.Close()
	return b.Bytes()
}

// Metadata: a metadata.json as trivy-db publishes it (no DownloadedAt yet).
func Metadata(version int, next, updated time.Time) []byte {
	b, _ := json.Marshal(map[string]any{"Version": version, "NextUpdate": next, "UpdatedAt": updated, "DownloadedAt": time.Time{}})
	return b
}

// Digest: "sha256:<hex>" of b.
func Digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// Registry: a TLS registry; Push adds artifacts; Fail answers a status instead; Corrupt serves altered blobs.
type Registry struct {
	*httptest.Server
	mu        sync.Mutex
	manifests map[string][]byte // "<name>:<tag>"
	blobs     map[string][]byte
	// Fail: a status for every request (0: serve normally), e.g. 429
	Fail int
	// Corrupt: blobs are served with their first byte changed
	Corrupt bool
	// Pad: blobs are served with this many zero bytes more than the manifest says
	Pad int
	// NoChallenge: a 401 without a WWW-Authenticate (a private repository)
	NoChallenge bool
	// Requests: method, path and the request headers' names, for checking what is sent
	Requests []Request
}

// Request: what a client sent.
type Request struct {
	Path    string
	Headers []string // canonical names
	UA      string
}

// New: a registry closed with the test; dbget trusts its certificate while the test runs.
func New(t testing.TB) *Registry {
	r := &Registry{manifests: map[string][]byte{}, blobs: map[string][]byte{}}
	r.Server = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	old := dbget.Transport
	dbget.Transport = r.Client().Transport
	t.Cleanup(func() { dbget.Transport = old; r.Close() })
	return r
}

// Host: host:port, as a repository reference starts.
func (r *Registry) Host() string { return strings.TrimPrefix(r.URL, "https://") }

// Push: name:tag as a single-layer artifact of mediaType; the reference ("host:port/name:tag").
func (r *Registry) Push(name, tag, mediaType string, layer []byte) string {
	m := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"mediaType": "application/vnd.aquasec.trivy.config.v1+json", "digest": Digest([]byte("{}")), "size": 2},
		"layers": []map[string]any{{"mediaType": mediaType, "digest": Digest(layer), "size": len(layer),
			"annotations": map[string]string{"org.opencontainers.image.title": "db.tar.gz"}}},
	}
	b, _ := json.Marshal(m)
	r.mu.Lock()
	r.manifests[name+":"+tag] = b
	r.blobs[Digest(layer)] = layer
	r.mu.Unlock()
	return r.Host() + "/" + name + ":" + tag
}

// Paths: the paths requested, in order.
func (r *Registry) Paths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, q := range r.Requests {
		out = append(out, q.Path)
	}
	return out
}

func (r *Registry) serve(w http.ResponseWriter, q *http.Request) {
	var names []string
	for k := range q.Header {
		names = append(names, k)
	}
	sort.Strings(names)
	r.mu.Lock()
	r.Requests = append(r.Requests, Request{q.URL.Path, names, q.UserAgent()})
	fail, corrupt, noChallenge, pad := r.Fail, r.Corrupt, r.NoChallenge, r.Pad
	r.mu.Unlock()
	if fail != 0 {
		w.WriteHeader(fail)
		return
	}
	if q.URL.Path == "/token" {
		fmt.Fprint(w, `{"token":"t0k"}`)
		return
	}
	rest, ok := strings.CutPrefix(q.URL.Path, "/v2/")
	if !ok {
		http.NotFound(w, q)
		return
	}
	if q.Header.Get("Authorization") != "Bearer t0k" {
		if !noChallenge {
			name, _, _ := strings.Cut(rest, "/manifests/")
			name, _, _ = strings.Cut(name, "/blobs/")
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test",scope="repository:%s:pull"`, r.URL, name))
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if name, tag, ok := strings.Cut(rest, "/manifests/"); ok {
		m, ok := r.manifests[name+":"+tag]
		if !ok {
			http.NotFound(w, q)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		_, _ = w.Write(m)
		return
	}
	if _, digest, ok := strings.Cut(rest, "/blobs/"); ok {
		b, ok := r.blobs[digest]
		if !ok {
			http.NotFound(w, q)
			return
		}
		if corrupt {
			b = append([]byte{b[0] ^ 0xff}, b[1:]...)
		}
		if pad > 0 {
			b = append(slices.Clip(b), make([]byte, pad)...)
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		_, _ = w.Write(b)
		return
	}
	http.NotFound(w, q)
}
