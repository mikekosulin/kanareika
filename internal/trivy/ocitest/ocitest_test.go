package ocitest

import (
	"bytes"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// TestRegistryProtocol: the fake answers as ghcr.io does — a 401 with a token challenge naming the repository, the
// token, then the manifest and the blob it names — and 404 for whatever it does not hold or is not the registry
// API, so a client that asks for the wrong thing fails as it would against the real one.
func TestRegistryProtocol(t *testing.T) {
	r := New(t)
	layer := Layer(map[string][]byte{"trivy.db": []byte("db")})
	ref := r.Push("a/trivy-db", "2", "application/x-test", layer)
	if ref != r.Host()+"/a/trivy-db:2" {
		t.Fatal(ref)
	}
	type answer struct { // what a request got: the body is read and closed here
		code   int
		header http.Header
	}
	get := func(path, token string) (answer, []byte) {
		t.Helper()
		q, _ := http.NewRequest(http.MethodGet, r.URL+path, nil)
		if token != "" {
			q.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := r.Client().Do(q)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return answer{resp.StatusCode, resp.Header}, b
	}
	resp, _ := get("/v2/a/trivy-db/manifests/2", "")
	if c := resp.header.Get("WWW-Authenticate"); resp.code != 401 ||
		c != `Bearer realm="`+r.URL+`/token",service="test",scope="repository:a/trivy-db:pull"` {
		t.Fatal(resp.code, c)
	}
	if _, b := get("/token", ""); string(b) != `{"token":"t0k"}` {
		t.Fatal(string(b))
	}
	resp, m := get("/v2/a/trivy-db/manifests/2", "t0k")
	if resp.code != 200 || !strings.Contains(string(m), `"digest":"`+Digest(layer)+`"`) {
		t.Fatal(resp.code, string(m))
	}
	if resp, b := get("/v2/a/trivy-db/blobs/"+Digest(layer), "t0k"); resp.code != 200 || !bytes.Equal(b, layer) {
		t.Fatal(resp.code)
	}
	for _, p := range []string{"/v2/a/trivy-db/manifests/3", "/v2/a/trivy-db/blobs/" + Digest([]byte("other")), "/v2/a/trivy-db/tags/list", "/other"} {
		if resp, _ := get(p, "t0k"); resp.code != 404 {
			t.Errorf("%s: %d", p, resp.code)
		}
	}
	if got := r.Paths(); len(got) != 8 || got[0] != "/v2/a/trivy-db/manifests/2" || got[7] != "/other" {
		t.Fatal(got)
	}
	if h := r.Requests[2].Headers; !slices.Contains(h, "Authorization") {
		t.Fatal(h)
	}
}
