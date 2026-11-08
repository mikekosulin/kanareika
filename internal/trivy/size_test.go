package trivy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDownloadSize: the layer sizes from the manifest, after the anonymous token dance ghcr.io wants; a registry
// that fails is skipped for the next one.
func TestDownloadSize(t *testing.T) {
	var reg *httptest.Server
	reg = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			if r.URL.Query().Get("scope") != "repository:a/trivy-db:pull" && r.URL.Query().Get("scope") != "repository:a/trivy-java-db:pull" {
				http.Error(w, "scope", 400)
				return
			}
			fmt.Fprint(w, `{"token":"t0k"}`)
		case strings.HasPrefix(r.URL.Path, "/v2/broken/"):
			http.Error(w, "nope", 500)
		case r.Header.Get("Authorization") != "Bearer t0k":
			name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/"), "/manifests/2")
			name = strings.TrimSuffix(name, "/manifests/1")
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="x",scope="repository:%s:pull"`, reg.URL, name))
			w.WriteHeader(401)
		case strings.Contains(r.URL.Path, "java"):
			fmt.Fprint(w, `{"layers":[{"size":996500000}]}`)
		default:
			fmt.Fprint(w, `{"layers":[{"size":138600000},{"size":400}]}`)
		}
	}))
	defer reg.Close()
	old := registryScheme
	registryScheme = "http"
	t.Cleanup(func() { registryScheme = old })
	host := strings.TrimPrefix(reg.URL, "http://")
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", host+"/broken/x:2,"+host+"/a/trivy-db:2")
	t.Setenv("KANAREIKA_TRIVY_JAVA_DB_REPOS", host+"/a/trivy-java-db:1")
	got := DownloadSize(context.Background())
	if got["db"] != 138600400 || got["java-db"] != 996500000 {
		t.Errorf("%v", got)
	}
}
