package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/dbget"
)

// registryScheme: tests point it at a plain-HTTP registry.
var registryScheme = "https"

// DownloadSize: bytes the next download of each DB would take ("db", "java-db"), read from the registry's manifest
// (a few KB, nothing is downloaded). A DB whose size could not be read is missing from the map.
func DownloadSize(ctx context.Context) map[string]int64 {
	out := map[string]int64{}
	for _, k := range dbKinds {
		repos := k.repositories()
		if repos == nil {
			repos = k.repos
		}
		for _, r := range repos {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			n, err := manifestSize(ctx, r)
			cancel()
			if err == nil {
				out[k.name] = n
				break
			}
		}
	}
	return out
}

// manifestSize: the summed layer size of an OCI image ("ghcr.io/aquasecurity/trivy-db:2").
func manifestSize(ctx context.Context, ref string) (int64, error) {
	r, err := parseRef(ref)
	if err != nil {
		return 0, err
	}
	m, err := r.manifest(ctx)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, l := range m.Layers {
		n += l.Size
	}
	if n == 0 {
		return 0, errors.New(ref + ": no layers")
	}
	return n, nil
}

// repo: an OCI repository and tag, with the anonymous pull token once the registry asked for one.
type repo struct {
	host, name, tag string
	token           string
}

func parseRef(ref string) (*repo, error) {
	host, rest, ok := strings.Cut(ref, "/")
	if !ok || rest == "" {
		return nil, fmt.Errorf("%s: not host/name:tag", ref)
	}
	name, tag, ok := strings.Cut(rest, ":")
	if !ok {
		tag = "latest"
	}
	return &repo{host: host, name: name, tag: tag}, nil
}

type ociLayer struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
}

type ociManifest struct {
	Layers []ociLayer `json:"layers"`
}

// get: GET path under /v2/<name>/ with the pull token, fetching one when the registry answers 401.
func (r *repo) get(ctx context.Context, path, accept string) (*http.Response, error) {
	u := fmt.Sprintf("%s://%s/v2/%s/%s", registryScheme, r.host, r.name, path)
	do := func() (*http.Response, error) {
		h := http.Header{}
		if accept != "" {
			h.Set("Accept", accept)
		}
		if r.token != "" {
			h.Set("Authorization", "Bearer "+r.token)
		}
		return dbget.Get(ctx, u, h)
	}
	resp, err := do()
	var se *dbget.StatusError
	if errors.As(err, &se) && se.Code == http.StatusUnauthorized && r.token == "" && se.Challenge != "" {
		if r.token, err = anonToken(ctx, se.Challenge); err != nil {
			return nil, err
		}
		resp, err = do()
	}
	return resp, err
}

// manifest: the image manifest of the tag.
func (r *repo) manifest(ctx context.Context) (ociManifest, error) {
	var m ociManifest
	resp, err := r.get(ctx, "manifests/"+r.tag,
		"application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return m, fmt.Errorf("manifest: %w", err)
	}
	return m, nil
}

// anonToken: the token a registry hands out for anonymous pulls (Bearer realm="…",service="…",scope="…").
func anonToken(ctx context.Context, challenge string) (string, error) {
	scheme, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", errors.New("registry asks for " + scheme + " auth")
	}
	p := map[string]string{}
	for _, kv := range strings.Split(params, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
		p[k] = strings.Trim(v, `"`)
	}
	if p["realm"] == "" {
		return "", errors.New("registry gave no token realm")
	}
	u, err := url.Parse(p["realm"])
	if err != nil {
		return "", fmt.Errorf("token realm: %w", err)
	}
	q := u.Query()
	for _, k := range []string{"service", "scope"} {
		if p[k] != "" {
			q.Set(k, p[k])
		}
	}
	u.RawQuery = q.Encode()
	resp, err := dbget.Get(ctx, u.String(), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	if t.Token == "" {
		t.Token = t.AccessToken
	}
	return t.Token, nil
}
