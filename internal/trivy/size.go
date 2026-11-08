package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
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

// manifestSize: the summed layer size of an OCI image ("ghcr.io/aquasecurity/trivy-db:2"), with an anonymous
// token when the registry asks for one.
func manifestSize(ctx context.Context, ref string) (int64, error) {
	host, rest, ok := strings.Cut(ref, "/")
	if !ok {
		return 0, fmt.Errorf("%s: not host/name:tag", ref)
	}
	name, tag, ok := strings.Cut(rest, ":")
	if !ok {
		tag = "latest"
	}
	url := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", registryScheme, host, name, tag)
	get := func(token string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return http.DefaultClient.Do(req)
	}
	resp, err := get("")
	if err != nil {
		return 0, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		tok, err := anonToken(ctx, resp.Header.Get("WWW-Authenticate"))
		if err != nil {
			return 0, err
		}
		if resp, err = get(tok); err != nil {
			return 0, err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s: %s", ref, resp.Status)
	}
	var m struct {
		Layers []struct {
			Size int64 `json:"size"`
		} `json:"layers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p["realm"], nil)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	for _, k := range []string{"service", "scope"} {
		if p[k] != "" {
			q.Set(k, p[k])
		}
	}
	req.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("token: " + resp.Status)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return "", err
	}
	if t.Token == "" {
		t.Token = t.AccessToken
	}
	return t.Token, nil
}
