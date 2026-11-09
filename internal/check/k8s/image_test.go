package k8s

import (
	"testing"

	"github.com/mikekosulin/kanareika/internal/trivy"
)

// TestImageOf: the workload's image from the OS result's target; language results and bare names don't count.
func TestImageOf(t *testing.T) {
	for want, rs := range map[string][]trivy.Result{
		"registry.example.com/app:1.2":           {{Target: "Java"}, {Target: "registry.example.com/app:1.2 (ubuntu 22.04)"}},
		"nginx@sha256:0123":                      {{Target: "nginx@sha256:0123 (alpine 3.20)"}},
		"":                                       {{Target: "Java"}, {Target: "Python"}},
		"registry.k8s.io/ingress-nginx/c:v1.9.4": {{Target: "registry.k8s.io/ingress-nginx/c:v1.9.4 (alpine 3.18.4)"}},
	} {
		if got := imageOf(rs); got != want {
			t.Errorf("%v: %q, want %q", rs, got, want)
		}
	}
	if imageOf(nil) != "" || imageOf([]trivy.Result{{Target: "something (else)"}}) != "" {
		t.Error("no image")
	}
}
