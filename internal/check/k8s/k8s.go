// Package k8s is the org-level k8s module: `trivy k8s` per cluster of the environment, with the org's kubeconfig
// from secrets/, limited to the namespaces in scope. Read-only: trivy's node-collector jobs are disabled.
package k8s

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// trivyRun is trivy.Run; tests swap it for recorded reports.
var trivyRun = trivy.Run

// report: the part of a `trivy k8s --report all` JSON kanareika reads. Each resource carries ordinary trivy
// Results (one per container image / layer).
type report struct {
	Resources []resource `json:"Resources"`
}

// resource keeps the raw keys: an absent Namespace and a null one print differently.
type resource map[string]json.RawMessage

// field: how Python's f"{res.get(k, def)}" prints a JSON value: def when absent, None for null.
func (r resource) field(k, def string) string {
	raw, ok := r[k]
	if !ok {
		return def
	}
	if string(raw) == "null" { // Unmarshal would leave a string empty
		return "None"
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func exposure(m map[string]any) int {
	switch v := m["exposure"].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 2
}

// imageOf: the image a resource runs, from its OS result's target ("registry/app:1.2 (ubuntu 22.04)"); "" when no
// result names one (language results are "Java", "Python", ...).
func imageOf(results []trivy.Result) string {
	for _, r := range results {
		if img, _, ok := strings.Cut(r.Target, " ("); ok && img != "" && strings.ContainsAny(img, ":/@") {
			return img
		}
	}
	return ""
}

// Args: the trivy command line for one cluster (the kubeconfig path resolved).
func Args(cl map[string]any, kubeconfig string) []string {
	args := []string{"k8s", "--kubeconfig", kubeconfig, "--scanners", "vuln", "--report", "all",
		"--disable-node-collector"} // read-only: don't schedule node-collector jobs in the cluster
	var ns []string
	if l, ok := cl["namespaces"].([]any); ok {
		for _, x := range l {
			ns = append(ns, fmt.Sprint(x))
		}
	} else if l, ok := cl["namespaces"].([]string); ok {
		ns = l
	}
	if len(ns) > 0 {
		args = append(args, "--include-namespaces", strings.Join(ns, ","))
	}
	if c := str(cl, "context"); c != "" {
		args = append(args, c)
	}
	return args
}

// Run is the org-level module for env (cfg: the org's k8s check settings, unused). Findings are on the pseudo-host
// "k8s:<cluster>"; raw reports go to <run>/k8s/<cluster>.json.gz. A cluster that can't be scanned (no kubeconfig,
// trivy error) is logged and skipped; a kubeconfig path escaping secrets/ is an error.
func Run(ctx *check.Ctx, cfg map[string]any, env string) ([]finding.Finding, error) {
	var findings []finding.Finding
	out := filepath.Join(ctx.RunDir, "k8s")
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	for _, cl := range ctx.Org.K8s(env) {
		name := str(cl, "name")
		kubeconfig, err := ctx.Org.Secret(str(cl, "kubeconfig"))
		if err != nil {
			return nil, err
		}
		if st, err := os.Stat(kubeconfig); kubeconfig == "" || err != nil || !st.Mode().IsRegular() {
			ctx.Log("k8s %s: kubeconfig not found: secrets/%s", name, str(cl, "kubeconfig"))
			continue
		}
		data, err := trivyRun(ctx, Args(cl, kubeconfig), filepath.Join(out, name+".json"), 2*time.Hour)
		var terr *trivy.Error
		if errors.As(err, &terr) {
			ctx.Log("k8s %s: %v", name, err)
			continue
		} else if err != nil {
			return nil, err
		}
		var r report
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("trivy k8s report: %w", err)
		}
		for _, res := range r.Resources {
			var results []trivy.Result
			if raw, ok := res["Results"]; ok {
				if err := json.Unmarshal(raw, &results); err != nil {
					return nil, fmt.Errorf("trivy k8s report: %w", err)
				}
			}
			base := finding.Finding{Org: ctx.Org.ID, Host: "k8s:" + name, Group: "k8s:" + name, Exposure: exposure(cl),
				Module: "k8s", Target: res.field("Namespace", "") + "/" + res.field("Kind", "None") + "/" + res.field("Name", "None"),
				Image: imageOf(results)}
			findings = append(findings, trivy.VulnFindings(&trivy.Report{Results: results}, base)...)
		}
		ctx.Log("k8s %s: %d resources", name, len(r.Resources))
	}
	return findings, nil
}
