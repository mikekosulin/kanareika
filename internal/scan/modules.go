package scan

import (
	"encoding/json"
	"os"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/check/access"
	"github.com/mikekosulin/kanareika/internal/check/docker"
	"github.com/mikekosulin/kanareika/internal/check/exposure"
	"github.com/mikekosulin/kanareika/internal/check/hardening"
	"github.com/mikekosulin/kanareika/internal/check/health"
	"github.com/mikekosulin/kanareika/internal/check/k8s"
	"github.com/mikekosulin/kanareika/internal/check/mongo"
	"github.com/mikekosulin/kanareika/internal/check/network"
	"github.com/mikekosulin/kanareika/internal/check/ospkg"
	"github.com/mikekosulin/kanareika/internal/check/softwarefs"
	"github.com/mikekosulin/kanareika/internal/check/swarm"
	"github.com/mikekosulin/kanareika/internal/finding"
)

// HostModules: module name (as in orgs/*.yml checks) -> implementation. nil = configurable but not implemented.
var HostModules = map[string]check.Func{
	"os_packages":      ospkg.Run,
	"software_fs":      softwarefs.Run,
	"docker":           docker.Run,
	"health":           health.Run,
	"access":           access.Run,
	"exposure":         exposure.Run,
	"hardening":        hardening.Run,
	"swarm":            swarm.Run,
	"mongo":            mongo.Run,
	"network_internal": nil, // not implemented yet, see docs/org-file.md
}

// OrgFunc: an org-level module (once per org/env, not per host).
type OrgFunc func(ctx *check.Ctx, cfg map[string]any, env string) ([]finding.Finding, error)

var OrgModules = map[string]OrgFunc{
	"network_external": network.RunExternal,
	"k8s":              k8s.Run,
}

// writeJSON as json.dumps(indent=1) did; errors are ignored like the other per-host side files.
func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", " ")
	if err == nil {
		_ = os.WriteFile(path, b, 0o644)
	}
}
