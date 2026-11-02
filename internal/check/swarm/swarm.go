// Package swarm: Swarm managers — cluster inventory (nodes, services). Images are covered by the docker module.
package swarm

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/priv"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

func run(ctx *check.Ctx, h config.Host, op string) (string, error) {
	c, err := priv.Cmd(h.Privilege, op, false)
	if err != nil {
		return "", err
	}
	return ctx.SSH.Run(ctx, h, c, 300*time.Second, true)
}

// lines: one JSON document per non-blank line (docker --format '{{json .}}'), key order kept.
func lines(text string) ([]any, error) {
	out := []any{}
	for _, x := range pyfmt.SplitLines(text) {
		if pyfmt.Strip(x) == "" {
			continue
		}
		v, err := pyfmt.Loads(x)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Run is the module: swarm.json with docker's own JSON (written as docker printed it) plus one inventory finding
// per node.
func Run(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, facts check.Facts) ([]finding.Finding, error) {
	raw, err := run(ctx, h, "swarm-info")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		raw = "{}"
	}
	v, err := pyfmt.Loads(raw)
	if err != nil {
		return nil, err
	}
	info, ok := v.(pyfmt.Obj)
	if !ok {
		return nil, fmt.Errorf("docker info: not a JSON object")
	}
	if !pyfmt.Truthy(info.Get("ControlAvailable")) {
		return nil, errors.New("host is not a swarm manager (docker info: ControlAvailable=false)")
	}
	nodesRaw, err := run(ctx, h, "swarm-nodes")
	if err != nil {
		return nil, err
	}
	servicesRaw, err := run(ctx, h, "swarm-services")
	if err != nil {
		return nil, err
	}
	nodes, err := lines(nodesRaw)
	if err != nil {
		return nil, err
	}
	services, err := lines(servicesRaw)
	if err != nil {
		return nil, err
	}
	if err := pyfmt.WriteJSON(filepath.Join(out, "swarm.json"), pyfmt.O("swarm", info, "nodes", nodes, "services", services), true); err != nil {
		return nil, err
	}
	ctx.Log("%s: swarm: %d nodes, %d services", h.Name, len(nodes), len(services))
	var f []finding.Finding
	for _, n := range nodes {
		o, _ := n.(pyfmt.Obj)
		x := check.Base(h, "swarm")
		x.Kind, x.ID, x.Severity, x.Title, x.Target = finding.Inventory, "swarm-node", "INFO", "Swarm node", "swarm"
		x.Pkg, _ = o.Get("Hostname").(string)
		x.Installed, _ = o.Get("EngineVersion").(string)
		x.Status, _ = o.Get("Status").(string)
		f = append(f, x)
	}
	return f, nil
}
