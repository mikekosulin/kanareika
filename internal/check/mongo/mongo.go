// Package mongo: MongoDB version and listen addresses. CVEs for mongod come from os_packages / docker images.
package mongo

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

const (
	CmdVersion = "mongod --version 2>/dev/null | head -1 || true"
	CmdListen  = "ss -Hltn 2>/dev/null | awk '{print $4}'"
)

var reVersion = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)

// Run is the module; both outputs are kept as mongo.txt.
func Run(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, facts check.Facts) ([]finding.Finding, error) {
	ver, err := ctx.SSH.Run(ctx, h, CmdVersion, 300*time.Second, false)
	if err != nil {
		return nil, err
	}
	ver = pyfmt.Strip(ver)
	listen, err := ctx.SSH.Run(ctx, h, CmdListen, 300*time.Second, false)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(out, "mongo.txt"), []byte(ver+"\n---\n"+listen), 0o644); err != nil {
		return nil, err
	}
	return analyze(h, ver, listen), nil
}

func analyze(h config.Host, ver, listen string) []finding.Finding {
	var f []finding.Finding
	if m := reVersion.FindStringSubmatch(ver); m != nil {
		x := check.Base(h, "mongo")
		x.Kind, x.ID, x.Pkg, x.Installed, x.Severity = finding.Inventory, "mongod", "mongod", m[1], "INFO"
		x.Title, x.Target = "MongoDB server version", "mongod"
		f = append(f, x)
	}
	for _, addr := range pyfmt.Fields(listen) {
		if !strings.HasSuffix(addr, ":27017") {
			continue
		}
		switch addr[:strings.LastIndex(addr, ":")] {
		case "0.0.0.0", "*", "[::]":
			sev := "HIGH"
			if h.Exposure > 1 {
				sev = "MEDIUM"
			}
			f = append(f, check.Misconfig(h, "mongo", "mongo-listen-all", sev, i18n.Msg("mongo.listen_all", nil),
				i18n.Plain(addr)))
		}
	}
	return f
}
