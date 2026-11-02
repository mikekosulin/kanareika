// Package hardening: patch-related host state — pending reboot, uptime. SSH settings live in package access.
package hardening

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/check/health"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
)

// Script: no privileged ops, so it is not rendered.
const Script = `
export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"  # non-login SSH shells on RHEL 7 lack sbin
echo "kernel=$(uname -r)"
[ -f /var/run/reboot-required ] && echo reboot_required=yes
command -v needs-restarting >/dev/null 2>&1 && { needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ] && echo reboot_required=yes; }
k=$(rpm -q --last kernel 2>/dev/null | head -1 | awk '{print $1}'); [ -n "$k" ] && [ "${k#kernel-}" != "$(uname -r)" ] && echo reboot_required=yes
echo "uptime_days=$(awk '{print int($1/86400)}' /proc/uptime)"
`

var reUptime = regexp.MustCompile(`uptime_days=(\d+)`)

// Run is the module; the raw output is kept as hardening.txt.
func Run(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, facts check.Facts) ([]finding.Finding, error) {
	raw, err := ctx.SSH.Run(ctx, h, "sh -c "+health.Quote(Script), 300*time.Second, false)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(out, "hardening.txt"), []byte(raw), 0o644); err != nil {
		return nil, err
	}
	return analyze(h, raw), nil
}

func analyze(h config.Host, raw string) []finding.Finding {
	var f []finding.Finding
	if strings.Contains(raw, "reboot_required=yes") {
		f = append(f, check.Misconfig(h, "hardening", "reboot-required", "MEDIUM", i18n.Msg("hardening.reboot", nil),
			i18n.Plain("")))
	}
	if m := reUptime.FindStringSubmatch(raw); m != nil {
		if days, err := strconv.Atoi(m[1]); err == nil && days > 180 {
			f = append(f, check.Misconfig(h, "hardening", "long-uptime", "LOW", i18n.Msg("hardening.uptime", nil),
				i18n.Msg("hardening.uptime.detail", map[string]any{"days": m[1]})))
		}
	}
	return f
}
