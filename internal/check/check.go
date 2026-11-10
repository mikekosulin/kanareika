// Package check defines what a host check (a "module") gets and returns. Each module lives in its own package
// under internal/check/<name> and exposes Run(ctx, host, cfg, out, facts) -> findings.
package check

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
)

// Runner executes read-only commands on a host over SSH (package sshx implements it).
type Runner interface {
	// Run a command; with check, a non-zero exit is an error (stderr tail in the message).
	Run(ctx context.Context, h config.Host, command string, timeout time.Duration, check bool) (string, error)
	// Stream stdout into w; aborts when it exceeds maxBytes. progress(mb) is called while data flows.
	Stream(ctx context.Context, h config.Host, command string, w io.Writer, maxBytes int64, timeout time.Duration,
		progress func(mb int64)) (int64, error)
}

// Ctx: what one scan run gives every module.
type Ctx struct {
	context.Context
	Org    *config.Org
	SSH    Runner
	RunDir string // reports/<org>/<env>/<run>
	Log    func(format string, args ...any)
	// shared across hosts of one org within a run (e.g. image id -> findings)
	Cache sync.Map
	// Sinks: host -> where the scan streams that host's findings. A module with many findings (a package scan)
	// passes them there one at a time instead of returning them, so they are never held. Set before the hosts
	// run, only read after; nil (tests, replays): modules return what they find.
	Sinks map[string]func(f *finding.Finding)
	// Spool: a directory for what a module shares across hosts and would otherwise hold for the whole run (an
	// image's findings); the scan removes it at the end. "": held in memory.
	Spool string
}

// Sink: where h's findings go one at a time; nil when they are returned.
func (c *Ctx) Sink(host string) func(f *finding.Finding) { return c.Sinks[host] }

// Facts collected before the modules run.
type Facts struct {
	OSRelease map[string]string `json:"os_release"`
	Uname     string            `json:"uname"`
	Hostname  string            `json:"hostname"`
}

// Func is a module: findings for one host. out is reports/.../hosts/<host>/ for raw outputs and module JSON.
type Func func(ctx *Ctx, h config.Host, cfg map[string]any, out string, facts Facts) ([]finding.Finding, error)

// Base: the "where" part of every finding of a host.
func Base(h config.Host, module string) finding.Finding {
	return finding.Finding{Org: h.Org, Host: h.Name, Group: h.Group, Exposure: h.Exposure, Module: module}
}

// New: a non-vulnerability finding (misconfig / exposure / health / inventory) with a localizable title and detail.
// maxDetail > 0 truncates the detail text (as the original modules did).
func New(h config.Host, module, kind, id, severity string, title, detail i18n.Text, maxDetail int) finding.Finding {
	f := Base(h, module)
	f.Kind, f.ID, f.Severity = kind, id, severity
	f.Title, f.Msg, f.Args = title.Text, title.Key, title.Args
	f.Target = detail.Text
	if maxDetail > 0 && len([]rune(f.Target)) > maxDetail {
		f.Target = string([]rune(f.Target)[:maxDetail])
	}
	if detail.Key != "" {
		f.TargetMsg, f.TargetArgs = detail.Key, detail.Args
	}
	if title.Key == "" {
		f.Msg, f.Args = "", nil
	}
	return f
}

// Misconfig: New with kind misconfig and no truncation.
func Misconfig(h config.Host, module, id, severity string, title, detail i18n.Text) finding.Finding {
	return New(h, module, finding.Misconfig, id, severity, title, detail, 0)
}
