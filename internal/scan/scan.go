// Package scan runs one organization and one environment at a time: preflight (consent, window), host checks in
// parallel over SSH, org-level checks, prioritization, then the run is stored and folded into the current state.
package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/sbom"
	"github.com/mikekosulin/kanareika/internal/sshx"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// prepare / prepareOffline: trivy's DBs before a run (downloaded, or only checked); tests replace them.
var (
	prepare        = trivy.Prepare
	prepareOffline = trivy.PrepareOffline
	refreshScores  = priority.RefreshScores
)

// feedsWarn: what a scan says about KEV / EPSS it could not refresh (or, offline, did not try to).
func (s *Scanner) feedsWarn(offline bool) {
	f, _ := priority.LoadFeeds()
	if f.Updated == "" || len(f.KEV) == 0 {
		s.log("WARNING: no KEV / EPSS data: priorities ignore known-exploited CVEs and exploit likelihood. " +
			"Run `kanareika db update` (or `db import` on an isolated network).")
		return
	}
	at, err := priority.FeedsTime(f.Updated)
	if err != nil {
		return
	}
	if age := time.Since(at); offline && age > 7*24*time.Hour || !offline && age > priority.FeedsMaxAge {
		s.log("WARNING: KEV / EPSS from %s (%s old): newly exploited CVEs may be missing", at.UTC().Format("2006-01-02"),
			age.Round(time.Hour))
	}
}

// Options of one scan run.
type Options struct {
	Groups, Hosts, Modules []string
	DryRun                 bool
	IgnoreWindow           bool
	Parallel               int
	Offline                bool   // use the cached vulnerability DBs, never download (isolated networks)
	Version                string // kanareika version, stored in run.json
}

// Scanner: shared state of one process (paths, log output).
type Scanner struct {
	Paths config.Paths
	Out   io.Writer // plan / summary lines (stdout)
	Err   io.Writer // log lines (stderr)

	mu       sync.Mutex
	progress *Progress
}

func (s *Scanner) log(format string, a ...any) {
	line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
	s.mu.Lock()
	fmt.Fprintln(s.Err, line)
	p := s.progress
	s.mu.Unlock()
	if p != nil {
		p.Line(line)
	}
}

func (s *Scanner) track(host string, u HostUpdate) {
	s.mu.Lock()
	p := s.progress
	s.mu.Unlock()
	if p != nil {
		p.Host(host, u)
	}
}

// SelectHosts: hosts of env, filtered by groups/hosts; unknown names are errors (with a hint for another env).
func SelectHosts(o *config.Org, env string, groups, hosts []string) ([]config.Host, error) {
	var in []config.Host
	knownGroups, knownHosts := map[string]bool{}, map[string]bool{}
	for _, h := range o.Hosts {
		if h.Env == env {
			in = append(in, h)
			knownGroups[h.Group], knownHosts[h.Name] = true, true
		}
	}
	for _, g := range groups {
		if !knownGroups[g] {
			names := make([]string, 0, len(knownGroups))
			for k := range knownGroups {
				names = append(names, k)
			}
			sort.Strings(names)
			return nil, fmt.Errorf("%s/%s: unknown group '%s' (known: %s)", o.ID, env, g, strings.Join(names, ", "))
		}
	}
	for _, h := range hosts {
		if !knownHosts[h] {
			hint := ""
			for _, x := range o.Hosts {
				if x.Name == h {
					hint = fmt.Sprintf(" (it is in env '%s')", x.Env)
					break
				}
			}
			return nil, fmt.Errorf("%s/%s: unknown host '%s'%s", o.ID, env, h, hint)
		}
	}
	var out []config.Host
	for _, h := range in {
		if (len(groups) == 0 || slices.Contains(groups, h.Group)) && (len(hosts) == 0 || slices.Contains(hosts, h.Name)) {
			out = append(out, h)
		}
	}
	return out, nil
}

// Plan: modules per host; org-level modules only when the whole org is selected.
type Plan struct {
	Hosts map[string][]string
	Org   []string
}

func MakePlan(o *config.Org, selected []config.Host, modules []string, wholeOrg bool) Plan {
	p := Plan{Hosts: map[string][]string{}}
	for _, h := range selected {
		mods := []string{}
		for _, m := range config.HostModules {
			if h.Enabled(m) && (len(modules) == 0 || slices.Contains(modules, m)) {
				mods = append(mods, m)
			}
		}
		p.Hosts[h.Name] = mods
	}
	if wholeOrg {
		for _, m := range config.OrgModules {
			if o.Enabled(m) && (len(modules) == 0 || slices.Contains(modules, m)) {
				p.Org = append(p.Org, m)
			}
		}
	}
	return p
}

// Preflight: reasons not to scan now (consent, window, external scan without consent).
func Preflight(o *config.Org, p Plan, ignoreWindow bool, now time.Time) []string {
	var out []string
	for _, pr := range config.ConsentProblems(o, now) {
		out = append(out, o.ID+": "+pr)
	}
	if !ignoreWindow && !config.InWindow(o, now) {
		w := o.Consent()["window"].(map[string]any)
		tz, _ := w["tz"].(string)
		if tz == "" {
			tz = "UTC"
		}
		out = append(out, fmt.Sprintf("%s: outside scan window %v-%v %s (use --ignore-window if agreed with the owner)",
			o.ID, w["from"], w["to"], tz))
	}
	if slices.Contains(p.Org, "network_external") {
		if ok, _ := o.Consent()["external_scan"].(bool); !ok {
			out = append(out, o.ID+": network_external enabled but consent.external_scan is false")
		}
	}
	return out
}

// Org scans one org/env; the return value is the process exit code contribution (1 on refusal or failed hosts).
func (s *Scanner) Org(ctx context.Context, o *config.Org, env string, opt Options) int {
	selected, err := SelectHosts(o, env, opt.Groups, opt.Hosts)
	if err != nil {
		fmt.Fprintln(s.Out, "  !", err)
		return 1
	}
	whole := len(opt.Groups) == 0 && len(opt.Hosts) == 0
	p := MakePlan(o, selected, opt.Modules, whole)
	problems := Preflight(o, p, opt.IgnoreWindow, time.Now())

	fmt.Fprintf(s.Out, "\n== %s / %s: %s\n", o.ID, env, o.Name())
	for _, h := range selected {
		jump := ""
		if h.Jump != "" {
			jump = " via " + h.Jump
		}
		mods := strings.Join(p.Hosts[h.Name], ", ")
		if mods == "" {
			mods = "-"
		}
		fmt.Fprintf(s.Out, "  %-16s %-16s %-14s exp=%d%s: %s\n", h.Name, h.Address, h.Group, h.Exposure, jump, mods)
	}
	if len(p.Org) > 0 {
		fmt.Fprintf(s.Out, "  org-level: %s\n", strings.Join(p.Org, ", "))
	}
	for _, pr := range problems {
		fmt.Fprintf(s.Out, "  ! %s\n", pr)
	}
	if opt.DryRun {
		if len(problems) > 0 {
			return 1
		}
		return 0
	}
	if len(problems) > 0 {
		fmt.Fprintf(s.Out, "  %s: refusing to scan\n", o.ID)
		return 1
	}
	refuse := func(err error) int {
		fmt.Fprintf(s.Out, "  ! %v\n  %s: refusing to scan\n", err, o.ID)
		return 1
	}
	if opt.Offline {
		if err := prepareOffline(s.log); err != nil {
			return refuse(err)
		}
		s.feedsWarn(true)
	} else {
		s.log("trivy: updating vulnerability DB ...")
		if err := prepare(ctx, s.log); err != nil {
			return refuse(err)
		}
		if pol, err := priority.LoadPolicy(s.Paths); err == nil { // a broken policy is reported where it is used
			if got, err := refreshScores(ctx, pol, priority.FeedsMaxAge); err != nil {
				s.log("KEV / EPSS: not updated: %v", err)
			} else if got {
				s.log("KEV / EPSS: updated")
			}
		}
		s.feedsWarn(false)
	}
	conn, err := sshx.New(o, s.Paths)
	if err != nil {
		return refuse(err)
	}
	defer conn.Close()
	envDir := report.EnvDir(s.Paths, o.ID, env)
	lock, err := report.EnvLock(envDir, false)
	if err != nil {
		return refuse(err)
	}
	defer lock.Unlock()
	return s.run(ctx, o, env, selected, opt, p, conn, envDir)
}

func (s *Scanner) run(ctx context.Context, o *config.Org, env string, selected []config.Host, opt Options, p Plan,
	conn *sshx.OrgSSH, envDir string) (rc int) {
	started := time.Now().UTC()
	runID := started.Format("2006-01-02_150405")
	runDir := filepath.Join(envDir, runID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		fmt.Fprintln(s.Out, "  !", err)
		return 1
	}
	names := make([]string, len(selected))
	for i, h := range selected {
		names[i] = h.Name
	}
	prog, err := NewProgress(runDir, o.ID, env, runID, names, p.Org)
	if err != nil {
		fmt.Fprintln(s.Out, "  !", err)
		return 1
	}
	s.mu.Lock()
	s.progress = prog
	s.mu.Unlock()
	finished := false
	defer func() { // also on panic / Ctrl+C: mark the run so the dashboard doesn't show it as running
		s.mu.Lock()
		s.progress = nil
		s.mu.Unlock()
		if !finished {
			state := "failed"
			if errors.Is(ctx.Err(), context.Canceled) {
				state = "interrupted"
			}
			prog.Finish(state, map[string]any{"error": "aborted"})
		}
	}()

	cctx := &check.Ctx{Context: ctx, Org: o, SSH: conn, RunDir: runDir, Log: s.log, Spool: filepath.Join(runDir, ".spool")}
	defer os.RemoveAll(cctx.Spool)
	failed := pyfmt.Ordered[string]{}
	moduleErrors := pyfmt.Ordered[[]string]{}

	// each finding is prioritized and written into its host's file as it comes: a module that streams (a package
	// scan) never holds its findings, and no host's findings are gathered. The policy is read with the first
	// finding, as it was at the end before.
	var (
		mu      sync.Mutex
		applier *priority.Applier
		prepErr error
		prepped bool
		updated string // feeds' date
		orgF    []finding.Finding
	)
	prep := func() (*priority.Applier, error) {
		mu.Lock()
		defer mu.Unlock()
		if !prepped {
			prepped = true
			pol, err := priority.LoadPolicy(s.Paths)
			if err == nil {
				feeds, _ := priority.LoadFeeds()
				updated = feeds.Updated
				applier, err = priority.NewApplier(o, env, pol, feeds, started)
			}
			prepErr = err
		}
		return applier, prepErr
	}
	type hostOut struct {
		host string
		w    *report.HostWriter
		prev priority.Prev
		err  error
	}
	add := func(st *hostOut, f *finding.Finding) {
		if st.err != nil {
			return
		}
		a, err := prep()
		if err != nil {
			st.err = err
			return
		}
		if report.FileHost(f) == report.OrgHost && st.host != report.OrgHost { // a host module's org-level finding
			mu.Lock()
			orgF = append(orgF, *f)
			mu.Unlock()
			return
		}
		if st.w == nil {
			if st.w, st.err = report.NewHostWriter(runDir, st.host); st.err != nil {
				return
			}
			if p, err := report.HostPrev(envDir, st.host); err != nil {
				s.log("previous state of %s: %v (due dates count from this scan)", st.host, err)
			} else {
				st.prev = p
			}
		}
		a.Apply(f, st.prev)
		st.err = st.w.Add(f)
	}
	finish := func(st *hostOut) error {
		if st.err == nil && st.w == nil { // nothing found: an empty file says the host was scanned
			if _, err := prep(); err != nil {
				st.err = err
			} else {
				st.w, st.err = report.NewHostWriter(runDir, st.host)
			}
		}
		if st.err != nil {
			if st.w != nil {
				st.w.Abort()
			}
			return st.err
		}
		return st.w.Commit()
	}
	outs := map[string]*hostOut{}
	cctx.Sinks = map[string]func(*finding.Finding){}
	for _, h := range selected {
		st := &hostOut{host: h.Name}
		outs[h.Name] = st
		cctx.Sinks[h.Name] = func(f *finding.Finding) { add(st, f) }
	}

	type result struct {
		host string
		err  string
		merr []string
		werr error
	}
	results := make(chan result)
	sem := make(chan struct{}, max(1, opt.Parallel))
	var wg sync.WaitGroup
	for _, h := range selected {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			st := outs[h.Name]
			fs, e, m := s.host(cctx, h, p.Hosts[h.Name])
			for i := range fs {
				add(st, &fs[i])
			}
			results <- result{h.Name, e, m, finish(st)}
		}()
	}
	go func() { wg.Wait(); close(results) }()
	n := 0
	var saveErr error
	for r := range results { // completion order: hosts_failed / module_errors keep it, like the Python version
		n++
		status := "ok"
		if r.err != "" {
			status = "FAILED"
		}
		extra := ""
		if len(r.merr) > 0 {
			extra = fmt.Sprintf(" (%d module errors)", len(r.merr))
		}
		s.log("== hosts done %d/%d: %s %s%s", n, len(selected), r.host, status, extra)
		if saveErr == nil {
			saveErr = r.werr
		}
		if r.err != "" {
			failed.Set(r.host, r.err)
		}
		if len(r.merr) > 0 {
			moduleErrors.Set(r.host, r.merr)
		}
	}
	if saveErr != nil {
		fmt.Fprintln(s.Out, "  !", saveErr)
		return 1
	}
	for _, m := range p.Org {
		fn := OrgModules[m]
		if fn == nil {
			continue
		}
		prog.OrgModule(m, "running")
		f, err := fn(cctx, o.Checks[m], env)
		if err != nil {
			s.log("%s: %v", m, err)
		}
		orgF = append(orgF, f...)
		prog.OrgModule(m, "done")
	}
	if len(orgF) > 0 || len(p.Org) > 0 {
		st := &hostOut{host: report.OrgHost}
		for i := range orgF {
			add(st, &orgF[i])
		}
		if err := finish(st); err != nil {
			fmt.Fprintln(s.Out, "  !", err)
			return 1
		}
	} else if _, err := prep(); err != nil { // no hosts and no org checks: the policy is still checked
		fmt.Fprintln(s.Out, "  !", err)
		return 1
	}
	orgF = nil

	tv := trivy.Version(ctx)
	var fu *string
	if updated != "" {
		fu = &updated
	}
	mods := map[string]bool{}
	for _, ms := range p.Hosts {
		for _, m := range ms {
			mods[m] = true
		}
	}
	for _, m := range p.Org {
		mods[m] = true
	}
	modList := make([]string, 0, len(mods))
	for m := range mods {
		modList = append(modList, m)
	}
	sort.Strings(modList)
	meta := &report.Meta{
		Org: o.ID, Env: env, RunID: runID, Kanareika: opt.Version, TrivyVersion: &tv,
		Started: started.Format("2006-01-02T15:04:05.000000+00:00"), Finished: time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00"),
		Selection: report.Selection{Groups: orEmpty(opt.Groups), Hosts: orEmpty(opt.Hosts), Modules: orEmpty(opt.Modules)},
		Modules:   modList, HostsScanned: names, HostsOK: len(selected) - failed.Len(),
		ModulesByHost: p.Hosts, HostsFailed: failed, ModuleErrors: moduleErrors, FeedsUpdated: fu,
	}
	if err := report.FinishRun(runDir, meta); err != nil {
		fmt.Fprintln(s.Out, "  !", err)
		return 1
	}
	prog.Finish("done", map[string]any{"counts": meta.Counts, "totals": meta.Totals})
	finished = true
	if _, err := report.UpdateCurrent(envDir, true, false); err != nil {
		s.log("current state: %v", err)
	}
	if _, err := report.Prune(s.Paths, envDir, report.KeepDefault, report.KeepDefault, false); err != nil {
		s.log("prune: %v", err)
	}
	fmt.Fprintf(s.Out, "  done: %s; failed hosts: %d\n  report: %s/summary.md\n", meta.Totals.Line(), failed.Len(), runDir)
	if failed.Len() > 0 {
		return 1
	}
	return 0
}

func orEmpty(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// facts: os-release (or redhat-release on RHEL/CentOS 6), uname, hostname.
func facts(ctx *check.Ctx, h config.Host) (check.Facts, error) {
	raw, err := ctx.SSH.Run(ctx, h, "cat /etc/os-release 2>/dev/null; echo '@@'; uname -srm; echo '@@'; hostname; echo '@@'; "+
		"cat /etc/redhat-release 2>/dev/null | head -1", 60*time.Second, true)
	if err != nil {
		return check.Facts{}, err
	}
	parts := append(strings.SplitN(raw, "@@", 4), "", "", "")
	osr := sbom.ParseOSRelease(parts[0])
	if len(osr) == 0 {
		osr = sbom.OSReleaseFromRedhat(parts[3])
	}
	return check.Facts{OSRelease: osr, Uname: strings.TrimSpace(parts[1]), Hostname: strings.TrimSpace(parts[2])}, nil
}

// host runs the modules of one host: (findings, fatal error text, module errors).
func (s *Scanner) host(ctx *check.Ctx, h config.Host, modules []string) ([]finding.Finding, string, []string) {
	out := filepath.Join(ctx.RunDir, "hosts", h.Name)
	_ = os.MkdirAll(out, 0o755)
	s.track(h.Name, HostUpdate{State: "running", Module: ptr("connect"), Steps: len(modules)})
	f, err := facts(ctx, h)
	if err != nil {
		msg := err.Error()
		s.track(h.Name, HostUpdate{State: "failed", Module: ptr("")})
		var hk *sshx.HostKeyError
		if errors.As(err, &hk) || strings.Contains(msg, "IDENTIFICATION HAS CHANGED") || strings.Contains(msg, "Host key verification failed") {
			// never auto-accept: a changed key means a reinstall or a man-in-the-middle
			s.log("%s: HOST KEY CHANGED — not connecting", h.Name)
			fd := check.New(h, "ssh", finding.Misconfig, "ssh-host-key-changed", "CRITICAL",
				i18n.Msg("ssh.host_key_changed", nil),
				i18n.Msg("ssh.host_key_changed.detail", map[string]any{"address": h.Address, "org": h.Org}), 0)
			return []finding.Finding{fd}, "host key changed — did not connect", nil
		}
		s.log("%s: unreachable: %s", h.Name, msg)
		return nil, "unreachable: " + msg, nil
	}
	writeJSON(filepath.Join(out, "facts.json"), f)
	pretty := f.OSRelease["PRETTY_NAME"]
	if pretty == "" {
		pretty = "?"
	}
	s.log("%s: %s (%s)", h.Name, pretty, f.Hostname)
	var all []finding.Finding
	var errs []string
	for i, m := range modules {
		fn, ok := HostModules[m]
		if !ok || fn == nil {
			errs = append(errs, m+": not implemented yet")
			continue
		}
		s.log("%s: %s ...", h.Name, m)
		s.track(h.Name, HostUpdate{Module: ptr(m), Step: i + 1})
		res, err := fn(ctx, h, h.Checks[m], out, f)
		if err != nil {
			s.log("%s: %s: %v", h.Name, m, err)
			errs = append(errs, fmt.Sprintf("%s: %v", m, err))
			s.track(h.Name, HostUpdate{Errors: ptr(len(errs))})
			continue
		}
		all = append(all, res...)
	}
	state := "ok"
	if len(errs) > 0 {
		state = "warn"
	}
	s.track(h.Name, HostUpdate{State: state, Module: ptr(""), Step: len(modules)})
	return all, "", errs
}
