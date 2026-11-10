package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/scan"
)

// interruptible: Ctrl+C / SIGTERM cancel the context, so a scan marks its run as interrupted and stops.
func interruptible() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// runOrg is (*scan.Scanner).Org; tests replace it.
var runOrg = func(ctx context.Context, s *scan.Scanner, o *config.Org, env string, opt scan.Options) int {
	return s.Org(ctx, o, env, opt)
}

func (a *app) scanCmd() *cobra.Command {
	var (
		flagOrgs, groups, hosts, modules []string
		env                              string
		all, dryRun, ignoreWindow        bool
		offline, yes                     bool
		parallel, trivyParallel          int
	)
	c := &cobra.Command{
		Use:   "scan [org...]",
		Short: "run a scan",
		Long: `Scan one or more orgs: each org and environment is one run with its own SSH connections,
report directory and history. An org with several environments needs --env (or --all).`,
		Example: `  kanareika scan acme --env production
  kanareika scan acme --host web-01 --module os_packages
  kanareika scan acme --dry-run          # what would run; connects nowhere
  kanareika scan --all`,
		RunE: func(cmd *cobra.Command, args []string) error {
			limitMemory()
			ids := orgIDs(args, flagOrgs)
			if !all && len(ids) == 0 {
				return fail(1, "refusing to scan: name an org (kanareika scan <org>) or use --all")
			}
			if all && len(ids) > 0 {
				return fail(1, "--all and an org are mutually exclusive")
			}
			if (len(hosts) > 0 || len(groups) > 0 || env != "") && len(ids) != 1 {
				return fail(1, "--env/--host/--group require exactly one org")
			}
			for _, m := range modules {
				if !slices.Contains(config.Modules, m) {
					return fail(2, "invalid --module %q (choose from %s)", m, strings.Join(config.Modules, ", "))
				}
			}
			orgs, byID, err := a.load(ids, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			targets := orgs
			if !all {
				targets = nil
				for _, id := range ids {
					targets = append(targets, byID[id])
				}
			}
			ctx, stop := interruptible()
			defer stop()
			if !offline && !dryRun {
				switch a.confirmDownload(ctx, yes) {
				case aborted:
					return fail(130, "interrupted")
				case declined:
					at := cachedDB()
					if at.IsZero() {
						return fail(1, "refusing to scan: the vulnerability DBs are not downloaded (kanareika db update, or db import and --offline)")
					}
					offline = true // as --offline: what is cached, however old
					fmt.Fprintf(cmd.ErrOrStderr(), "Scanning with the cached vulnerability DB from %s (%s old)\n",
						at.Local().Format("2006-01-02"), age(time.Since(at)))
				}
			}
			if !offline && !dryRun {
				a.downloadFirst(ctx, cmd.ErrOrStderr())
			}
			s := &scan.Scanner{Paths: a.paths, Out: cmd.OutOrStdout(), Err: cmd.ErrOrStderr()}
			rc := 0
			for _, o := range targets {
				envList := o.Envs()
				if !all {
					if envList, err = envs(o, env); err != nil {
						return err
					}
				}
				for _, e := range envList {
					rc |= runOrg(ctx, s, o, e, scan.Options{Groups: groups, Hosts: hosts, Modules: modules, DryRun: dryRun,
						IgnoreWindow: ignoreWindow, Parallel: parallel, TrivyParallel: trivyParallel, Offline: offline, Version: a.version})
					if ctx.Err() != nil {
						return fail(130, "interrupted")
					}
				}
			}
			if rc != 0 {
				return fail(rc, "")
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringArrayVar(&flagOrgs, "org", nil, "org id (repeatable; same as arguments)")
	f.StringVar(&env, "env", "", "environment (required if the org has several)")
	f.BoolVar(&all, "all", false, "all orgs and all their envs, one run per org/env")
	f.StringArrayVar(&groups, "group", nil, "only these groups (one org)")
	f.StringArrayVar(&hosts, "host", nil, "only these hosts (one org)")
	f.StringArrayVar(&modules, "module", nil, "only these modules (if enabled in config)")
	f.BoolVar(&dryRun, "dry-run", false, "show what would run, connect nowhere")
	f.BoolVar(&ignoreWindow, "ignore-window", false, "scan outside consent.window")
	f.IntVar(&parallel, "parallel", 0, "hosts collected at once over SSH (default: policy/settings.yml or the org file, else 8)")
	f.IntVar(&trivyParallel, "trivy-parallel", 0, "vulnerability matches at once, each holds its report in memory (default: policy/settings.yml, else 2)")
	f.BoolVar(&offline, "offline", os.Getenv("KANAREIKA_OFFLINE") != "",
		"don't download vulnerability DBs, use what db update or db import left (env KANAREIKA_OFFLINE=1)")
	f.BoolVarP(&yes, "yes", "y", false, "don't ask before downloading the DBs (also KANAREIKA_YES=1, or without a terminal)")
	return c
}

func (a *app) historyCmd() *cobra.Command {
	var flagOrg, env string
	c := &cobra.Command{
		Use:   "history <org>",
		Short: "list runs of an org/env with P1..P4 counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, err := oneOrg(args, flagOrg)
			if err != nil {
				return err
			}
			_, byID, err := a.load([]string{orgID}, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			list, err := envs(byID[orgID], env)
			if err != nil {
				return err
			}
			for _, e := range list {
				t, err := report.HistoryTable(a.paths, orgID, e)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "== %s / %s\n%s\n", orgID, e, t)
			}
			return nil
		},
	}
	c.Flags().StringVar(&flagOrg, "org", "", "org id (same as the argument)")
	c.Flags().StringVar(&env, "env", "", "environment")
	return c
}

func (a *app) diffCmd() *cobra.Command {
	var flagOrg, env, from, to string
	var limit int
	c := &cobra.Command{
		Use:   "diff <org>",
		Short: "new / resolved findings between two runs (default: last two)",
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, err := oneOrg(args, flagOrg)
			if err != nil {
				return err
			}
			_, byID, err := a.load([]string{orgID}, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			list, err := envs(byID[orgID], env)
			if err != nil {
				return err
			}
			return diffRuns(cmd.OutOrStdout(), a.paths, orgID, list[0], from, to, limit)
		},
	}
	f := c.Flags()
	f.StringVar(&flagOrg, "org", "", "org id (same as the argument)")
	f.StringVar(&env, "env", "", "environment")
	f.StringVar(&from, "from", "", "run id (default: the one before last)")
	f.StringVar(&to, "to", "", "run id (default: the last)")
	f.IntVar(&limit, "limit", 50, "rows per section")
	return c
}

func diffRuns(out io.Writer, paths config.Paths, orgID, e, from, to string, limit int) error {
	dirs := report.Runs(paths, orgID, e)
	names := make([]string, len(dirs))
	byName := map[string]string{}
	for i, d := range dirs {
		names[i] = filepath.Base(d)
		byName[names[i]] = d
	}
	if len(names) < 2 && (from == "" || to == "") {
		return fail(1, "need at least two runs")
	}
	if from == "" {
		from = names[len(names)-2]
	}
	if to == "" {
		to = names[len(names)-1]
	}
	ra, rb := byName[from], byName[to]
	if ra == "" || rb == "" {
		return fail(1, "unknown run; available: %s", strings.Join(names, ", "))
	}
	ma, fa, err := report.LoadRun(ra)
	if err != nil {
		return err
	}
	mb, fb, err := report.LoadRun(rb)
	if err != nil {
		return err
	}
	ok := func(m *report.Meta) map[string]bool {
		out := map[string]bool{}
		for _, h := range m.HostsScanned {
			if !m.HostsFailed.Has(h) {
				out[h] = true
			}
		}
		return out
	}
	oa, ob := ok(ma), ok(mb)
	hosts := map[string]bool{}
	for h := range oa {
		if ob[h] {
			hosts[h] = true
		}
	}
	for _, f := range append(append(fa[:0:0], fa...), fb...) { // external:/k8s: pseudo-hosts
		if strings.Contains(f.Host, ":") {
			hosts[f.Host] = true
		}
	}
	newF, gone := report.Diff(fa, fb, hosts)
	fmt.Fprintf(out, "%s/%s: %s -> %s, comparing %d hosts scanned in both\n", orgID, e, from, to, len(hosts))
	for _, part := range []struct {
		title string
		items int
	}{{"NEW", len(newF)}, {"RESOLVED", len(gone)}} {
		items := newF
		if part.title == "RESOLVED" {
			items = gone
		}
		fmt.Fprintf(out, "\n%s: %d\n", part.title, part.items)
		for i, f := range items {
			if i >= limit {
				fmt.Fprintf(out, "  ... %d more\n", len(items)-limit)
				break
			}
			p := f.PriorityOr()
			if p == "" {
				p = "-"
			}
			fmt.Fprintf(out, "  %-3s %-16s %-22s %-24s %s -> %s\n", p, f.Host, f.ID, f.Pkg, f.Installed, f.Fixed)
		}
	}
	return nil
}

func (a *app) pruneCmd() *cobra.Command {
	var flagOrgs []string
	var keepFull, keepPartial int
	var dryRun bool
	c := &cobra.Command{
		Use:   "prune [org...]",
		Short: "delete old runs according to policy/settings.yml (or flags)",
		RunE: func(cmd *cobra.Command, args []string) error {
			limitMemory()
			ids := orgIDs(args, flagOrgs)
			orgs, _, err := a.load(ids, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			for _, o := range orgs {
				if len(ids) > 0 && !slices.Contains(ids, o.ID) {
					continue
				}
				for _, e := range o.Envs() {
					gone, err := report.Prune(a.paths, report.EnvDir(a.paths, o.ID, e), keepFull, keepPartial, dryRun)
					if err != nil {
						return err
					}
					verb := "deleted"
					if dryRun {
						verb = "would delete"
					}
					tail := ""
					if len(gone) > 0 {
						tail = ": " + strings.Join(gone, ", ")
					}
					fmt.Fprintf(cmd.OutOrStdout(), "%s/%s: %s %d%s\n", o.ID, e, verb, len(gone), tail)
				}
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringArrayVar(&flagOrgs, "org", nil, "org id (repeatable; same as arguments)")
	f.IntVar(&keepFull, "keep-full", report.KeepDefault, "full runs to keep (default: policy/settings.yml)")
	f.IntVar(&keepPartial, "keep-partial", report.KeepDefault, "partial runs to keep (default: policy/settings.yml)")
	f.BoolVar(&dryRun, "dry-run", false, "show what would be deleted")
	return c
}
