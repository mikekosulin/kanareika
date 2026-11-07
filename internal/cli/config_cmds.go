package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/priv"
)

func (a *app) validateCmd() *cobra.Command {
	var flagOrgs []string
	c := &cobra.Command{
		Use:   "validate [org...]",
		Short: "validate orgs/*.yml against the schema and check cross-org isolation",
		RunE: func(cmd *cobra.Command, args []string) error {
			ids := orgIDs(args, flagOrgs)
			orgs, _, err := a.load(ids, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if len(orgs) == 0 {
				return fail(1, "no orgs in %s: `kanareika org new <id>` creates one", a.paths.Orgs)
			}
			for _, o := range orgs {
				if len(ids) > 0 && !contains(ids, o.ID) {
					continue
				}
				var parts []string
				for _, e := range o.Envs() {
					n := 0
					for _, h := range o.Hosts {
						if h.Env == e {
							n++
						}
					}
					parts = append(parts, fmt.Sprintf("%s: %d", e, n))
				}
				fmt.Fprintf(cmd.OutOrStdout(), "ok  %-16s hosts [%s], consent until %v\n", o.ID, strings.Join(parts, ", "),
					o.Consent()["valid_until"])
			}
			return nil
		},
	}
	c.Flags().StringArrayVar(&flagOrgs, "org", nil, "org id (repeatable; same as arguments)")
	return c
}

func (a *app) showCmd() *cobra.Command {
	var flagOrgs []string
	c := &cobra.Command{
		Use:   "show <org>...",
		Short: "print resolved hosts and checks for an org",
		RunE: func(cmd *cobra.Command, args []string) error {
			ids := orgIDs(args, flagOrgs)
			if len(ids) == 0 {
				return fail(1, "specify an org: kanareika show <org>")
			}
			_, byID, err := a.load(ids, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			for _, id := range ids {
				o := byID[id]
				hosts := map[string]any{}
				for _, h := range o.Hosts {
					checks := map[string]any{}
					for m, c := range h.Checks {
						if h.Enabled(m) {
							checks[m] = c
						}
					}
					var jump any
					if h.Jump != "" {
						jump = h.Jump
					}
					hosts[h.Name] = map[string]any{"env": h.Env, "address": h.Address, "port": h.Port, "group": h.Group,
						"role": h.Role, "exposure": h.Exposure, "jump": jump, "sudo": h.Sudo, "checks": checks}
				}
				out := map[string]any{"org": o.ID, "envs": o.Envs(), "hosts": hosts,
					"org_checks": map[string]any{"k8s": o.Checks["k8s"], "network_external": o.Checks["network_external"]}}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
			}
			return nil
		},
	}
	c.Flags().StringArrayVar(&flagOrgs, "org", nil, "org id (repeatable; same as arguments)")
	return c
}

func (a *app) migrateCmd() *cobra.Command {
	var dryRun bool
	c := &cobra.Command{
		Use:   "migrate [orgs/<id>.yml ...]",
		Short: fmt.Sprintf("rewrite org files in the current format (version %d); keeps a .bak copy", config.CurrentVersion),
		RunE: func(cmd *cobra.Command, files []string) error {
			if len(files) == 0 {
				m, _ := filepath.Glob(filepath.Join(a.paths.Orgs, "*.yml"))
				files = m
			}
			changed := 0
			for _, f := range files {
				steps, err := config.MigrateFile(f, dryRun)
				if err != nil {
					return fail(1, "%s: %v", f, err)
				}
				if len(steps) == 0 {
					continue
				}
				changed++
				verb := "migrated"
				if dryRun {
					verb = "would migrate"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s:\n  - %s\n", verb, f, strings.Join(steps, "\n  - "))
			}
			if changed == 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "all files are in the current format (version %d)\n", config.CurrentVersion)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "show what would change, write nothing")
	return c
}

func (a *app) helperCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "helper",
		Short: "print the root helper script for servers (privilege: helper)",
		Long: "The root helper runs the few root-only reads for the audit user. Install it on servers as\n" +
			priv.HelperPath + " (root:root 0755), the only command sudoers allows the audit user,\n" +
			"e.g. through your provisioning: --out writes it straight into a role's files.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			script := priv.RenderHelper(a.version)
			if out == "" {
				fmt.Fprint(cmd.OutOrStdout(), script)
				return nil
			}
			if err := os.WriteFile(out, []byte(script), 0o755); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "root helper written to %s\n", out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "write to this file (mode 0755) instead of stdout")
	return c
}
