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
	var orgIDs []string
	c := &cobra.Command{
		Use:   "validate",
		Short: "validate orgs/*.yml against the schema and check cross-org isolation",
		RunE: func(*cobra.Command, []string) error {
			orgs, _, err := a.load(orgIDs)
			if err != nil {
				return err
			}
			for _, o := range orgs {
				if len(orgIDs) > 0 && !contains(orgIDs, o.ID) {
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
				fmt.Printf("ok  %-16s hosts [%s], consent until %v\n", o.ID, strings.Join(parts, ", "), o.Consent()["valid_until"])
			}
			return nil
		},
	}
	c.Flags().StringArrayVar(&orgIDs, "org", nil, "org id (repeatable)")
	return c
}

func (a *app) showCmd() *cobra.Command {
	var orgIDs []string
	c := &cobra.Command{
		Use:   "show",
		Short: "print resolved hosts and checks for an org",
		RunE: func(*cobra.Command, []string) error {
			_, byID, err := a.load(orgIDs)
			if err != nil {
				return err
			}
			for _, id := range orgIDs {
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
					hosts[h.Name] = map[string]any{"env": h.Env, "address": h.Address, "group": h.Group, "role": h.Role,
						"exposure": h.Exposure, "jump": jump, "sudo": h.Sudo, "checks": checks}
				}
				out := map[string]any{"org": o.ID, "envs": o.Envs(), "hosts": hosts,
					"org_checks": map[string]any{"k8s": o.Checks["k8s"], "network_external": o.Checks["network_external"]}}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(b))
			}
			return nil
		},
	}
	c.Flags().StringArrayVar(&orgIDs, "org", nil, "org id (repeatable)")
	_ = c.MarkFlagRequired("org")
	return c
}

func (a *app) migrateCmd() *cobra.Command {
	var dryRun bool
	c := &cobra.Command{
		Use:   "migrate [orgs/<id>.yml ...]",
		Short: fmt.Sprintf("rewrite org files in the current format (version %d); keeps a .bak copy", config.CurrentVersion),
		RunE: func(_ *cobra.Command, files []string) error {
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
				fmt.Printf("%s %s:\n  - %s\n", verb, f, strings.Join(steps, "\n  - "))
			}
			if changed == 0 {
				fmt.Fprintf(os.Stderr, "all files are in the current format (version %d)\n", config.CurrentVersion)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "show what would change, write nothing")
	return c
}

func (a *app) helperCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "helper",
		Short: "print the root helper script for servers (privilege: helper)",
		RunE: func(*cobra.Command, []string) error {
			fmt.Print(priv.RenderHelper(a.version))
			return nil
		},
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
