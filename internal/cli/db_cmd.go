package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/mikekosulin/kanareika/internal/dbbundle"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// Downloads, replaceable in tests (they need the network).
var (
	updateFeeds = priority.UpdateFeeds
	prepareDB   = trivy.Prepare
)

// dbParts: what `db export` packs and `db import` restores.
func dbParts() []dbbundle.Part {
	parts := []dbbundle.Part{}
	if c := trivy.CacheDir(); c != "" {
		parts = append(parts, dbbundle.Part{Name: "trivy-db", Dir: filepath.Join(c, "db")},
			dbbundle.Part{Name: "trivy-java-db", Dir: filepath.Join(c, "java-db")})
	}
	return append(parts, dbbundle.Part{Name: "feeds", Dir: priority.FeedsDir()})
}

func (a *app) dbCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "db",
		Short: "vulnerability DBs and feeds: update, status, export/import for isolated networks",
		Long: `kanareika needs data it downloads: trivy's vulnerability DBs (OS packages, languages, Java),
CISA KEV and EPSS (prioritization) and the DB-IP Lite IP database. "db update" downloads all of
it; a scan also refreshes trivy's DBs by itself unless --offline.

Isolated network: "db export bundle.tar.gz" on a connected machine, carry the file over,
"db import bundle.tar.gz" there, then "scan --offline". The bundle holds public data only.`,
	}
	c.AddCommand(a.dbUpdateCmd("update"), a.dbStatusCmd(), a.dbExportCmd(), a.dbImportCmd())
	return c
}

// dbUpdateCmd: `db update`, and `feeds` (its old name) when hidden.
func (a *app) dbUpdateCmd(use string) *cobra.Command {
	var skipTrivy, yes bool
	c := &cobra.Command{
		Use:   use,
		Short: "download trivy's vulnerability DBs, CISA KEV, EPSS and the IP database",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := interruptible()
			defer stop()
			if !a.confirmDownload(ctx, yes) {
				return fail(1, "nothing downloaded")
			}
			return a.updateDBs(ctx, cmd.OutOrStdout(), cmd.ErrOrStderr(), skipTrivy)
		},
	}
	c.Flags().BoolVar(&skipTrivy, "skip-trivy", false, "feeds only, not trivy's vulnerability DBs")
	c.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask before downloading (also KANAREIKA_YES=1, or without a terminal)")
	return c
}

// updateDBs: the feeds (KEV, EPSS, IP database), then trivy's DBs unless skipTrivy; what `db update` does, and what
// the TUI and the web start with U / the update button.
func (a *app) updateDBs(ctx context.Context, out, errOut io.Writer, skipTrivy bool) error {
	pol, err := priority.LoadPolicy(a.paths)
	if err != nil {
		return err
	}
	st, err := updateFeeds(ctx, pol)
	if err != nil {
		return err
	}
	city, asn := st.IPDBCity, st.IPDBASN
	if city == "" {
		city = "none"
	}
	if asn == "" {
		asn = "none"
	}
	fmt.Fprintf(out, "KEV: %d CVEs, EPSS: %d scores, IP DB (DB-IP Lite): city %s, asn %s -> %s\n",
		st.KEV, st.EPSS, city, asn, priority.FeedsDir())
	if skipTrivy {
		return nil
	}
	logf := func(f string, a ...any) { fmt.Fprintf(errOut, f+"\n", a...) }
	if err := prepareDB(ctx, logf); err != nil {
		return err
	}
	printDBStatus(out, time.Now())
	return nil
}

func printDBStatus(out io.Writer, now time.Time) {
	for _, d := range trivy.DBStatus() {
		if d.Updated.IsZero() {
			fmt.Fprintf(out, "trivy %s: not downloaded (%s)\n", d.Name, d.Dir)
			continue
		}
		fmt.Fprintf(out, "trivy %s: %s (%s old) -> %s\n", d.Name, d.Updated.UTC().Format("2006-01-02 15:04Z"),
			now.Sub(d.Updated).Round(time.Hour), d.Dir)
	}
}

func (a *app) dbStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "what is downloaded and how old it is",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "trivy (embedded): %s\n", orNone(trivy.Embedded()))
			printDBStatus(out, time.Now())
			f, err := priority.LoadFeeds()
			if err != nil || f.Updated == "" {
				fmt.Fprintf(out, "feeds: not downloaded (%s)\n", priority.FeedsDir())
				return nil
			}
			fmt.Fprintf(out, "feeds: KEV %d, EPSS %d, updated %s -> %s\n", len(f.KEV), len(f.EPSS), f.Updated,
				priority.FeedsDir())
			return nil
		},
	}
}

func orNone(s string) string {
	if s == "" {
		return "none (KANAREIKA_TRIVY)"
	}
	return s
}

func (a *app) dbExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export <bundle.tar.gz>",
		Short: "pack the downloaded DBs and feeds into one file for an isolated machine",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			done, err := dbbundle.Export(args[0], dbParts())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "exported %v -> %s\n", done, args[0])
			return nil
		},
	}
}

func (a *app) dbImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <bundle.tar.gz>",
		Short: "install DBs and feeds from a bundle made by `db export`",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			done, err := dbbundle.Import(args[0], dbParts())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "imported %v from %s\n", done, args[0])
			printDBStatus(cmd.OutOrStdout(), time.Now())
			return nil
		},
	}
}

// feedsCmd: the old name of `db update`, kept so existing scripts and cron jobs work.
func (a *app) feedsCmd() *cobra.Command {
	c := a.dbUpdateCmd("feeds")
	c.Hidden = true
	c.Deprecated = "use `kanareika db update`"
	return c
}
