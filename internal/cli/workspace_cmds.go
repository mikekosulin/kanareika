package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/mikekosulin/kanareika/assets"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// orgIDRE: what an org id may be (it names files and directories).
var orgIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// workspace: create the directories of a working directory; secrets/ readable by the owner only.
func workspace(p config.Paths) error {
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{p.Orgs, 0o755}, {p.Reports, 0o755}, {p.Secrets, 0o700}} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return err
		}
		if d.mode == 0o700 {
			if err := os.Chmod(d.path, d.mode); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *app) initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init [dir]",
		Short: "create a working directory: orgs/, secrets/ (owner only), reports/",
		Long: `Create a working directory (default: --home, else the current directory). Safe to repeat:
existing files are left alone. Everything in it stays local: org files, keys and reports never
leave this machine (and are git-ignored in the kanareika repository).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := a.paths
			if len(args) == 1 {
				abs, err := filepath.Abs(args[0])
				if err != nil {
					return err
				}
				p = config.PathsAt(abs)
			}
			if err := workspace(p); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "working directory: %s\n", p.Home)
			fmt.Fprintln(out, "next:")
			home := ""
			if p.Home != a.paths.Home {
				home = " --home " + p.Home
			}
			fmt.Fprintf(out, "  kanareika%s org new <id>     # an org file to describe hosts, access and consent\n", home)
			fmt.Fprintf(out, "  kanareika%s db update        # vulnerability DBs and feeds\n", home)
			return nil
		},
	}
}

func (a *app) orgCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "org",
		Short: "manage org files",
	}
	c.AddCommand(a.orgNewCmd())
	return c
}

func (a *app) orgNewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "new <id>",
		Short: "create orgs/<id>.yml from the template, and secrets/<id>/",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			if !orgIDRE.MatchString(id) {
				return fail(1, "org id %q: only a-z, 0-9, '-', '_' (starting with a letter or digit)", id)
			}
			if err := workspace(a.paths); err != nil {
				return err
			}
			path := filepath.Join(a.paths.Orgs, id+".yml")
			body := bytes.ReplaceAll(assets.OrgTemplate(), []byte(assets.OrgTemplateID), []byte(id))
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if errors.Is(err, fs.ErrExist) {
				return fail(1, "%s already exists", path)
			} else if err != nil {
				return err
			}
			_, err = f.Write(body)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Join(a.paths.Secrets, id), 0o700); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "created %s and %s/\nfill it in, then: kanareika validate %s\n", path,
				filepath.Join(a.paths.Secrets, id), id)
			return nil
		},
	}
}

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "versions of kanareika and the embedded trivy",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "kanareika %s\ntrivy %s\n%s %s/%s\n\n%s  (a star helps)\nissues: %s\n", a.version,
				orNone(trivy.Embedded()), runtime.Version(), runtime.GOOS, runtime.GOARCH, assets.Repo, assets.Issues)
		},
	}
}
