package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/mikekosulin/kanareika/internal/prompt"
	"github.com/mikekosulin/kanareika/internal/server"
)

func (a *app) serveCmd() *cobra.Command {
	var host string
	var port int
	c := &cobra.Command{
		Use:   "serve",
		Short: "local web dashboard over reports/",
		RunE: func(*cobra.Command, []string) error {
			s, err := server.New(server.Options{Paths: a.paths, Prompt: prompt.Build})
			if err != nil {
				return err
			}
			ctx, stop := interruptible()
			defer stop()
			return s.Serve(ctx, host, port, os.Stderr)
		},
	}
	c.Flags().StringVar(&host, "host", "127.0.0.1", "address to listen on (localhost: reports contain addresses and vulnerabilities)")
	c.Flags().IntVar(&port, "port", 8088, "port")
	return c
}
