package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/mikekosulin/kanareika/internal/mcp"
)

func (a *app) mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "MCP server on stdio (read-only) for Claude Code and other agents",
		RunE: func(*cobra.Command, []string) error {
			ctx, stop := interruptible()
			defer stop()
			return mcp.Serve(ctx, os.Stdin, os.Stdout, a.paths, a.version)
		},
	}
}
