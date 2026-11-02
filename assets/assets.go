// Package assets holds the files built into the binary: default policy, the org schema, translations and the
// dashboard page. Policy files can be overridden by policy/ in the working directory (KANAREIKA_HOME).
package assets

import (
	"embed"
	"io/fs"
)

//go:embed policy/*.yml schemas/*.json
var defaults embed.FS

//go:embed locales/*.json
var locales embed.FS

//go:embed web/index.html web/logo.png
var web embed.FS

// Defaults: policy/<name>.yml and schemas/<name>.json as shipped.
func Defaults() fs.FS { return defaults }

// Locales: <lang>.json files.
func Locales() fs.FS { sub, _ := fs.Sub(locales, "locales"); return sub }

// Web: index.html and logo.png of the dashboard.
func Web() fs.FS { sub, _ := fs.Sub(web, "web"); return sub }
