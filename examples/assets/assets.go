// Package assets provides shared static files (fonts, CSS) for authkit example servers.
package assets

import "embed"

//go:embed files
var FS embed.FS
