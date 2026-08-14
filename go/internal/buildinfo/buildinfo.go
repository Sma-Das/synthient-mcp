package buildinfo

import "strings"

// These values are replaced with -ldflags for release builds.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func UserAgent() string {
	version := strings.TrimSpace(Version)
	if version == "" {
		version = "dev"
	}
	return "synthient-mcp-go/" + version
}
