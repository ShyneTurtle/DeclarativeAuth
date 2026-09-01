// Package buildinfo holds the version string embedded at build time.
package buildinfo

// Version is overridden at build time via:
//
//	-ldflags="-X declarativeauth/internal/buildinfo.Version=v1.2.3"
//
// See deploy/docker/Dockerfile. Left as "dev" for local `go build`/`go run`.
var Version = "dev"
