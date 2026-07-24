// Package version exposes the build version, injected at build time.
package version

// Version is set with
//
//	-ldflags "-X github.com/khalid-src/corv-client/internal/version.Version=vX.Y.Z"
//
// and defaults to "dev" for unstamped local builds.
var Version = "dev"
