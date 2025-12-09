package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:frontend/dist
var distFS embed.FS

// GetFileSystem returns an http.FileSystem for the embedded frontend files.
// Returns nil if the frontend hasn't been built yet.
func GetFileSystem() http.FileSystem {
	subFS, err := fs.Sub(distFS, "frontend/dist")
	if err != nil {
		return nil
	}
	return http.FS(subFS)
}

// GetFS returns the raw fs.FS for the embedded frontend files.
// Returns nil if the frontend hasn't been built yet.
func GetFS() fs.FS {
	subFS, err := fs.Sub(distFS, "frontend/dist")
	if err != nil {
		return nil
	}
	return subFS
}
