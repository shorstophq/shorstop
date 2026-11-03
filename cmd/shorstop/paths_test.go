package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestNoOldOwnerPath fails if the module's old GitHub owner reappears
// anywhere in the repository. The project moved from github.com/shorstop to
// github.com/shorstophq because "shorstop" belongs to an unrelated, dormant
// account. A stray reference in an install command or import would point
// users at code someone else controls, so it must never come back.
func TestNoOldOwnerPath(t *testing.T) {
	// Built at run time so this file doesn't match itself.
	old := [][]byte{
		[]byte("github.com/" + "shorstop/"),
		[]byte("ghcr.io/" + "shorstop/"),
	}
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "dist", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, o := range old {
			if i := bytes.Index(data, o); i >= 0 {
				line := 1 + bytes.Count(data[:i], []byte("\n"))
				t.Errorf("%s:%d mentions %s; the module lives at github.com/shorstophq/shorstop", p, line, o)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
