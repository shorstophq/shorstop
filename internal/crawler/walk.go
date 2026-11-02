package crawler

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
)

// defaultSkipDirs are directory names never scanned: VCS metadata, installed
// dependencies and build output.
var defaultSkipDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"vendor":       {},
	"dist":         {},
	"build":        {},
	".venv":        {},
}

// walkStats is owned by the walker goroutine and read only after it finishes.
type walkStats struct {
	ignored    int
	notRegular int
	errors     []FileError
}

// walk sends the slash-separated, root-relative path of every regular file
// that is not ignored into jobs. Errors on individual entries are recorded and
// the walk continues; only an unreadable root or cancellation stops it.
func walk(ctx context.Context, root string, excludes []rule, jobs chan<- string) (walkStats, error) {
	var st walkStats
	var stack ignoreStack

	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			rel = ""
		}
		if err != nil {
			if rel == "" {
				return err
			}
			// An unreadable directory has already failed its .gitignore read on
			// the first visit; report the directory once, not twice.
			if n := len(st.errors); n > 0 && st.errors[n-1].Path == joinRel(rel, ".gitignore") {
				st.errors = st.errors[:n-1]
			}
			st.errors = append(st.errors, FileError{Path: rel, Err: err})
			return nil
		}

		if rel != "" {
			stack.popTo(rel)
			if isIgnored(e, rel, excludes, stack) {
				st.ignored++
				if e.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		if e.IsDir() {
			rules, err := readIgnoreFile(filepath.Join(p, ".gitignore"))
			if err != nil {
				st.errors = append(st.errors, FileError{Path: joinRel(rel, ".gitignore"), Err: err})
			}
			stack.push(rel, rules)
			return nil
		}

		// Symlinks are not followed: they can point outside the scan root or
		// form loops. Sockets, devices and FIFOs are skipped too; opening a
		// FIFO would block a worker forever.
		if !e.Type().IsRegular() {
			st.notRegular++
			return nil
		}

		select {
		case jobs <- rel:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	return st, err
}

func isIgnored(e fs.DirEntry, rel string, excludes []rule, stack ignoreStack) bool {
	isDir := e.IsDir()
	if isDir {
		if _, skip := defaultSkipDirs[e.Name()]; skip {
			return true
		}
	}
	parts := strings.Split(rel, "/")
	if ignored, ok := lastMatch(excludes, parts, isDir); ok && ignored {
		return true
	}
	return stack.ignored(parts, isDir)
}

func joinRel(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}
