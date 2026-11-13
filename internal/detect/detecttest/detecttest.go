// Package detecttest holds checks shared by the detectors' fuzz tests.
package detecttest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/shorstophq/shorstop/internal/detect"
	"github.com/shorstophq/shorstop/internal/rules"
)

// sniffLen matches the crawler: a NUL byte in the first 8000 bytes makes a
// file binary.
const sniffLen = 8000

// File builds the detect.File the crawler would hand a detector for this
// path and content.
func File(path string, content []byte) detect.File {
	return detect.File{Path: path, Content: content, Binary: bytes.IndexByte(content[:min(len(content), sniffLen)], 0) >= 0}
}

// Check runs d on f, if d supports it, and fails t when a finding breaks
// the contract every detector promises. A panic fails the fuzz test by
// itself. Errors are fine: untrusted input is often malformed.
//
//   - f.Content is not modified (detectors share it).
//   - The same input gives the same findings (no map-order dependence).
//   - Every finding has a rule ID, a known algorithm (or none), a line inside
//     the file (0 for binary files), and a snippet of at most 120 runes of
//     valid UTF-8 that is one line.
func Check(t *testing.T, d detect.Detector, f detect.File) {
	t.Helper()
	if !d.Supports(f.Path, f.Binary) {
		return
	}
	orig := bytes.Clone(f.Content)
	first, _ := d.Detect(context.Background(), f)
	if !bytes.Equal(f.Content, orig) {
		t.Fatalf("%s modified the file content", d.Name())
	}
	again, _ := d.Detect(context.Background(), f)
	if !reflect.DeepEqual(first, again) {
		t.Fatalf("%s is not deterministic:\n%+v\n%+v", d.Name(), first, again)
	}

	lines := bytes.Count(f.Content, []byte("\n")) + 1
	for _, fd := range first {
		switch {
		case fd.RuleID == "":
			t.Errorf("finding without a rule ID: %+v", fd)
		case fd.Algorithm != "" && !slices.Contains(rules.Algorithms, fd.Algorithm):
			t.Errorf("unknown algorithm %q: %+v", fd.Algorithm, fd)
		case fd.Line < 0 || fd.Line > lines:
			t.Errorf("line %d outside a %d-line file: %+v", fd.Line, lines, fd)
		case f.Binary && fd.Line != 0:
			t.Errorf("binary file finding with line %d: %+v", fd.Line, fd)
		case utf8.RuneCountInString(fd.Snippet) > detect.MaxSnippet || !utf8.ValidString(fd.Snippet) || strings.Contains(fd.Snippet, "\n"):
			t.Errorf("bad snippet %q: %+v", fd.Snippet, fd)
		}
	}
}

// Seed adds each file (relative to the repository root) to f's corpus,
// with the index of the name it is scanned as.
func Seed(f *testing.F, names []string, files map[string]int) {
	f.Helper()
	root := filepath.Join("..", "..", "..")
	for file, i := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
		if err != nil {
			f.Fatal(err)
		}
		if i < 0 || i >= len(names) {
			f.Fatalf("seed %s: name index %d out of range", file, i)
		}
		f.Add(uint8(i), data)
	}
}
