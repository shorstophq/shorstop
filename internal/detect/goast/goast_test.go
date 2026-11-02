package goast

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/rules"
)

var update = flag.Bool("update", false, "rewrite the .golden files from the current output")

const fixtures = "../../../testdata/fixtures/go"

func builtin(t *testing.T) *Detector {
	t.Helper()
	p, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return New(p.ForDetector(rules.DetectorGoAST))
}

// format renders findings and the error, one per line, tab-separated, so
// golden diffs are easy to review.
func format(found []detect.Finding, err error) string {
	var b strings.Builder
	for _, f := range found {
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%d\t%s\t%s\n",
			f.Line, f.RuleID, f.Algorithm, f.Primitive, f.KeySize, f.Confidence, f.Snippet)
	}
	if err != nil {
		fmt.Fprintf(&b, "error: %v\n", err)
	}
	return b.String()
}

// TestFixtures runs the detector with the built-in rules over every fixture
// and compares the result with <fixture>.golden. Run with -update after an
// intended change, then review the diff.
func TestFixtures(t *testing.T) {
	d := builtin(t)
	paths, err := filepath.Glob(filepath.Join(fixtures, "*.go"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures in %s (%v)", fixtures, err)
	}
	for _, p := range paths {
		name := filepath.Base(p)
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			got := format(d.Detect(context.Background(), detect.File{Path: name, Content: src}))
			golden := p + ".golden"
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if got != string(want) {
				t.Errorf("findings differ from %s\n--- got ---\n%s--- want ---\n%s", golden, got, want)
			}
		})
	}
}

func TestSupports(t *testing.T) {
	d := New(nil)
	tests := []struct {
		path   string
		binary bool
		want   bool
	}{
		{"main.go", false, true},
		{"pkg/x_test.go", false, true},
		{"main.go", true, false},
		{"main.go.txt", false, false},
		{"go.mod", false, false},
	}
	for _, tt := range tests {
		if got := d.Supports(tt.path, tt.binary); got != tt.want {
			t.Errorf("Supports(%q, %v) = %v, want %v", tt.path, tt.binary, got, tt.want)
		}
	}
}

func TestOnlyGoastRules(t *testing.T) {
	p, err := rules.Parse([]byte(`
version: 1
rules:
  - { id: g, description: d, detector: goast, algorithm: MD5, match: { import: crypto/md5 } }
  - { id: r, description: d, detector: regex, algorithm: MD5, match: { keywords: [md5], pattern: md5, examples: [md5] } }
`), "t.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Both rules passed in: the regex one must be skipped, not treated as an
	// import rule with an empty path.
	d := New([]*rules.Rule{&p.Rules[0], &p.Rules[1]})
	src := detect.File{Path: "x.go", Content: []byte("package x\nimport \"crypto/md5\"\n")}
	found, err := d.Detect(context.Background(), src)
	if err != nil || len(found) != 1 || found[0].RuleID != "g" {
		t.Errorf("got %v, %v; want one finding from rule g", found, err)
	}
}

func TestNotGo(t *testing.T) {
	found, err := builtin(t).Detect(context.Background(), detect.File{Path: "x.go", Content: []byte("not go at all")})
	if len(found) != 0 || err == nil {
		t.Errorf("got %v, %v; want no findings and a parse error", found, err)
	}
}

func TestCancelledBeforeFullParse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src := []byte("package x\nimport (\"crypto/rand\"; \"crypto/rsa\")\nvar _, _ = rsa.GenerateKey(rand.Reader, 2048)\n")
	found, err := builtin(t).Detect(ctx, detect.File{Path: "x.go", Content: src})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if len(found) != 1 || found[0].RuleID != "go-rsa-import" {
		t.Errorf("want only the import finding from pass 1, got %v", found)
	}
}
