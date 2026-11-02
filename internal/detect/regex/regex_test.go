package regex

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/rules"
)

var update = flag.Bool("update", false, "rewrite the .golden files from the current output")

const fixtures = "../../../testdata/fixtures"

// fixtureDirs are the fixture directories for this detector. go/ and cert/
// belong to the goast and cert detectors.
var fixtureDirs = []string{"c", "csharp", "generic", "java", "javascript", "php", "python", "ruby", "rust", "typescript"}

func builtin(t testing.TB) *Detector {
	t.Helper()
	p, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return New(p.ForDetector(rules.DetectorRegex))
}

func format(found []detect.Finding, err error) string {
	var b strings.Builder
	for _, f := range found {
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			f.Line, f.RuleID, f.Algorithm, f.Primitive, f.KeySize, f.Mode, f.Confidence, f.Snippet)
	}
	if err != nil {
		fmt.Fprintf(&b, "error: %v\n", err)
	}
	return b.String()
}

// TestFixtures compares the findings for every fixture with
// testdata/fixtures/<lang>/golden/<file>.golden. Regenerate with -update and
// review the diff.
func TestFixtures(t *testing.T) {
	d := builtin(t)
	for _, dir := range fixtureDirs {
		entries, err := os.ReadDir(filepath.Join(fixtures, dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := dir + "/" + e.Name()
			t.Run(name, func(t *testing.T) {
				src, err := os.ReadFile(filepath.Join(fixtures, name))
				if err != nil {
					t.Fatal(err)
				}
				f := detect.File{Path: name, Content: src}
				if !d.Supports(f.Path, false) {
					t.Fatalf("Supports(%q) = false", name)
				}
				got := format(d.Detect(context.Background(), f))
				golden := filepath.Join(fixtures, dir, "golden", e.Name()+".golden")
				if *update {
					if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
						t.Fatal(err)
					}
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
}

// TestNearMisses checks that nothing below each fixture's "Near-misses"
// marker produces a finding, so a loosened pattern can't slip into a golden
// file unnoticed.
func TestNearMisses(t *testing.T) {
	d := builtin(t)
	for _, dir := range fixtureDirs {
		paths, _ := filepath.Glob(filepath.Join(fixtures, dir, "*"))
		for _, p := range paths {
			src, err := os.ReadFile(p)
			if err != nil || !strings.Contains(string(src), "Near-misses") {
				continue
			}
			marker := 1 + strings.Count(string(src[:strings.Index(string(src), "Near-misses")]), "\n")
			found, _ := d.Detect(context.Background(), detect.File{Path: dir + "/" + filepath.Base(p), Content: src})
			for _, f := range found {
				if f.Line > marker {
					t.Errorf("%s:%d: near-miss matched rule %s: %s", p, f.Line, f.RuleID, f.Snippet)
				}
			}
		}
	}
}

func TestSupports(t *testing.T) {
	d := builtin(t)
	tests := []struct {
		path   string
		binary bool
		want   bool
	}{
		{"a.py", false, true},
		{"A.JAVA", false, true}, // extension case doesn't matter
		{"Makefile", false, true},
		{"notes.md", false, true},
		{"a.py", true, false},
	}
	for _, tt := range tests {
		if got := d.Supports(tt.path, tt.binary); got != tt.want {
			t.Errorf("Supports(%q, %v) = %v, want %v", tt.path, tt.binary, got, tt.want)
		}
	}
	if New(nil).Supports("a.py", false) {
		t.Error("a detector with no rules wants files")
	}
}

// TestLanguageSets checks the rule sets per extension: generic rules
// everywhere, language rules only for their own extensions.
func TestLanguageSets(t *testing.T) {
	d := builtin(t)
	ids := func(p string) []string {
		var out []string
		for _, r := range d.setFor(p).rules {
			out = append(out, r.ID)
		}
		return out
	}
	py, java, md := ids("x.py"), ids("X.java"), ids("x.md")
	for _, set := range [][]string{py, java, md} {
		if !slices.Contains(set, "generic-rsa-bits") {
			t.Error("generic rule missing from a set")
		}
	}
	if !slices.Contains(py, "py-hashlib-md5") || slices.Contains(java, "py-hashlib-md5") || slices.Contains(md, "py-hashlib-md5") {
		t.Error("python rule in the wrong sets")
	}
	if !slices.Contains(ids("Main.kt"), "java-cipher-aes-default") {
		t.Error("kotlin files don't get the java rules")
	}
}

func TestCRLFAndLastLine(t *testing.T) {
	src := "x = 1\r\nkey = RSA.generate(2048)\r\nh = hashlib.md5(b)"
	found, err := builtin(t).Detect(context.Background(), detect.File{Path: "a.py", Content: []byte(src)})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || found[0].Line != 2 || found[0].KeySize != 2048 || found[1].Line != 3 {
		t.Fatalf("got %+v", found)
	}
	if strings.ContainsRune(found[0].Snippet, '\r') {
		t.Errorf("snippet keeps the CR: %q", found[0].Snippet)
	}
}

func TestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src := strings.Repeat("h = hashlib.md5(b)\n", 2*ctxCheckLines)
	found, err := builtin(t).Detect(ctx, detect.File{Path: "a.py", Content: []byte(src)})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if len(found) >= 2*ctxCheckLines {
		t.Errorf("scanned the whole file after cancellation (%d findings)", len(found))
	}
}

// BenchmarkDetect measures a typical source file with no crypto (the common
// case: rejected by the keyword prefilter) and one with crypto.
func BenchmarkDetect(b *testing.B) {
	d := builtin(b)
	clean := []byte(strings.Repeat("def handler(request):\n    return render(request, 'index.html', {'items': items})\n", 200))
	src, err := os.ReadFile(filepath.Join(fixtures, "python", "crypto.py"))
	if err != nil {
		b.Fatal(err)
	}
	dirty := []byte(strings.Repeat(string(src), 10))
	for _, bc := range []struct {
		name    string
		content []byte
	}{{"clean", clean}, {"crypto", dirty}} {
		b.Run(bc.name, func(b *testing.B) {
			f := detect.File{Path: "a.py", Content: bc.content}
			b.SetBytes(int64(len(bc.content)))
			for b.Loop() {
				if _, err := d.Detect(context.Background(), f); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
