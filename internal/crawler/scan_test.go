package crawler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/goleak"

	"github.com/shorstop/shorstop/internal/detect"
)

// TestMain fails the package's tests if any goroutine is still running after
// they finish, which is how leaks from cancelled scans would show up.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// writeTree creates files under a new temp dir. Map keys are slash paths.
func writeTree(t testing.TB, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func opts(root string) Options {
	return Options{Root: root, Workers: 4, MaxFileSize: 1 << 20}
}

// fakeDetector reports one finding per line containing "RSA".
type fakeDetector struct {
	name      string
	binaryOK  bool
	detectErr error
	panicOn   string
	calls     atomic.Int64
}

func (d *fakeDetector) Name() string { return d.name }

func (d *fakeDetector) Supports(path string, binary bool) bool { return !binary || d.binaryOK }

func (d *fakeDetector) Detect(_ context.Context, f detect.File) ([]detect.Finding, error) {
	d.calls.Add(1)
	if d.panicOn != "" && f.Path == d.panicOn {
		panic("boom")
	}
	var out []detect.Finding
	for i, line := range strings.Split(string(f.Content), "\n") {
		if strings.Contains(line, "RSA") {
			out = append(out, detect.Finding{RuleID: "fake-rsa", Algorithm: "RSA", Line: i + 1})
		}
	}
	return out, d.detectErr
}

func TestScanEligibleFiles(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main.go":               "package main\n",
		"README.md":             "readme\n",
		".gitignore":            "*.log\n/out/\nsecret*\n",
		"debug.log":             "ignored by *.log\n",
		"out/gen.go":            "ignored: anchored /out/\n",
		"pkg/out/kept.go":       "kept: /out/ only matches at root\n",
		"pkg/.gitignore":        "!secret-ok.txt\n",
		"pkg/secret.txt":        "ignored by root secret*\n",
		"pkg/secret-ok.txt":     "re-included by pkg/.gitignore\n",
		"node_modules/lib/x.js": "default skip dir\n",
		".git/config":           "default skip dir\n",
		"vendor/v.go":           "default skip dir\n",
		"pkg/node_modules/y.js": "default skip dir at any depth\n",
		"image.png":             "\x89PNG\x00\x00binary",
		"big.txt":               strings.Repeat("x", 2000),
		"empty.txt":             "",
	})
	if err := os.Symlink(filepath.Join(root, "main.go"), filepath.Join(root, "link.go")); err != nil {
		t.Logf("symlinks unsupported here, skipping that case: %v", err)
	}

	o := opts(root)
	o.MaxFileSize = 1000
	res, err := Scan(context.Background(), o, nil)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{".gitignore", "README.md", "empty.txt", "main.go", "pkg/.gitignore", "pkg/out/kept.go", "pkg/secret-ok.txt"}
	if !slices.Equal(res.Files, want) {
		t.Errorf("Files =\n  %q\nwant\n  %q", res.Files, want)
	}
	if res.Stats.Scanned != len(want) {
		t.Errorf("Stats.Scanned = %d, want %d", res.Stats.Scanned, len(want))
	}
	if res.Stats.TooLarge != 1 {
		t.Errorf("Stats.TooLarge = %d, want 1", res.Stats.TooLarge)
	}
	if res.Stats.Binary != 1 {
		t.Errorf("Stats.Binary = %d, want 1", res.Stats.Binary)
	}
	// debug.log, out/, pkg/secret.txt, node_modules/, .git/, vendor/, pkg/node_modules/
	if res.Stats.Ignored != 7 {
		t.Errorf("Stats.Ignored = %d, want 7", res.Stats.Ignored)
	}
	if len(res.Errors) != 0 {
		t.Errorf("unexpected errors: %v", res.Errors)
	}
}

func TestScanExcludes(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a.go":            "a\n",
		"app.min.js":      "minified\n",
		"testdata/f.pem":  "fixture\n",
		"src/testdata/ok": "exclude is anchored: src/testdata stays\n",
	})
	o := opts(root)
	o.Excludes = []string{"*.min.js", "/testdata/"}
	res, err := Scan(context.Background(), o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.go", "src/testdata/ok"}; !slices.Equal(res.Files, want) {
		t.Errorf("Files = %q, want %q", res.Files, want)
	}
}

func TestScanFindingsDeterministic(t *testing.T) {
	files := map[string]string{}
	for i := range 200 {
		files[fmt.Sprintf("dir%d/f%d.txt", i%7, i)] = "x\nRSA\ny\nRSA\n"
	}
	root := writeTree(t, files)

	var first *Result
	for _, workers := range []int{1, 3, 16} {
		o := opts(root)
		o.Workers = workers
		res, err := Scan(context.Background(), o, []detect.Detector{&fakeDetector{name: "fake"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 400 {
			t.Fatalf("workers=%d: %d findings, want 400", workers, len(res.Findings))
		}
		f := res.Findings[0]
		if f.File == "" || f.Detector != "fake" {
			t.Errorf("crawler must set File and Detector, got %+v", f)
		}
		if first == nil {
			first = res
			continue
		}
		if !slices.Equal(res.Findings, first.Findings) || !slices.Equal(res.Files, first.Files) {
			t.Errorf("workers=%d gave a different result than workers=1", workers)
		}
	}
}

func TestScanDetectorFailures(t *testing.T) {
	root := writeTree(t, map[string]string{"a.txt": "RSA\n", "b.txt": "RSA\n", "c.txt": "RSA\n"})
	dets := []detect.Detector{
		&fakeDetector{name: "panicky", panicOn: "b.txt"},
		&fakeDetector{name: "erroring", detectErr: errors.New("parse failed")},
	}
	res, err := Scan(context.Background(), opts(root), dets)
	if err != nil {
		t.Fatalf("detector failures must not fail the scan: %v", err)
	}
	// panicky: a and c; erroring: all three (findings are kept despite its error).
	if len(res.Findings) != 5 {
		t.Errorf("%d findings, want 5", len(res.Findings))
	}
	if len(res.Errors) != 3 {
		t.Fatalf("%d errors, want 3: %v", len(res.Errors), res.Errors)
	}
	if msg := res.Errors[1].Error(); !strings.Contains(msg, "b.txt") || !strings.Contains(msg, "panicky: panic: boom") {
		t.Errorf("error for b.txt = %q, want it to name the file and the panic", msg)
	}
}

func TestScanBinaryForDetectorThatWantsIt(t *testing.T) {
	root := writeTree(t, map[string]string{"cert.der": "\x30\x82\x00RSA"})
	d := &fakeDetector{name: "certs", binaryOK: true}
	res, err := Scan(context.Background(), opts(root), []detect.Detector{d})
	if err != nil {
		t.Fatal(err)
	}
	if d.calls.Load() != 1 || res.Stats.Binary != 0 || res.Stats.Scanned != 1 {
		t.Errorf("binary file not handed to detector: calls=%d stats=%+v", d.calls.Load(), res.Stats)
	}
}

// cancellingDetector cancels the scan the first time it runs.
type cancellingDetector struct {
	cancel context.CancelFunc
	calls  atomic.Int64
}

func (d *cancellingDetector) Name() string               { return "cancel" }
func (d *cancellingDetector) Supports(string, bool) bool { return true }
func (d *cancellingDetector) Detect(context.Context, detect.File) ([]detect.Finding, error) {
	d.calls.Add(1)
	d.cancel()
	return nil, nil
}

func TestScanCancelMidway(t *testing.T) {
	files := map[string]string{}
	for i := range 2000 {
		files[fmt.Sprintf("d%d/f%d", i%20, i)] = "x"
	}
	root := writeTree(t, files)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &cancellingDetector{cancel: cancel}
	_, err := Scan(ctx, opts(root), []detect.Detector{d})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// Each worker may finish the file it was on, but no more.
	if n := d.calls.Load(); n > int64(opts(root).Workers) {
		t.Errorf("detector ran %d times after cancel, want at most %d", n, opts(root).Workers)
	}
	// Goroutine leaks are checked by goleak in TestMain.
}

func TestScanCancelledBeforeStart(t *testing.T) {
	root := writeTree(t, map[string]string{"a": "x"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, opts(root), nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestScanUnreadableEntries(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read everything")
	}
	root := writeTree(t, map[string]string{"ok.txt": "x", "locked/inner.txt": "x", "noread.txt": "x"})
	locked := filepath.Join(root, "locked")
	noread := filepath.Join(root, "noread.txt")
	for p, mode := range map[string]os.FileMode{locked: 0o000, noread: 0o000} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	res, err := Scan(context.Background(), opts(root), []detect.Detector{&fakeDetector{name: "f"}})
	if err != nil {
		t.Fatalf("unreadable entries must not fail the scan: %v", err)
	}
	if !slices.Equal(res.Files, []string{"ok.txt"}) {
		t.Errorf("Files = %q, want [ok.txt]", res.Files)
	}
	if res.Stats.Failed != 1 || len(res.Errors) != 2 {
		t.Errorf("want 1 failed file and 2 errors (dir + file), got stats=%+v errors=%v", res.Stats, res.Errors)
	}
}

func TestScanOptionsValidation(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Options{
		"zero workers":  {Root: root, Workers: 0, MaxFileSize: 1},
		"zero max size": {Root: root, Workers: 1, MaxFileSize: 0},
		"missing root":  {Root: filepath.Join(root, "nope"), Workers: 1, MaxFileSize: 1},
		"root is file":  {Root: file, Workers: 1, MaxFileSize: 1},
		"bad exclude":   {Root: root, Workers: 1, MaxFileSize: 1, Excludes: []string{"!x"}},
	}
	for name, o := range cases {
		if _, err := Scan(context.Background(), o, nil); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// TestScanLargeTree is the Phase 1 acceptance check: 100k files, all listed,
// no leaks. It creates 100k files, so it only runs when asked:
//
//	SHORSTOP_LARGE_TEST=1 go test -race -run LargeTree ./internal/crawler
func TestScanLargeTree(t *testing.T) {
	if os.Getenv("SHORSTOP_LARGE_TEST") == "" {
		t.Skip("set SHORSTOP_LARGE_TEST=1 to run")
	}
	const n = 100_000
	root := t.TempDir()
	for i := range n {
		dir := filepath.Join(root, fmt.Sprintf("d%03d", i%500))
		if i < 500 {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%06d.txt", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Scan(context.Background(), opts(root), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != n {
		t.Errorf("listed %d files, want %d", len(res.Files), n)
	}
}

func BenchmarkScan(b *testing.B) {
	files := map[string]string{}
	for i := range 5000 {
		files[fmt.Sprintf("d%d/f%d.go", i%50, i)] = strings.Repeat("line with RSA maybe\n", 50)
	}
	root := writeTree(b, files)
	dets := []detect.Detector{&fakeDetector{name: "fake"}}
	b.ResetTimer()
	for b.Loop() {
		if _, err := Scan(context.Background(), opts(root), dets); err != nil {
			b.Fatal(err)
		}
	}
}
