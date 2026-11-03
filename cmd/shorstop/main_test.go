package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shorstop/shorstop/pkg/cbom"
)

func TestRun(t *testing.T) {
	version = "v0.0.1"
	t.Cleanup(func() { version = "" })

	dir := t.TempDir()
	for name, content := range map[string]string{
		"a.go":            "package a\n",
		"sub/b.txt":       "hello\n",
		"node_modules/x":  "skipped\n",
		"big.txt":         strings.Repeat("x", 2048),
		"ignored.log":     "skipped\n",
		".gitignore":      "*.log\n",
		"bin.dat":         "\x00\x01binary",
		"sub/.gitignore":  "",
		"sub/keep.log.md": "kept: not *.log\n",
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	listed := ".gitignore\na.go\nsub/.gitignore\nsub/b.txt\nsub/keep.log.md\n"

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
	}{
		{"version flag", []string{"--version"}, exitOK, "shorstop v0.0.1\n"},
		{"version single dash", []string{"-version"}, exitOK, "shorstop v0.0.1\n"},
		{"version subcommand", []string{"version"}, exitOK, "shorstop v0.0.1\n"},
		{"help", []string{"-h"}, exitOK, ""},
		{"unknown flag", []string{"--nope"}, exitError, ""},
		{"unexpected argument", []string{"--dir", dir, "extra"}, exitError, ""},
		{"list files", []string{"--dir", dir, "--list-files", "--max-file-size", "1KB"}, exitOK, listed},
		{"exclude", []string{"--dir", dir, "--list-files", "--max-file-size", "1KB", "--exclude", "sub/", "--exclude", ".gitignore"}, exitOK, "a.go\n"},
		{"bad size", []string{"--dir", dir, "--max-file-size", "2XB"}, exitError, ""},
		{"zero workers", []string{"--dir", dir, "--workers", "0"}, exitError, ""},
		{"missing dir", []string{"--dir", filepath.Join(dir, "nope")}, exitError, ""},
		{"negated exclude", []string{"--dir", dir, "--exclude", "!a.go"}, exitError, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %q)", code, tt.wantCode, stderr.String())
			}
			if stdout.String() != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}
		})
	}
}

func TestRunSummary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--dir", dir}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, stderr: %q", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "Scanned 1 files · 0 findings") {
		t.Errorf("summary = %q", stdout.String())
	}
}

func TestRunFormatCBOM(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import hashlib\nh = hashlib.md5(b)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "cbom"} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), []string{"--dir", dir, "--format", format}, &stdout, &stderr); code != exitOK {
			t.Fatalf("%s: exit code = %d, stderr: %q", format, code, stderr.String())
		}
		var bom cbom.BOM
		if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
			t.Fatalf("%s: stdout is not JSON (%v): %q", format, err, stdout.String())
		}
		if bom.BOMFormat != "CycloneDX" || bom.Metadata.Component.Name != filepath.Base(dir) || len(bom.Components) != 1 {
			t.Errorf("%s: unexpected CBOM: %+v", format, bom)
		}
		if !strings.HasPrefix(stderr.String(), "Scanned 1 files · 1 findings · 1 critical") {
			t.Errorf("%s: the summary should go to stderr, got %q", format, stderr.String())
		}
	}
}

func TestRunFormatSARIF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import hashlib\nh = hashlib.md5(b)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--dir", dir, "--format", "sarif"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, stderr: %q", code, stderr.String())
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID               string `json:"id"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &log); err != nil {
		t.Fatalf("stdout is not JSON (%v): %q", err, stdout.String())
	}
	r := log.Runs[0]
	if log.Version != "2.1.0" || len(r.Results) != 1 || r.Results[0].RuleID != "py-hashlib-md5" || r.Results[0].Level != "error" {
		t.Errorf("unexpected SARIF: %+v", log)
	}
	if d := r.Tool.Driver.Rules[0].ShortDescription.Text; !strings.Contains(d, "MD5") {
		t.Errorf("rule description from the rule pack expected, got %q", d)
	}
}

func TestRunUnknownFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--dir", t.TempDir(), "--format", "xml"}, &stdout, &stderr)
	if code != exitError || !strings.Contains(stderr.String(), `unknown --format "xml"`) || stdout.Len() != 0 {
		t.Errorf("code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

func TestRunOutputFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "files.txt")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--dir", dir, "--list-files", "--output", out}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, stderr: %q", code, stderr.String())
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "a.txt\n" {
		t.Errorf("output file = %q, want %q", got, "a.txt\n")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout should be empty when --output is set, got %q", stdout.String())
	}
}

func TestRunCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"--dir", t.TempDir()}, &stdout, &stderr); code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr.String(), "scan cancelled") {
		t.Errorf("stderr = %q, want it to mention cancellation", stderr.String())
	}
}

func TestResolveVersionFallback(t *testing.T) {
	version = ""
	// Under `go test` the main module version is "(devel)", so the fallback applies.
	if got := resolveVersion(); got != "dev" {
		t.Errorf("resolveVersion() = %q, want %q", got, "dev")
	}
}
