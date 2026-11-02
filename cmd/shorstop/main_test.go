package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
