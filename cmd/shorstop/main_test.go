package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shorstophq/shorstop/pkg/cbom"
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
		{"version shorthand", []string{"-v"}, exitOK, "shorstop v0.0.1\n"},
		{"version subcommand", []string{"version"}, exitOK, "shorstop v0.0.1\n"},
		// GNU-style flags since the move to cobra: -version is -v -e -r ...
		{"single-dash long flag", []string{"-version"}, exitError, ""},
		{"help", []string{"-h"}, exitOK, "<help>"},
		{"scan help", []string{"scan", "--help"}, exitOK, "<help>"},
		{"unknown flag", []string{"--nope"}, exitError, ""},
		{"unexpected argument", []string{"--dir", dir, "extra"}, exitError, ""},
		{"unknown command", []string{"scna"}, exitError, ""},
		{"list files", []string{"--dir", dir, "--list-files", "--max-file-size", "1KB"}, exitOK, listed},
		{"scan subcommand, dir argument", []string{"scan", dir, "--list-files", "--max-file-size", "1KB"}, exitOK, listed},
		{"dir given twice", []string{"scan", dir, "--dir", "/elsewhere"}, exitError, ""},
		{"bad fail-on", []string{"--dir", dir, "--fail-on", "severe"}, exitError, ""},
		{"missing baseline", []string{"--dir", dir, "--baseline", filepath.Join(dir, "nope.sarif")}, exitError, ""},
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
			if tt.wantStdout == "<help>" {
				if !strings.Contains(stdout.String(), "Usage:") || !strings.Contains(stdout.String(), "--fail-on") {
					t.Errorf("help not on stdout: %q", stdout.String())
				}
			} else if stdout.String() != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}
		})
	}
}

func TestFailOnSuppressAndBaseline(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.py", "import hashlib\nh = hashlib.md5(b)\nkey = RSA.generate(2048)  # shorstop:ignore py-pycryptodome-rsa-generate reason=\"vendor API\"\n")
	scan := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), append([]string{"--dir", dir}, args...), &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}

	// MD5 is critical; the RSA line is suppressed.
	code, out, _ := scan("--fail-on", "high")
	if code != exitFindings || !strings.Contains(out, "1 findings · 1 critical · 1 suppressed") {
		t.Errorf("fail-on high: code %d, out:\n%s", code, out)
	}
	if code, _, _ := scan("--fail-on", "none"); code != exitOK {
		t.Errorf("fail-on none: code %d", code)
	}

	// A baseline made from this scan makes the MD5 finding known: nothing new.
	sarif := filepath.Join(dir, "base.sarif")
	if code, _, _ := scan("--format", "sarif", "--output", sarif); code != exitOK {
		t.Fatalf("writing the baseline: code %d", code)
	}
	code, out, _ = scan("--baseline", sarif, "--fail-on", "low")
	if code != exitOK || !strings.Contains(out, "0 findings · 1 suppressed · 1 in baseline") {
		t.Errorf("with baseline: code %d, out:\n%s", code, out)
	}

	// A new problem is reported despite the baseline.
	write("new.py", "import hashlib\nhashlib.sha1(x)\n")
	code, out, stderr := scan("--baseline", sarif, "--fail-on", "critical")
	if code != exitFindings || !strings.Contains(out, "SHA-1") || strings.Contains(out, "MD5") ||
		!strings.Contains(stderr, "1 findings at or above critical") {
		t.Errorf("new finding: code %d, out:\n%s\nstderr: %s", code, out, stderr)
	}

	// The CBOM keeps every finding, suppressed and baselined included.
	_, out, _ = scan("--format", "json", "--baseline", sarif)
	var bom cbom.BOM
	if err := json.Unmarshal([]byte(out), &bom); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range bom.Components {
		names[c.Name] = true
	}
	if !names["MD5"] || !names["RSA-2048"] || !names["SHA-1"] {
		t.Errorf("CBOM should list all three assets, got %v", names)
	}
}

func TestConfigFileAndCustomRules(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.py", "import hashlib\nh = hashlib.md5(b)\nlegacy_cipher('blowfish')\n")
	write("vendor_lib/x.py", "hashlib.sha1(b)\n")
	write("README.md", "openssl req -newkey rsa:2048\n")
	// A custom rule for an algorithm name the built-in pack doesn't cover,
	// rated as the closest known algorithm.
	write(".shorstop/rules.yaml", `version: 1
rules:
  - id: acme-legacy-cipher
    description: ACME's in-house wrapper around Blowfish, a 64-bit block cipher.
    detector: regex
    languages: [python]
    algorithm: 3DES
    primitive: block-cipher
    match: { keywords: [legacy_cipher], pattern: 'legacy_cipher\(', examples: ["legacy_cipher('blowfish')"] }
`)
	write(".shorstop.yaml", "fail-on: critical\nexclude: [vendor_lib/]\nrules: [.shorstop/rules.yaml]\ndisable: [generic-rsa-bits]\n")
	scan := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), append([]string{"scan", dir}, args...), &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}

	// The config's fail-on, exclude, custom rule and disable all apply.
	code, out, errOut := scan()
	if code != exitFindings || !strings.Contains(out, "acme-legacy-cipher") || strings.Contains(out, "vendor_lib") ||
		strings.Contains(out, "generic-rsa-bits") || !strings.Contains(out, "2 findings · 2 critical") {
		t.Errorf("with config: code %d\n%s\n%s", code, out, errOut)
	}
	// A flag overrides the config; --exclude adds to it.
	if code, out, _ := scan("--fail-on", "none", "--exclude", "app.py"); code != exitOK || !strings.Contains(out, "0 findings") {
		t.Errorf("flags over config: code %d\n%s", code, out)
	}
	// --no-config ignores the file entirely.
	if code, out, _ := scan("--no-config"); code != exitOK || !strings.Contains(out, "sha1") && !strings.Contains(out, "SHA-1") || strings.Contains(out, "acme-legacy-cipher") {
		t.Errorf("--no-config: code %d\n%s", code, out)
	}
	// The custom rule's description reaches SARIF.
	if _, out, _ := scan("--format", "sarif"); !strings.Contains(out, "in-house wrapper around Blowfish") {
		t.Error("custom rule description missing from SARIF")
	}
	// rules list checks and shows a rule file.
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"rules", "list", "--rules", filepath.Join(dir, ".shorstop", "rules.yaml")}, &stdout, &stderr); code != exitOK || !strings.Contains(stdout.String(), "acme-legacy-cipher") {
		t.Errorf("rules list --rules: code %d %s", code, stderr.String())
	}

	// Mistakes are errors, before scanning.
	for name, cfg := range map[string]string{
		"misspelt key":           "fail_on: high\n",
		"unknown disabled rule":  "disable: [no-such-rule]\n",
		"bad fail-on":            "fail-on: severe\n",
		"bad size":               "max-file-size: huge\n",
		"missing rule file":      "rules: [nope.yaml]\n",
		"clash with built-in":    "rules: [.shorstop/clash.yaml]\n",
		"clash with a pack rule": "rules: [.shorstop/dup.yaml]\n",
	} {
		write(".shorstop/clash.yaml", "version: 1\nrules:\n  - { id: tls-cipher, description: d, detector: regex, algorithm: RSA, match: { keywords: [rsa], pattern: rsa, examples: [rsa] } }\n")
		write(".shorstop/dup.yaml", "version: 1\nrules:\n  - { id: go-rsa-import, description: d, detector: regex, algorithm: RSA, match: { keywords: [rsa], pattern: rsa, examples: [rsa] } }\n")
		write(".shorstop.yaml", cfg)
		if code, _, errOut := scan(); code != exitError || errOut == "" {
			t.Errorf("%s: code %d, stderr %q", name, code, errOut)
		}
	}
	// An explicit --config that doesn't exist is an error; a missing default is not.
	if code, _, _ := scan("--config", filepath.Join(dir, "nope.yaml")); code != exitError {
		t.Errorf("missing --config: code %d", code)
	}
}

func TestSelfExcludes(t *testing.T) {
	root := t.TempDir()
	got := selfExcludes(root,
		filepath.Join(root, ".shorstop.yaml"),
		filepath.Join(root, "ci", "base.sarif"),
		"", // unset
		filepath.Join(root, "..", "elsewhere.sarif"), // outside the tree
		root, // the root itself
	)
	want := []string{"/.shorstop.yaml", "/ci/base.sarif"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("selfExcludes = %q, want %q", got, want)
	}
}

// TestBaselineInsideTheRepo: a committed baseline full of "MD5" snippets
// must not be scanned into new findings.
func TestBaselineInsideTheRepo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.js"), []byte("crypto.createCipheriv('aes-128-ecb', k, null)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "base.sarif")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"scan", dir, "-f", "sarif", "-o", base}, &stdout, &stderr); code != exitOK {
		t.Fatal(stderr.String())
	}
	stdout.Reset()
	if code := run(context.Background(), []string{"scan", dir, "--baseline", base, "--fail-on", "low"}, &stdout, &stderr); code != exitOK || !strings.Contains(stdout.String(), "0 findings · 1 in baseline") {
		t.Errorf("code %d\n%s", code, stdout.String())
	}
}

func TestRulesList(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"rules", "list"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"ID  ", "go-rsa-import", "private-key-committed", "tls-protocol-version", "dep-npm-node-forge"} {
		if !strings.Contains(out, want) {
			t.Errorf("rules list lacks %q", want)
		}
	}
	stdout.Reset()
	if code := run(context.Background(), []string{"rules", "list", "--detector", "cert"}, &stdout, &stderr); code != exitOK || strings.Contains(stdout.String(), "go-rsa-import") || !strings.Contains(stdout.String(), "6 rules") {
		t.Errorf("--detector cert: code %d\n%s", code, stdout.String())
	}
	if code := run(context.Background(), []string{"rules", "list", "--detector", "nope"}, &stdout, &stderr); code != exitError {
		t.Errorf("unknown detector: code %d", code)
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
	if log.Version != "2.1.0" || len(r.Results) != 1 || r.Results[0].RuleID != "py-hashlib-md5/critical" || r.Results[0].Level != "error" {
		t.Errorf("unexpected SARIF: %+v", log)
	}
	if d := r.Tool.Driver.Rules[0].ShortDescription.Text; !strings.Contains(d, "MD5") {
		t.Errorf("rule description from the rule pack expected, got %q", d)
	}
}

func TestRunTableAndMarkdown(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import hashlib\nh = hashlib.md5(b)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--dir", dir}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, stderr: %q", code, stderr.String())
	}
	out := stdout.String()
	if !strings.HasPrefix(out, "CRITICAL · 1\n  MD5 · BROKEN · 1 place\n") || !strings.Contains(out, "app.py:2") ||
		!strings.Contains(out, "\nScanned 1 files · 1 findings · 1 critical") || strings.Contains(out, "\x1b[") {
		t.Errorf("default table (to a buffer: no colour):\n%s", out)
	}

	stdout.Reset()
	if code := run(context.Background(), []string{"--dir", dir, "--format", "markdown"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.HasPrefix(stdout.String(), "## ShorStop post-quantum scan\n\n**1 findings** · 1 critical") {
		t.Errorf("markdown:\n%s", stdout.String())
	}
}

func TestUseColor(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if useColor(w) {
		t.Error("a pipe is not a terminal")
	}
	if useColor(&bytes.Buffer{}) {
		t.Error("a buffer is not a terminal")
	}
	if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
		defer tty.Close()
		t.Setenv("NO_COLOR", "")
		if !useColor(tty) {
			t.Error("a terminal with NO_COLOR unset should get colour")
		}
		t.Setenv("NO_COLOR", "1")
		if useColor(tty) {
			t.Error("NO_COLOR must turn colour off")
		}
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
