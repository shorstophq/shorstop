package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shorstophq/shorstop/internal/detect"
)

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	golden := filepath.Join(testdata, "report", name)
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s\n--- got ---\n%s--- want ---\n%s", golden, got, want)
	}
}

func TestTableGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTable(&buf, goldenFindings(), TableOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Error("colour codes without Color")
	}
	checkGolden(t, "table.golden.txt", buf.Bytes())
}

func TestTableColorAndLimit(t *testing.T) {
	var fs []detect.Finding
	for i := range 8 {
		fs = append(fs, detect.Finding{RuleID: "go-md5-import", Algorithm: "MD5", Primitive: "hash", File: fmt.Sprintf("f%d.go", i), Line: 3})
	}
	var buf bytes.Buffer
	if err := WriteTable(&buf, fs, TableOptions{Color: true, MaxLocations: 3}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, ansiBold+ansiRed+"CRITICAL · 8"+ansiReset) {
		t.Errorf("critical header not coloured:\n%q", out)
	}
	if strings.Count(out, "go-md5-import") != 3 || !strings.Contains(out, "… and 5 more") {
		t.Errorf("want 3 places and '… and 5 more':\n%s", out)
	}
}

// TestUntrustedText: paths and names come from the scanned repository.
func TestUntrustedText(t *testing.T) {
	evil := detect.Finding{RuleID: "go-md5-import", Algorithm: "MD5", Primitive: "hash",
		File: "a|b<script>\x1b[2Jx.go", Line: 1}
	var tbl bytes.Buffer
	if err := WriteTable(&tbl, []detect.Finding{evil}, TableOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tbl.String(), "\x1b") {
		t.Errorf("an escape sequence from a file name reached the terminal: %q", tbl.String())
	}
	var md bytes.Buffer
	if err := WriteMarkdown(&md, []detect.Finding{evil}, MarkdownOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(md.String(), "<script>") || strings.Contains(md.String(), "\x1b") {
		t.Errorf("markup from a file name reached the Markdown:\n%s", md.String())
	}
	if got := mdCell("a|b`c*d_[e]"); got != `a\|b'c\*d\_\[e\]` {
		t.Errorf("mdCell = %q", got)
	}
}

func TestMarkdownGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, goldenFindings(), MarkdownOptions{}); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "markdown.golden.md", buf.Bytes())
}

func TestMarkdownLimits(t *testing.T) {
	var fs []detect.Finding
	for i := range 6 {
		fs = append(fs, detect.Finding{RuleID: "go-md5-import", Algorithm: "MD5", Primitive: "hash", File: fmt.Sprintf("f%d.go", i), Line: 1})
	}
	var full bytes.Buffer
	if err := WriteMarkdown(&full, fs, MarkdownOptions{}); err != nil {
		t.Fatal(err)
	}
	// A budget that fits about half the file sections.
	budget := full.Len() - 2*(strings.Index(full.String(), "</details>")-strings.Index(full.String(), "<details>")) - truncationNote
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, fs, MarkdownOptions{MaxBytes: budget}); err != nil {
		t.Fatal(err)
	}
	got := strings.Count(buf.String(), "<details>")
	if got == 0 || got == 6 || !strings.Contains(buf.String(), fmt.Sprintf("%d more files not shown", 6-got)) {
		t.Errorf("want some file sections and a note for the rest, got %d sections:\n%s", got, buf.String())
	}
	if buf.Len() > budget {
		t.Errorf("report is %d bytes, over the %d budget", buf.Len(), budget)
	}
	if strings.Count(buf.String(), "<details>") != strings.Count(buf.String(), "</details>") {
		t.Error("a file section was cut in the middle")
	}
	// The summary table always lists every asset.
	if !strings.Contains(buf.String(), "| critical | MD5 | BROKEN | 6 |") {
		t.Errorf("summary row missing:\n%s", buf.String())
	}

	buf.Reset()
	safe := []detect.Finding{{RuleID: "go-mlkem-import", Algorithm: "ML-KEM", Primitive: "kem", File: "a.go", Line: 1}}
	if err := WriteMarkdown(&buf, safe, MarkdownOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "**1 findings** · 1 quantum-safe") || !strings.Contains(buf.String(), "Nothing needs attention.") {
		t.Errorf("all-clear report:\n%s", buf.String())
	}
}

func TestCountString(t *testing.T) {
	c := Count(goldenFindings())
	if got := c.String(); got != " · 2 critical · 5 high · 1 medium · 3 low · 1 quantum-safe" {
		t.Errorf("Count = %q", got)
	}
	if got := Count(nil).String(); got != "" {
		t.Errorf("empty Count = %q", got)
	}
}
