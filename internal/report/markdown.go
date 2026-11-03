package report

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/shorstophq/shorstop/internal/detect"
)

// MarkdownOptions control the Markdown report.
type MarkdownOptions struct {
	// MaxBytes caps the report's size, so it fits in a GitHub comment
	// (65,536 characters); 0 means 60,000, leaving room for text around
	// it. File sections that would go over it are left out, with a note.
	// The summary table is never cut.
	MaxBytes    int
	IncludeInfo bool
}

// truncationNote is the most a truncation note takes, reserved in the budget.
const truncationNote = 160

// WriteMarkdown writes a report for a pull-request comment or an audit
// attachment: a summary table with one row per asset and rating, then a
// collapsible table per file.
func WriteMarkdown(w io.Writer, fs []detect.Finding, opts MarkdownOptions) error {
	maxBytes := cmp.Or(opts.MaxBytes, 60000)
	groups := groupFindings(fs, opts.IncludeInfo)
	var b strings.Builder

	b.WriteString("## ShorStop post-quantum scan\n\n")
	listed := 0
	for _, g := range groups {
		listed += len(g.items)
	}
	fmt.Fprintf(&b, "**%d findings**%s\n\n", len(fs), Count(fs))
	if listed == 0 {
		b.WriteString("Nothing needs attention.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	b.WriteString("| Severity | Asset | Status | Places | What to do |\n|---|---|---|---:|---|\n")
	for _, g := range groups {
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s |\n",
			g.r.Severity, mdCell(g.label), g.r.Status, len(g.items), mdCell(cmp.Or(g.r.Recommendation, g.r.Reason)))
	}

	// Per-file tables, files in path order, findings by line.
	byFile := map[string][]rated{}
	var files []string
	for _, g := range groups {
		for _, it := range g.items {
			if _, ok := byFile[it.f.File]; !ok {
				files = append(files, it.f.File)
			}
			byFile[it.f.File] = append(byFile[it.f.File], it)
		}
	}
	slices.Sort(files)
	b.WriteString("\n### Findings by file\n\n")
	var sec strings.Builder
	for i, file := range files {
		items := byFile[file]
		slices.SortStableFunc(items, func(a, b rated) int {
			return cmp.Or(cmp.Compare(a.f.Line, b.f.Line), cmp.Compare(b.r.Severity.Rank(), a.r.Severity.Rank()))
		})
		sec.Reset()
		fmt.Fprintf(&sec, "<details><summary><code>%s</code> · %d</summary>\n\n", htmlEscape(file), len(items))
		sec.WriteString("| Line | Asset | Status | Severity | Rule |\n|---:|---|---|---|---|\n")
		for _, it := range items {
			line := "–"
			if it.f.Line > 0 {
				line = fmt.Sprint(it.f.Line)
			}
			fmt.Fprintf(&sec, "| %s | %s | %s | %s | `%s` |\n", line, mdCell(assetLabel(it.f)), it.r.Status, it.r.Severity, it.f.RuleID)
		}
		sec.WriteString("\n</details>\n\n")
		// Whole sections only: a cut table would render as garbage.
		if b.Len()+sec.Len()+truncationNote > maxBytes {
			fmt.Fprintf(&b, "_%d more files not shown to keep this report under %d bytes; the CBOM (`--format json`) and SARIF list every finding._\n", len(files)-i, maxBytes)
			break
		}
		b.WriteString(sec.String())
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// mdCell makes text safe inside a Markdown table cell: "|" would end the
// cell, and HTML or a newline would break the table or inject markup.
// Text comes from scanned files (paths, package names), so it is untrusted.
func mdCell(s string) string {
	s = htmlEscape(clean(s))
	return strings.NewReplacer("|", `\|`, "`", "'", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`).Replace(s)
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(clean(s))
}
