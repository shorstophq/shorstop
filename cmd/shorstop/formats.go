package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/shorstophq/shorstop/internal/crawler"
	"github.com/shorstophq/shorstop/internal/detect"
	"github.com/shorstophq/shorstop/internal/detect/cert"
	"github.com/shorstophq/shorstop/internal/detect/config"
	"github.com/shorstophq/shorstop/internal/report"
	"github.com/shorstophq/shorstop/internal/rules"
)

// renderEnv is what a renderer needs besides the result.
type renderEnv struct {
	dir   string // the scanned directory, as given
	color bool   // the output is a terminal and NO_COLOR is unset
	// all is every finding, including suppressed and baselined ones: the
	// CBOM is the full inventory. The result passed alongside holds only
	// the findings to report.
	all                   []detect.Finding
	suppressed, baselined int
	pack                  *rules.Pack // the rules in effect, for SARIF's rule descriptions
}

// renderFunc writes a scan result in one output format.
type renderFunc func(w io.Writer, res *crawler.Result, env renderEnv) error

// formats are the --format values. "json" is the CycloneDX CBOM, as in the
// plan; "cbom" is accepted as a clearer alias.
var formats = map[string]renderFunc{
	"table":    renderTable,
	"json":     renderCBOM,
	"cbom":     renderCBOM,
	"sarif":    renderSARIF,
	"markdown": renderMarkdown,
}

// formatNames lists the formats in help text and errors, in a fixed order.
var formatNames = []string{"table", "json", "cbom", "sarif", "markdown"}

// renderTable is the default: findings grouped by severity, then the
// summary line.
func renderTable(w io.Writer, res *crawler.Result, env renderEnv) error {
	if err := report.WriteTable(w, res.Findings, report.TableOptions{Color: env.color}); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, summary(res, env))
	return err
}

// renderCBOM writes the findings as a CycloneDX 1.6 CBOM.
func renderCBOM(w io.Writer, res *crawler.Result, env renderEnv) error {
	serial, err := report.NewSerialNumber()
	if err != nil {
		return err
	}
	return report.WriteCBOM(w, report.CBOM(env.all, report.CBOMOptions{
		ProjectName:  projectName(env.dir),
		ToolVersion:  resolveVersion(),
		Timestamp:    time.Now(),
		SerialNumber: serial,
	}))
}

// renderSARIF writes the findings as SARIF 2.1.0 for code scanning.
func renderSARIF(w io.Writer, res *crawler.Result, env renderEnv) error {
	return report.WriteSARIF(w, res.Findings, report.SARIFOptions{
		ToolVersion: resolveVersion(),
		Catalog:     report.NewCatalog(env.pack, cert.RuleDescriptions, config.RuleDescriptions),
	})
}

// renderMarkdown writes a report for a pull-request comment or an audit.
func renderMarkdown(w io.Writer, res *crawler.Result, _ renderEnv) error {
	return report.WriteMarkdown(w, res.Findings, report.MarkdownOptions{})
}

// projectName is the scanned directory's own name: "." becomes the name of
// the working directory.
func projectName(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return filepath.Base(dir)
}

// useColor reports whether output to w may be coloured: w is a terminal
// and NO_COLOR (no-color.org) is unset or empty.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
