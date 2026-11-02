package main

import (
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/shorstop/shorstop/internal/crawler"
	"github.com/shorstop/shorstop/internal/report"
)

// renderFunc writes a scan result in one output format.
type renderFunc func(w io.Writer, res *crawler.Result, dir string) error

// formats are the --format values. "json" is the CycloneDX CBOM, as in the
// plan; "cbom" is accepted as a clearer alias.
var formats = map[string]renderFunc{
	"table": renderTable,
	"json":  renderCBOM,
	"cbom":  renderCBOM,
}

// formatNames lists the formats in help text and errors, in a fixed order.
var formatNames = []string{"table", "json", "cbom"}

// renderTable is the plain summary line until the terminal reporter exists.
func renderTable(w io.Writer, res *crawler.Result, _ string) error {
	_, err := fmt.Fprintln(w, summary(res))
	return err
}

// renderCBOM writes the findings as a CycloneDX 1.6 CBOM.
func renderCBOM(w io.Writer, res *crawler.Result, dir string) error {
	serial, err := report.NewSerialNumber()
	if err != nil {
		return err
	}
	return report.WriteCBOM(w, report.CBOM(res.Findings, report.CBOMOptions{
		ProjectName:  projectName(dir),
		ToolVersion:  resolveVersion(),
		Timestamp:    time.Now(),
		SerialNumber: serial,
	}))
}

// projectName is the scanned directory's own name: "." becomes the name of
// the working directory.
func projectName(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return filepath.Base(dir)
}
