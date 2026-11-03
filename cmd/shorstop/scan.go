package main

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shorstop/shorstop/internal/baseline"
	"github.com/shorstop/shorstop/internal/classify"
	"github.com/shorstop/shorstop/internal/crawler"
	"github.com/shorstop/shorstop/internal/detect"
)

// scanOptions are the scan command's flags.
type scanOptions struct {
	dir         string
	workers     int
	output      string
	listFiles   bool
	format      string
	maxFileSize byteSize
	excludes    stringList
	failOn      string
	baseline    string
}

func newScanOptions() *scanOptions {
	return &scanOptions{maxFileSize: defaultMaxFileSize}
}

// failOnLevels are the --fail-on values, lowest threshold last.
var failOnLevels = []string{"none", "critical", "high", "medium", "low"}

func addScanFlags(cmd *cobra.Command, o *scanOptions) {
	f := cmd.Flags()
	f.StringVar(&o.dir, "dir", ".", "directory to scan")
	// GOMAXPROCS, not NumCPU: since Go 1.25 it respects container CPU limits,
	// so a CI container limited to 2 CPUs on a 64-core host gets 2 workers.
	f.IntVar(&o.workers, "workers", runtime.GOMAXPROCS(0), "number of files scanned in parallel")
	f.StringVarP(&o.output, "output", "o", "", "write output to this file instead of stdout")
	f.BoolVar(&o.listFiles, "list-files", false, "print the files that would be scanned, one per line")
	f.StringVarP(&o.format, "format", "f", "table", "output format: "+strings.Join(formatNames, ", "))
	f.Var(&o.maxFileSize, "max-file-size", "skip files larger than this (e.g. 512KB, 2MB)")
	f.Var(&o.excludes, "exclude", "gitignore-style pattern to skip, relative to the scanned directory (repeatable)")
	f.StringVar(&o.failOn, "fail-on", "none", "exit with code 1 if a finding is at or above this severity: "+strings.Join(failOnLevels, ", "))
	f.StringVar(&o.baseline, "baseline", "", "a previous --format sarif or json output; only findings not in it are reported")
}

func newScanCmd(stdout, stderr io.Writer) *cobra.Command {
	o := newScanOptions()
	cmd := &cobra.Command{
		Use:   "scan [dir]",
		Short: "Scan a directory (the default command)",
		Example: "  shorstop scan .\n" +
			"  shorstop scan --format sarif --output shorstop.sarif --fail-on high\n" +
			"  shorstop scan --baseline previous.sarif",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				if cmd.Flags().Changed("dir") && args[0] != o.dir {
					return fmt.Errorf("directory given twice: %q and --dir %q", args[0], o.dir)
				}
				o.dir = args[0]
			}
			return runScan(cmd.Context(), o, stdout, stderr)
		},
	}
	addScanFlags(cmd, o)
	return cmd
}

// runScan is the scan: check the options, crawl, set aside suppressed and
// baselined findings, render, and apply --fail-on.
func runScan(ctx context.Context, o *scanOptions, stdout, stderr io.Writer) error {
	// Everything that can be wrong with the options is checked before
	// scanning, so a typo doesn't cost a whole scan.
	render, ok := formats[o.format]
	if !ok {
		return fmt.Errorf("unknown --format %q (want one of: %s)", o.format, strings.Join(formatNames, ", "))
	}
	if !slices.Contains(failOnLevels, o.failOn) {
		return fmt.Errorf("unknown --fail-on %q (want one of: %s)", o.failOn, strings.Join(failOnLevels, ", "))
	}
	var base *baseline.Baseline
	if o.baseline != "" {
		var err error
		if base, err = baseline.Load(o.baseline); err != nil {
			return err
		}
	}
	dets, err := detectors()
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	res, err := crawler.Scan(ctx, crawler.Options{
		Root: o.dir, Workers: o.workers, MaxFileSize: int64(o.maxFileSize), Excludes: o.excludes,
	}, dets)
	if err != nil {
		return err
	}
	for _, e := range res.Errors {
		fmt.Fprintf(stderr, "shorstop: warning: %v\n", e)
	}

	// Suppressed and baselined findings leave the table, SARIF, Markdown
	// and --fail-on; the CBOM keeps every finding (the crypto is still there).
	env := renderEnv{dir: o.dir, color: o.output == "" && useColor(stdout), all: res.Findings}
	var shown []detect.Finding
	for _, f := range res.Findings {
		if f.Suppression != nil {
			env.suppressed++
		} else {
			shown = append(shown, f)
		}
	}
	if base != nil {
		var known []detect.Finding
		shown, known = base.Split(shown)
		env.baselined = len(known)
	}
	view := *res
	view.Findings = shown

	err = writeOutput(o.output, stdout, func(w io.Writer) error {
		if o.listFiles {
			for _, f := range res.Files {
				if _, err := fmt.Fprintln(w, f); err != nil {
					return err
				}
			}
			return nil
		}
		return render(w, &view, env)
	})
	if err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	// Machine-readable output keeps stdout clean; the summary goes to stderr.
	if o.listFiles || o.format != "table" {
		fmt.Fprintln(stderr, summary(&view, env))
	}

	if n := countAtOrAbove(shown, o.failOn); n > 0 {
		fmt.Fprintf(stderr, "shorstop: %d findings at or above %s (--fail-on %s)\n", n, o.failOn, o.failOn)
		return &exitCode{exitFindings}
	}
	return nil
}

// countAtOrAbove counts findings rated at or above the threshold; "none"
// counts nothing.
func countAtOrAbove(fs []detect.Finding, threshold string) int {
	if threshold == "none" {
		return 0
	}
	floor := classify.Severity(threshold).Rank()
	n := 0
	for _, f := range fs {
		if classify.Classify(f).Severity.Rank() >= floor {
			n++
		}
	}
	return n
}
