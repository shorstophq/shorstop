package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/shorstop/shorstop/internal/baseline"
	"github.com/shorstop/shorstop/internal/classify"
	"github.com/shorstop/shorstop/internal/crawler"
	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/detect/cert"
	"github.com/shorstop/shorstop/internal/detect/config"
	"github.com/shorstop/shorstop/internal/rules"
	"github.com/shorstop/shorstop/internal/settings"
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
	config      string
	noConfig    bool
	ruleFiles   stringList

	flags *pflag.FlagSet // to tell flags given on the command line from defaults
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
	f.StringVar(&o.config, "config", "", "config file (default: "+settings.FileName+" in the scanned directory, if present)")
	f.BoolVar(&o.noConfig, "no-config", false, "ignore "+settings.FileName)
	f.Var(&o.ruleFiles, "rules", "extra rule file, in the rule-pack format (repeatable)")
	o.flags = f
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
	cfg, err := applySettings(o)
	if err != nil {
		return err
	}
	render, ok := formats[o.format]
	if !ok {
		return fmt.Errorf("unknown --format %q (want one of: %s)", o.format, strings.Join(formatNames, ", "))
	}
	if !slices.Contains(failOnLevels, o.failOn) {
		return fmt.Errorf("unknown --fail-on %q (want one of: %s)", o.failOn, strings.Join(failOnLevels, ", "))
	}
	var base *baseline.Baseline
	if o.baseline != "" {
		if base, err = baseline.Load(o.baseline); err != nil {
			return err
		}
	}
	pack, disabledBuiltins, err := loadRules(o.ruleFiles, cfg.Disable)
	if err != nil {
		return err
	}

	excludes := append(slices.Clone(o.excludes), selfExcludes(o.dir, append([]string{cfg.Path, o.baseline, o.output}, o.ruleFiles...)...)...)
	res, err := crawler.Scan(ctx, crawler.Options{
		Root: o.dir, Workers: o.workers, MaxFileSize: int64(o.maxFileSize), Excludes: excludes,
	}, detectors(pack))
	if err != nil {
		return err
	}
	// Built-in cert and config rules have no rule-pack entry to remove, so
	// disabling them filters their findings.
	if len(disabledBuiltins) > 0 {
		res.Findings = slices.DeleteFunc(res.Findings, func(f detect.Finding) bool {
			return slices.Contains(disabledBuiltins, f.RuleID)
		})
	}
	for _, e := range res.Errors {
		fmt.Fprintf(stderr, "shorstop: warning: %v\n", e)
	}

	// Suppressed and baselined findings leave the table, SARIF, Markdown
	// and --fail-on; the CBOM keeps every finding (the crypto is still there).
	env := renderEnv{dir: o.dir, color: o.output == "" && useColor(stdout), all: res.Findings, pack: pack}
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

// applySettings reads the config file and fills in every option not given
// on the command line. Command-line flags win; --exclude patterns add to
// the config's. It returns the settings (empty when there is no file).
func applySettings(o *scanOptions) (*settings.Settings, error) {
	path := o.config
	if path == "" && !o.noConfig {
		var err error
		if path, err = settings.Find(o.dir); err != nil {
			return nil, err
		}
	}
	if path == "" || (o.noConfig && o.config == "") {
		return &settings.Settings{}, nil
	}
	cfg, err := settings.Load(path)
	if err != nil {
		return nil, err
	}
	set := func(name string) bool { return o.flags != nil && o.flags.Changed(name) }
	if cfg.FailOn != "" && !set("fail-on") {
		o.failOn = cfg.FailOn
	}
	if cfg.Baseline != "" && !set("baseline") {
		o.baseline = cfg.Baseline
	}
	if cfg.MaxFileSize != "" && !set("max-file-size") {
		if err := o.maxFileSize.Set(cfg.MaxFileSize); err != nil {
			return nil, fmt.Errorf("%s: max-file-size: %w", path, err)
		}
	}
	o.excludes = append(slices.Clone(cfg.Exclude), o.excludes...)
	o.ruleFiles = append(slices.Clone(cfg.Rules), o.ruleFiles...)
	return cfg, nil
}

// selfExcludes returns anchored exclude patterns for ShorStop's own files
// inside the scanned tree: the config, rule files, the baseline and the
// output. They name crypto by design (a baseline is full of "MD5"
// snippets), so scanning them would report the scanner's own records, and
// a committed baseline would grow new findings on every run.
func selfExcludes(dir string, paths ...string) []string {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
			continue // outside the scanned tree
		}
		out = append(out, "/"+filepath.ToSlash(rel))
	}
	return out
}

// loadRules returns the built-in rule pack merged with extra rule files,
// without the disabled rules, and the disabled IDs that belong to the
// built-in cert and config detectors (those are filtered from findings).
// Unknown IDs in disable are errors: a typo must not leave a rule on.
func loadRules(files, disable []string) (*rules.Pack, []string, error) {
	builtin, err := rules.Builtin()
	if err != nil {
		return nil, nil, fmt.Errorf("loading rules: %w", err)
	}
	builtins := builtinIDs()
	packs := []*rules.Pack{builtin}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("--rules: %w", err)
		}
		p, err := rules.Parse(data, f)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range p.Rules {
			if det, clash := builtins[r.ID]; clash {
				return nil, nil, fmt.Errorf("%s: rule %q has the ID of a built-in %s rule", f, r.ID, det)
			}
		}
		packs = append(packs, p)
	}
	pack, err := rules.Merge(packs...)
	if err != nil {
		return nil, nil, err
	}
	var builtinsOff []string
	for _, id := range disable {
		switch {
		case slices.ContainsFunc(pack.Rules, func(r rules.Rule) bool { return r.ID == id }):
		case builtins[id] != "":
			builtinsOff = append(builtinsOff, id)
		default:
			return nil, nil, fmt.Errorf("disable: no rule %q (see 'shorstop rules list')", id)
		}
	}
	return pack.Without(disable), builtinsOff, nil
}

// builtinIDs maps the cert and config detectors' rule IDs to their detector.
func builtinIDs() map[string]string {
	m := make(map[string]string)
	for id := range cert.RuleDescriptions {
		m[id] = cert.Name
	}
	for id := range config.RuleDescriptions {
		m[id] = config.Name
	}
	return m
}
