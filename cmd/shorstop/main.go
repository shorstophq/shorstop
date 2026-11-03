// Command shorstop scans a source tree for cryptography that is broken today
// or will be broken by a quantum computer, and reports it as a CycloneDX CBOM.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/shorstop/shorstop/internal/crawler"
	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/detect/cert"
	"github.com/shorstop/shorstop/internal/detect/config"
	"github.com/shorstop/shorstop/internal/detect/deps"
	"github.com/shorstop/shorstop/internal/detect/goast"
	"github.com/shorstop/shorstop/internal/detect/regex"
	"github.com/shorstop/shorstop/internal/report"
	"github.com/shorstop/shorstop/internal/rules"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
// When it is not set (plain `go build` or `go install`), resolveVersion falls
// back to the module version recorded by the Go toolchain.
var version = ""

// Exit codes. The CLI contract (plan, Phase 5) reserves 1 for "findings over
// the --fail-on threshold", so usage and runtime errors both use 2.
const (
	exitOK    = 0
	exitError = 2
)

const defaultMaxFileSize = 2 << 20

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, restore default handling so a second Ctrl+C
	// kills the process instead of waiting for a graceful stop.
	context.AfterFunc(ctx, stop)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run holds all CLI logic so tests can call it with fake args and buffers
// instead of building and executing the binary.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("shorstop", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	dir := fs.String("dir", ".", "directory to scan")
	// GOMAXPROCS, not NumCPU: since Go 1.25 it respects container CPU limits,
	// so a CI container limited to 2 CPUs on a 64-core host gets 2 workers.
	workers := fs.Int("workers", runtime.GOMAXPROCS(0), "number of files scanned in parallel")
	output := fs.String("output", "", "write output to this file instead of stdout")
	listFiles := fs.Bool("list-files", false, "print the files that would be scanned, one per line")
	format := fs.String("format", "table", "output format: "+strings.Join(formatNames, ", "))
	maxFileSize := byteSize(defaultMaxFileSize)
	fs.Var(&maxFileSize, "max-file-size", "skip files larger than this (e.g. 512KB, 2MB)")
	var excludes stringList
	fs.Var(&excludes, "exclude", "gitignore-style pattern to skip, relative to --dir (repeatable)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}

	if *showVersion || fs.Arg(0) == "version" {
		fmt.Fprintf(stdout, "shorstop %s\n", resolveVersion())
		return exitOK
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "shorstop: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return exitError
	}
	// Checked before scanning, so a typo doesn't cost a whole scan.
	render, ok := formats[*format]
	if !ok {
		fmt.Fprintf(stderr, "shorstop: unknown --format %q (want one of: %s)\n", *format, strings.Join(formatNames, ", "))
		return exitError
	}

	opts := crawler.Options{
		Root:        *dir,
		Workers:     *workers,
		MaxFileSize: int64(maxFileSize),
		Excludes:    excludes,
	}
	dets, err := detectors()
	if err != nil {
		fmt.Fprintf(stderr, "shorstop: loading rules: %v\n", err)
		return exitError
	}

	res, err := crawler.Scan(ctx, opts, dets)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "shorstop: scan cancelled")
		} else {
			fmt.Fprintf(stderr, "shorstop: %v\n", err)
		}
		return exitError
	}
	for _, e := range res.Errors {
		fmt.Fprintf(stderr, "shorstop: warning: %v\n", e)
	}

	err = writeOutput(*output, stdout, func(w io.Writer) error {
		if *listFiles {
			for _, f := range res.Files {
				if _, err := fmt.Fprintln(w, f); err != nil {
					return err
				}
			}
			return nil
		}
		// Colour only on a terminal: never in --output files or pipes.
		return render(w, res, renderEnv{dir: *dir, color: *output == "" && useColor(stdout)})
	})
	if err != nil {
		fmt.Fprintf(stderr, "shorstop: writing output: %v\n", err)
		return exitError
	}
	// Machine-readable output keeps stdout clean; the summary goes to stderr.
	if *listFiles || *format != "table" {
		fmt.Fprintln(stderr, summary(res))
	}
	return exitOK
}

// writeOutput sends output to path, or to stdout when path is empty, through
// a buffer: listing 100k files must not cost 100k write syscalls.
func writeOutput(path string, stdout io.Writer, write func(io.Writer) error) error {
	dst := stdout
	var f *os.File
	if path != "" {
		var err error
		if f, err = os.Create(path); err != nil {
			return err
		}
		dst = f
	}
	bw := bufio.NewWriter(dst)
	err := write(bw)
	if err == nil {
		err = bw.Flush()
	}
	if f != nil {
		// Close errors matter for files: they can be the first sign the data
		// never reached the disk.
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// detectors builds every detector from the built-in rule pack.
func detectors() ([]detect.Detector, error) {
	pack, err := rules.Builtin()
	if err != nil {
		return nil, err
	}
	return []detect.Detector{
		goast.New(pack.ForDetector(rules.DetectorGoAST)),
		cert.New(),
		config.New(),
		deps.New(pack.ForDetector(rules.DetectorDeps)),
		regex.New(pack.ForDetector(rules.DetectorRegex)),
	}, nil
}

func summary(res *crawler.Result) string {
	s := res.Stats
	return fmt.Sprintf("Scanned %d files · %d findings%s (skipped: %d ignored, %d too large, %d binary, %d not regular, %d failed) · %d warnings",
		s.Scanned, len(res.Findings), report.Count(res.Findings), s.Ignored, s.TooLarge, s.Binary, s.NotRegular, s.Failed, len(res.Errors))
}

func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
