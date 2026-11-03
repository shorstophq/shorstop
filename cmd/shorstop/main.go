// Command shorstop scans a source tree for cryptography that is broken today
// or will be broken by a quantum computer, and reports it as a CycloneDX CBOM.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/shorstophq/shorstop/internal/crawler"
	"github.com/shorstophq/shorstop/internal/detect"
	"github.com/shorstophq/shorstop/internal/detect/cert"
	"github.com/shorstophq/shorstop/internal/detect/config"
	"github.com/shorstophq/shorstop/internal/detect/deps"
	"github.com/shorstophq/shorstop/internal/detect/goast"
	"github.com/shorstophq/shorstop/internal/detect/regex"
	"github.com/shorstophq/shorstop/internal/report"
	"github.com/shorstophq/shorstop/internal/rules"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
// When it is not set (plain `go build` or `go install`), resolveVersion falls
// back to the module version recorded by the Go toolchain.
var version = ""

// Exit codes, the CLI contract from the plan: 0 clean, 1 findings over the
// --fail-on threshold, 2 usage or scanner error.
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
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

// exitCode is returned by a command that has already said what went wrong
// and only needs the process to exit with code.
type exitCode struct{ code int }

func (e *exitCode) Error() string { return fmt.Sprintf("exit %d", e.code) }

// run holds all CLI logic so tests can call it with fake args and buffers
// instead of building and executing the binary. It returns the exit code.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	root := newRootCmd(stdout, stderr)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	var ec *exitCode
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &ec):
		return ec.code
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(stderr, "shorstop: scan cancelled")
	default:
		fmt.Fprintf(stderr, "shorstop: %v\n", err)
	}
	return exitError
}

// newRootCmd builds the command tree. Plain `shorstop` scans, like
// `shorstop scan`, so `shorstop --format sarif` keeps working.
func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	rootOpts := newScanOptions()
	root := &cobra.Command{
		Use:   "shorstop",
		Short: "Find cryptography that quantum computers will break, and report it as a CBOM",
		Long: "ShorStop scans a source tree for cryptography that is broken today or will be broken\n" +
			"by a quantum computer (RSA, ECC, DH, ...), and reports it as a table, a CycloneDX 1.6\n" +
			"CBOM, SARIF for code scanning, or Markdown.",
		Version:       resolveVersion(),
		Args:          cobra.NoArgs,
		SilenceErrors: true, // run prints errors in one format
		SilenceUsage:  true, // a scan failure is not a usage mistake
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), rootOpts, stdout, stderr)
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("shorstop {{.Version}}\n")
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return fmt.Errorf("%w (see '%s --help')", err, cmd.CommandPath())
	})
	addScanFlags(root, rootOpts)

	root.AddCommand(newScanCmd(stdout, stderr), newRulesCmd(stdout), &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, err := fmt.Fprintf(stdout, "shorstop %s\n", resolveVersion())
			return err
		},
	})
	return root
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

// detectors builds every detector from a rule pack: the built-in one,
// possibly merged with --rules files and with disabled rules removed.
func detectors(pack *rules.Pack) []detect.Detector {
	return []detect.Detector{
		goast.New(pack.ForDetector(rules.DetectorGoAST)),
		cert.New(),
		config.New(),
		deps.New(pack.ForDetector(rules.DetectorDeps)),
		regex.New(pack.ForDetector(rules.DetectorRegex)),
	}
}

// summary is the one-line scan summary. res.Findings are the findings
// shown; env says how many more were set aside.
func summary(res *crawler.Result, env renderEnv) string {
	s := res.Stats
	extra := ""
	if env.suppressed > 0 {
		extra += fmt.Sprintf(" · %d suppressed", env.suppressed)
	}
	if env.baselined > 0 {
		extra += fmt.Sprintf(" · %d in baseline", env.baselined)
	}
	return fmt.Sprintf("Scanned %d files · %d findings%s%s (skipped: %d ignored, %d too large, %d binary, %d not regular, %d failed) · %d warnings",
		s.Scanned, len(res.Findings), report.Count(res.Findings), extra, s.Ignored, s.TooLarge, s.Binary, s.NotRegular, s.Failed, len(res.Errors))
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
