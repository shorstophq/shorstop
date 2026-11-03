// Package crawler walks a directory tree and runs detectors over every
// eligible file using a pool of worker goroutines.
package crawler

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/shorstophq/shorstop/internal/detect"
	"github.com/shorstophq/shorstop/internal/suppress"
)

const (
	// Channel buffers absorb bursts (a directory full of small files, a few
	// files with many findings) so the walker, workers and collector rarely
	// wait on each other. Their size affects throughput, not correctness.
	jobBuffer    = 256
	resultBuffer = 256

	// sniffLen is how much of a file is checked for a NUL byte to decide
	// whether it is binary. git uses the same heuristic and length.
	sniffLen = 8000
)

// Options configures a scan.
type Options struct {
	Root        string   // directory to scan
	Workers     int      // number of files processed in parallel; at least 1
	MaxFileSize int64    // files larger than this many bytes are skipped
	Excludes    []string // extra gitignore-style patterns, relative to Root
}

// Result is the outcome of a scan. Every slice is sorted, so the same tree
// always produces the same Result regardless of worker count or timing.
type Result struct {
	Findings []detect.Finding // sorted by file, line, rule ID
	Files    []string         // files scanned, slash-separated and relative to Root
	Errors   []FileError      // per-file problems that did not stop the scan, sorted by path
	Stats    Stats
}

// Stats counts what happened to every entry the walk visited.
type Stats struct {
	Scanned    int // eligible files, listed in Result.Files
	Ignored    int // files and directories excluded by rules or default skips
	TooLarge   int // files over MaxFileSize
	Binary     int // binary files that no detector asked for
	NotRegular int // symlinks, sockets, devices, FIFOs
	Failed     int // files that could not be opened or read
}

// FileError is a problem with one file or directory.
type FileError struct {
	Path string
	Err  error
}

func (e FileError) Error() string { return e.Path + ": " + e.Err.Error() }
func (e FileError) Unwrap() error { return e.Err }

type outcome int

const (
	outcomeScanned outcome = iota
	outcomeTooLarge
	outcomeBinary
	outcomeNotRegular
	outcomeFailed
)

// fileResult is everything one worker learned about one file. Workers send one
// per file, so the collector is the only goroutine that touches the Result.
type fileResult struct {
	path     string
	outcome  outcome
	findings []detect.Finding
	err      error
}

// Scan walks opts.Root and runs dets over every eligible file. If ctx is
// cancelled, Scan stops promptly and returns ctx's error along with whatever
// was collected so far.
func Scan(ctx context.Context, opts Options, dets []detect.Detector) (*Result, error) {
	if opts.Workers < 1 {
		return nil, fmt.Errorf("workers must be at least 1, got %d", opts.Workers)
	}
	if opts.MaxFileSize < 1 {
		return nil, fmt.Errorf("max file size must be at least 1 byte, got %d", opts.MaxFileSize)
	}
	info, err := os.Stat(opts.Root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", opts.Root)
	}
	excludes, err := parseExcludes(opts.Excludes)
	if err != nil {
		return nil, err
	}

	// Cancelled if the walk fails, so workers don't keep scanning a tree whose
	// result will be thrown away.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan string, jobBuffer)
	results := make(chan fileResult, resultBuffer)

	var walkSt walkStats
	walkDone := make(chan error, 1)
	go func() {
		defer close(jobs)
		st, err := walk(ctx, opts.Root, excludes, jobs)
		walkSt = st
		if err != nil {
			cancel()
		}
		walkDone <- err
	}()

	var wg sync.WaitGroup
	for range opts.Workers {
		wg.Go(func() {
			for rel := range jobs {
				if ctx.Err() != nil {
					return
				}
				results <- scanFile(ctx, opts, dets, rel)
			}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	res := &Result{}
	for r := range results {
		res.add(r)
	}

	// Receiving from walkDone also guarantees the walker's write to walkSt is visible here.
	walkErr := <-walkDone
	res.Stats.Ignored = walkSt.ignored
	res.Stats.NotRegular += walkSt.notRegular
	res.Errors = append(res.Errors, walkSt.errors...)
	res.sort()

	if walkErr != nil {
		return res, walkErr
	}
	// The walk can finish before cancellation while workers are still busy;
	// their early exit leaves the result incomplete, so report it.
	return res, ctx.Err()
}

// scanFile reads one file and runs the detectors that want it.
func scanFile(ctx context.Context, opts Options, dets []detect.Detector, rel string) fileResult {
	r := fileResult{path: rel}
	fail := func(err error) fileResult {
		r.outcome, r.err = outcomeFailed, err
		return r
	}

	f, err := os.Open(filepath.Join(opts.Root, filepath.FromSlash(rel)))
	if err != nil {
		return fail(err)
	}
	defer f.Close()

	// Checked again on the open file: the entry may have changed since the walk saw it.
	info, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() {
		r.outcome = outcomeNotRegular
		return r
	}
	size := info.Size()
	if size > opts.MaxFileSize {
		r.outcome = outcomeTooLarge
		return r
	}

	// Read only the head first; the rest is read only if a detector wants the file.
	head := make([]byte, min(size, sniffLen))
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fail(err)
	}
	head = head[:n]
	binary := bytes.IndexByte(head, 0) >= 0

	var wanted []detect.Detector
	for _, d := range dets {
		if d.Supports(rel, binary) {
			wanted = append(wanted, d)
		}
	}
	if binary && len(wanted) == 0 {
		r.outcome = outcomeBinary
		return r
	}
	r.outcome = outcomeScanned
	if len(wanted) == 0 {
		return r
	}

	// The file is read up to the size seen at Stat time: if it grows while
	// being scanned, the extra bytes are ignored rather than exceeding the limit.
	content := make([]byte, size)
	copy(content, head)
	m, err := io.ReadFull(f, content[n:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return fail(err)
	}
	file := detect.File{Path: rel, Content: content[:n+m], Binary: binary}

	var errs []error
	for _, d := range wanted {
		if ctx.Err() != nil {
			break
		}
		found, err := runDetector(ctx, d, file)
		for i := range found {
			found[i].File = rel
			found[i].Detector = d.Name()
		}
		r.findings = append(r.findings, found...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	// Two detectors can see the same line (regex and config both read
	// "Ciphers aes128-ctr"); report it once.
	r.findings = detect.Dedupe(r.findings)
	// shorstop:ignore comments need the file's text, which only this
	// function still has.
	if !binary {
		r.findings = suppress.Apply(file.Content, r.findings)
	}
	r.err = errors.Join(errs...)
	return r
}

// runDetector runs one detector, turning a panic into an error. Detectors parse
// untrusted files, so a parser bug on one file must not kill the whole scan.
func runDetector(ctx context.Context, d detect.Detector, f detect.File) (found []detect.Finding, err error) {
	defer func() {
		if p := recover(); p != nil {
			found, err = nil, fmt.Errorf("%s: panic: %v", d.Name(), p)
		}
	}()
	found, err = d.Detect(ctx, f)
	if err != nil {
		err = fmt.Errorf("%s: %w", d.Name(), err)
	}
	return found, err
}

func (res *Result) add(r fileResult) {
	switch r.outcome {
	case outcomeScanned:
		res.Stats.Scanned++
		res.Files = append(res.Files, r.path)
	case outcomeTooLarge:
		res.Stats.TooLarge++
	case outcomeBinary:
		res.Stats.Binary++
	case outcomeNotRegular:
		res.Stats.NotRegular++
	case outcomeFailed:
		res.Stats.Failed++
	}
	res.Findings = append(res.Findings, r.findings...)
	if r.err != nil {
		res.Errors = append(res.Errors, FileError{Path: r.path, Err: r.err})
	}
}

func (res *Result) sort() {
	slices.Sort(res.Files)
	slices.SortFunc(res.Findings, func(a, b detect.Finding) int {
		return cmp.Or(
			cmp.Compare(a.File, b.File),
			cmp.Compare(a.Line, b.Line),
			cmp.Compare(a.RuleID, b.RuleID),
			cmp.Compare(a.Detector, b.Detector),
		)
	})
	slices.SortStableFunc(res.Errors, func(a, b FileError) int {
		return cmp.Compare(a.Path, b.Path)
	})
}
