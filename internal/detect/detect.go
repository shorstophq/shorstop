// Package detect defines the interface every crypto detector implements and
// the Finding type detectors produce.
package detect

import "context"

// Detector finds cryptographic usage in a single file.
//
// One Detector value is shared by every worker goroutine, so implementations
// must be safe for concurrent use.
type Detector interface {
	// Name identifies the detector in findings and error messages.
	Name() string

	// Supports reports whether the detector wants this file. It runs before
	// the file is fully read, so it can only use the path and whether the
	// file looks binary.
	Supports(path string, binary bool) bool

	// Detect returns the findings in f. It must not modify f.Content, which
	// is shared with the other detectors for the same file. Returning an error
	// does not discard the findings returned with it. Long-running detectors
	// should stop when ctx is done.
	Detect(ctx context.Context, f File) ([]Finding, error)
}

// File is one file handed to a detector.
type File struct {
	Path    string // slash-separated, relative to the scan root
	Content []byte // the whole file; never larger than the --max-file-size limit
	Binary  bool   // a NUL byte appeared in the first 8000 bytes
}

// Finding is one piece of cryptography found in a file.
type Finding struct {
	RuleID     string // a rules.Rule ID, e.g. "go-rsa-import"
	Algorithm  string // one of rules.Algorithms: RSA, ECDSA, ML-KEM, AES, SHA-1 ...
	Primitive  string // one of rules.Primitives (CycloneDX names), or "" if unknown
	KeySize    int    // 0 if unknown
	Mode       string // CBC, GCM, ECB ...
	File       string // set by the crawler, not the detector
	Line       int
	Snippet    string // trimmed, max 120 chars
	Confidence string // high (AST/cert), medium (regex), low (string match)
	Detector   string // set by the crawler, not the detector
}
