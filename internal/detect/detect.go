// Package detect defines the interface every crypto detector implements and
// the Finding type detectors produce.
package detect

import (
	"context"
	"time"
)

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
	RuleID       string       // a rules.Rule ID, or a built-in ID such as "private-key-committed"
	Algorithm    string       // one of rules.Algorithms: RSA, ECDSA, ML-KEM, AES, SHA-1 ...; "" if unknown
	Primitive    string       // one of rules.Primitives (CycloneDX names), or "" if unknown
	KeySize      int          // 0 if unknown
	ParameterSet string       // a named parameter set such as "ML-DSA-65", or ""
	Mode         string       // CBC, GCM, ECB ...
	AssetType    string       // CycloneDX assetType; "" means AssetAlgorithm
	MaterialType string       // AssetMaterial only: MaterialPrivateKey or MaterialPublicKey
	Protocol     string       // AssetProtocol only: a TLS/SSL version, e.g. "TLSv1.0" or "SSLv3"
	PURL         string       // deps findings: the library's Package URL, e.g. "pkg:npm/node-forge@1.3.1"
	Cert         *Certificate // AssetCertificate only
	File         string       // set by the crawler, not the detector
	Line         int          // 1-based; 0 for binary files
	Snippet      string       // trimmed, max 120 chars; never contains key material
	Confidence   string       // high (AST/cert), medium (regex), low (string match)
	Detector     string       // set by the crawler, not the detector
	Suppression  *Suppression // set by the crawler when a shorstop:ignore comment covers the finding
}

// Suppression records an inline "shorstop:ignore" comment that covers a
// finding. Suppressed findings stay in the CBOM (the crypto is still there)
// but leave alerts, reports and --fail-on.
type Suppression struct {
	Reason string // the comment's reason="...", or ""
	Line   int    // where the comment is
}

// Finding.AssetType values, named as in CycloneDX 1.6 cryptoProperties.assetType.
const (
	AssetAlgorithm   = "algorithm"
	AssetCertificate = "certificate"
	AssetMaterial    = "related-crypto-material"
	AssetProtocol    = "protocol"
)

// TLS and SSL versions, as Finding.Protocol spells them.
const (
	SSLv2  = "SSLv2"
	SSLv3  = "SSLv3"
	TLSv10 = "TLSv1.0"
	TLSv11 = "TLSv1.1"
	TLSv12 = "TLSv1.2"
	TLSv13 = "TLSv1.3"
)

// Finding.MaterialType values, named as in CycloneDX 1.6
// relatedCryptoMaterialProperties.type.
const (
	MaterialPrivateKey = "private-key"
	MaterialPublicKey  = "public-key"
)

// Certificate holds the X.509 fields a CBOM records for a certificate.
type Certificate struct {
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
}
