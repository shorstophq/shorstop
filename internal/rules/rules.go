// Package rules loads and validates the rule pack that tells the
// rule-driven detectors what to look for.
//
// The built-in pack is rules.yaml, embedded in the binary. A pack is checked
// in full when it loads, so detectors can trust every Rule they are given:
// IDs are unique, names come from closed sets, and regexes are compiled.
package rules

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

// FormatVersion is the only rule-file format version this build understands.
const FormatVersion = 1

// Detector names a rule can target. They equal the Name() of the detector
// that consumes the rule.
const (
	DetectorGoAST = "goast"
	DetectorRegex = "regex"
)

// Confidence levels, from most to least certain.
const (
	ConfidenceHigh   = "high"   // the code was parsed (AST, certificate)
	ConfidenceMedium = "medium" // a pattern matched source text
	ConfidenceLow    = "low"    // indirect evidence, such as a dependency name
)

// defaultConfidence is used when a rule doesn't set one.
var defaultConfidence = map[string]string{
	DetectorGoAST: ConfidenceHigh,
	DetectorRegex: ConfidenceMedium,
}

// Algorithms is the closed set of algorithm names a rule may use. The
// classifier maps each one to a quantum-risk status, so adding a name here
// means adding it there too.
var Algorithms = []string{
	// Public-key, broken by Shor's algorithm.
	"RSA", "DSA", "DH", "ECC", "ECDSA", "ECDH", "EdDSA", "X25519",
	// Post-quantum (NIST FIPS 203/204/205).
	"ML-KEM", "ML-DSA", "SLH-DSA",
	// Symmetric ciphers.
	"AES", "DES", "3DES", "RC4", "ChaCha20",
	// Hashes.
	"MD4", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-3",
}

// Primitives is the closed set of primitive names, taken from CycloneDX 1.6
// cryptoProperties.algorithmProperties.primitive so the CBOM reporter can
// copy them unchanged. "unknown" is spelled as an empty field instead.
var Primitives = []string{
	"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
	"pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other",
}

var idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Pack is a validated set of rules.
type Pack struct {
	Version int
	Rules   []Rule
}

// Rule describes one piece of cryptography and how to recognise it.
type Rule struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Detector    string `yaml:"detector"`
	Algorithm   string `yaml:"algorithm"`
	Primitive   string `yaml:"primitive"` // empty means unknown
	KeySize     int    `yaml:"key_size"`  // 0 means unknown
	Mode        string `yaml:"mode"`
	Confidence  string `yaml:"confidence"` // empty in the file means the detector default
	Match       Match  `yaml:"match"`

	re *regexp.Regexp // compiled Match.Pattern, regex rules only
}

// Match holds the detector-specific part of a rule. Which fields are allowed
// depends on Rule.Detector; validate rejects the others.
type Match struct {
	// goast: an exact import path, e.g. "crypto/rsa".
	Import string `yaml:"import"`
	// goast, optional: a function of that package, e.g. "GenerateKey".
	// Without it the rule matches the import itself.
	Call string `yaml:"call"`
	// goast, optional, needs Call: which argument (0-based) holds the key
	// size in bits, read when it is an integer literal.
	KeySizeArg *int `yaml:"key_size_arg"`

	// regex: an RE2 pattern matched against each line. A named group "bits"
	// supplies the key size.
	Pattern string `yaml:"pattern"`
}

// Regexp returns the compiled pattern of a regex rule, or nil.
func (r *Rule) Regexp() *regexp.Regexp { return r.re }

// ForDetector returns the rules for one detector, in file order. The returned
// slice shares Rules' elements; callers must not modify them.
func (p *Pack) ForDetector(name string) []*Rule {
	var out []*Rule
	for i := range p.Rules {
		if p.Rules[i].Detector == name {
			out = append(out, &p.Rules[i])
		}
	}
	return out
}

//go:embed rules.yaml
var builtinYAML []byte

// Builtin returns the embedded rule pack. It is parsed once per process;
// every call returns the same *Pack, which callers must not modify.
var Builtin = sync.OnceValues(func() (*Pack, error) {
	return Parse(builtinYAML, "rules.yaml")
})

// file mirrors the top level of a rule file.
type file struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// Parse decodes and validates a rule file. source names the file in error
// messages. All validation problems are returned together, joined.
func Parse(data []byte, source string) (*Pack, error) {
	// Pass 1: strict decode into the structs. Unknown fields are errors, so
	// a misspelt key ("key_sise") can't silently turn a rule into a no-op.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f file
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: empty rule file", source)
		}
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: more than one YAML document; a rule file must contain exactly one", source)
	}

	if f.Version != FormatVersion {
		return nil, fmt.Errorf("%s: unsupported rule format version %d (this build supports %d)", source, f.Version, FormatVersion)
	}
	if len(f.Rules) == 0 {
		return nil, fmt.Errorf("%s: no rules", source)
	}

	// Pass 2: the same bytes as a node tree, only to find each rule's line
	// for error messages. Pass 1 already succeeded, so this can't fail.
	lines := ruleLines(data)

	var errs []error
	seen := make(map[string]int, len(f.Rules)) // id -> line of first use
	for i := range f.Rules {
		r := &f.Rules[i]
		line := 0
		if i < len(lines) {
			line = lines[i]
		}
		if first, dup := seen[r.ID]; dup && r.ID != "" {
			errs = append(errs, fmt.Errorf("%s:%d: rule %q: duplicate id (first used on line %d)", source, line, r.ID, first))
		} else {
			seen[r.ID] = line
		}
		for _, err := range r.validate() {
			errs = append(errs, fmt.Errorf("%s:%d: rule %q: %w", source, line, r.ID, err))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &Pack{Version: f.Version, Rules: f.Rules}, nil
}

// ruleLines returns the 1-based line of each element of the top-level
// "rules" sequence, in order.
func ruleLines(data []byte) []int {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	top := doc.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value != "rules" {
			continue
		}
		seq := top.Content[i+1].Content
		lines := make([]int, len(seq))
		for j, n := range seq {
			lines[j] = n.Line
		}
		return lines
	}
	return nil
}

// validate checks one rule, fills in defaults, and compiles its pattern. It
// returns every problem found rather than stopping at the first.
func (r *Rule) validate() []error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	switch {
	case r.ID == "":
		bad("missing id")
	case !idPattern.MatchString(r.ID):
		bad("id must be lowercase words joined by single hyphens, e.g. go-rsa-import")
	}
	if strings.TrimSpace(r.Description) == "" {
		bad("missing description")
	}
	if r.Algorithm == "" {
		bad("missing algorithm")
	} else if !slices.Contains(Algorithms, r.Algorithm) {
		bad("unknown algorithm %q (known: %s)", r.Algorithm, strings.Join(Algorithms, ", "))
	}
	if r.Primitive != "" && !slices.Contains(Primitives, r.Primitive) {
		bad("unknown primitive %q (known: %s)", r.Primitive, strings.Join(Primitives, ", "))
	}
	if r.KeySize < 0 {
		bad("key_size must not be negative")
	}

	def, known := defaultConfidence[r.Detector]
	switch {
	case r.Detector == "":
		bad("missing detector")
	case !known:
		bad("unknown detector %q (known: %s, %s)", r.Detector, DetectorGoAST, DetectorRegex)
	}
	switch r.Confidence {
	case "":
		r.Confidence = def
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
	default:
		bad("unknown confidence %q (known: high, medium, low)", r.Confidence)
	}

	m := r.Match
	switch r.Detector {
	case DetectorGoAST:
		if m.Import == "" {
			bad("goast rules need match.import")
		}
		if m.KeySizeArg != nil {
			if m.Call == "" {
				bad("match.key_size_arg needs match.call")
			}
			if *m.KeySizeArg < 0 {
				bad("match.key_size_arg must not be negative")
			}
			if r.KeySize != 0 {
				bad("set key_size or match.key_size_arg, not both")
			}
		}
		if m.Pattern != "" {
			bad("match.pattern is for regex rules, not goast")
		}
	case DetectorRegex:
		if m.Pattern == "" {
			bad("regex rules need match.pattern")
		} else if re, err := regexp.Compile(m.Pattern); err != nil {
			bad("match.pattern: %w", err)
		} else {
			r.re = re
			if r.KeySize != 0 && re.SubexpIndex("bits") >= 0 {
				bad("set key_size or a (?P<bits>...) group, not both")
			}
		}
		if m.Import != "" || m.Call != "" || m.KeySizeArg != nil {
			bad("match.import, match.call and match.key_size_arg are for goast rules, not regex")
		}
	}
	return errs
}
