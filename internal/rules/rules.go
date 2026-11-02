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
	"maps"
	"regexp"
	"slices"
	"strconv"
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
	DetectorDeps  = "deps"
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
	DetectorDeps:  ConfidenceLow, // a dependency says a library is present, not how it is used
}

// Algorithms is the closed set of algorithm names a rule may use. The
// classifier maps each one to a quantum-risk status, so adding a name here
// means adding it there too.
var Algorithms = []string{
	// Public-key, broken by Shor's algorithm.
	"RSA", "DSA", "DH", "ECC", "ECDSA", "ECDH", "EdDSA", "X25519",
	// Post-quantum (NIST FIPS 203/204/205).
	"ML-KEM", "ML-DSA", "SLH-DSA",
	// Post-quantum, not NIST-standardised: Streamlined NTRU Prime, used in
	// OpenSSH's default sntrup761x25519-sha512 key exchange.
	"sntrup761",
	// Symmetric ciphers.
	"AES", "DES", "3DES", "RC4", "ChaCha20",
	// Hashes.
	"MD2", "MD4", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-3",
}

// Primitives is the closed set of primitive names, taken from CycloneDX 1.6
// cryptoProperties.algorithmProperties.primitive so the CBOM reporter can
// copy them unchanged. "unknown" is spelled as an empty field instead.
var Primitives = []string{
	"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
	"pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other",
}

// Modes is the closed set of block-cipher modes. A (?P<mode>...) group
// whose text, upper-cased, isn't in this set gives an empty Finding.Mode.
var Modes = []string{
	"ECB", "CBC", "CTR", "GCM", "CCM", "CFB", "OFB", "XTS", "OCB", "EAX", "SIV",
}

// Languages maps each language a regex rule may name to its file
// extensions (lower-case, with the dot). An extension belongs to one
// language only.
var Languages = map[string][]string{
	"c":          {".c", ".h"},
	"cpp":        {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"},
	"csharp":     {".cs"},
	"go":         {".go"},
	"java":       {".java"},
	"javascript": {".js", ".mjs", ".cjs", ".jsx"},
	"kotlin":     {".kt", ".kts"},
	"php":        {".php"},
	"python":     {".py", ".pyi"},
	"ruby":       {".rb"},
	"rust":       {".rs"},
	"typescript": {".ts", ".tsx", ".mts", ".cts"},
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
	// Languages limits a regex rule to these languages' files (keys of
	// Languages). Empty means every text file.
	Languages []string `yaml:"languages"`
	Match     Match    `yaml:"match"`

	re               *regexp.Regexp // compiled Match.Pattern, regex rules only
	bitsIdx, modeIdx int            // subexpression indexes of "bits" and "mode", or -1
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
	// supplies the key size; a named group "mode" supplies the mode.
	Pattern string `yaml:"pattern"`
	// regex: literal words (printable ASCII, at least MinKeywordLen bytes),
	// matched case-insensitively. The pattern only runs on lines containing
	// at least one of them, so every line it can match must contain one.
	// Lower-cased at load.
	Keywords []string `yaml:"keywords"`
	// regex: lines the pattern must match, checked at load. Each must also
	// contain a keyword, and give a valid key size and mode if the pattern
	// captures them.
	Examples []string `yaml:"examples"`

	// deps: the package ecosystem, one of Ecosystems.
	Ecosystem string `yaml:"ecosystem"`
	// deps: the package name as the ecosystem spells it: "node-forge",
	// "@noble/curves", "org.bouncycastle:bcprov-jdk18on" (Maven
	// group:artifact), "golang.org/x/crypto". A trailing "*" matches any
	// suffix ("org.bouncycastle:bcprov-*").
	Package string `yaml:"package"`
}

// Ecosystems is the closed set of package ecosystems a deps rule may name,
// sorted.
// They are Package URL (purl) types.
var Ecosystems = []string{"cargo", "composer", "gem", "golang", "maven", "npm", "nuget", "pypi"}

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
	// A library (deps) often provides many algorithms; only its rule may
	// leave the algorithm unknown.
	if r.Algorithm == "" && r.Detector != DetectorDeps {
		bad("missing algorithm")
	} else if r.Algorithm != "" && !slices.Contains(Algorithms, r.Algorithm) {
		bad("unknown algorithm %q (known: %s)", r.Algorithm, strings.Join(Algorithms, ", "))
	}
	if r.Primitive != "" && !slices.Contains(Primitives, r.Primitive) {
		bad("unknown primitive %q (known: %s)", r.Primitive, strings.Join(Primitives, ", "))
	}
	if r.KeySize < 0 {
		bad("key_size must not be negative")
	}
	if r.Mode != "" && !slices.Contains(Modes, r.Mode) {
		bad("unknown mode %q (known: %s)", r.Mode, strings.Join(Modes, ", "))
	}

	def, known := defaultConfidence[r.Detector]
	switch {
	case r.Detector == "":
		bad("missing detector")
	case !known:
		bad("unknown detector %q (known: %s, %s, %s)", r.Detector, DetectorDeps, DetectorGoAST, DetectorRegex)
	}
	switch r.Confidence {
	case "":
		r.Confidence = def
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
	default:
		bad("unknown confidence %q (known: high, medium, low)", r.Confidence)
	}

	m := r.Match
	if r.Detector != DetectorDeps && (m.Ecosystem != "" || m.Package != "") {
		bad("match.ecosystem and match.package are for deps rules, not %s", r.Detector)
	}
	switch r.Detector {
	case DetectorDeps:
		if m.Import != "" || m.Call != "" || m.KeySizeArg != nil || m.Pattern != "" || len(m.Keywords) > 0 || len(m.Examples) > 0 {
			bad("deps rules take only match.ecosystem and match.package")
		}
		if len(r.Languages) > 0 {
			bad("languages is for regex rules; a deps rule's ecosystem says where it applies")
		}
		if !slices.Contains(Ecosystems, m.Ecosystem) {
			bad("unknown or missing match.ecosystem %q (known: %s)", m.Ecosystem, strings.Join(Ecosystems, ", "))
		}
		switch base, wild := strings.CutSuffix(m.Package, "*"); {
		case strings.TrimSpace(base) == "":
			bad("deps rules need match.package (a lone \"*\" would match every dependency)")
		case strings.Contains(base, "*"):
			bad("match.package may only end in \"*\", not contain one elsewhere")
		case wild && !strings.ContainsAny(base[len(base)-1:], "-_.:/"):
			bad("match.package %q: a wildcard needs a separator before it, e.g. \"bcprov-*\", so it can't match unrelated names", m.Package)
		}
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
		if m.Pattern != "" || len(m.Keywords) > 0 || len(m.Examples) > 0 {
			bad("match.pattern, match.keywords and match.examples are for regex rules, not goast")
		}
		if len(r.Languages) > 0 {
			bad("languages is for regex rules; goast rules are Go-only")
		}
	case DetectorRegex:
		if m.Import != "" || m.Call != "" || m.KeySizeArg != nil {
			bad("match.import, match.call and match.key_size_arg are for goast rules, not regex")
		}
		for _, l := range r.Languages {
			if _, ok := Languages[l]; !ok {
				bad("unknown language %q (known: %s)", l, strings.Join(slices.Sorted(maps.Keys(Languages)), ", "))
			}
		}
		if len(m.Keywords) == 0 {
			bad("regex rules need match.keywords")
		}
		for i, k := range m.Keywords {
			if !validKeyword(k) {
				bad("match.keywords[%d] %q must be at least %d printable ASCII characters", i, k, MinKeywordLen)
			}
			r.Match.Keywords[i] = strings.ToLower(k)
		}
		if m.Pattern == "" {
			bad("regex rules need match.pattern")
			break
		}
		re, err := regexp.Compile(m.Pattern)
		if err != nil {
			bad("match.pattern: %w", err)
			break
		}
		if re.MatchString("") {
			bad("match.pattern matches the empty string, so it would match every line")
			break
		}
		r.re, r.bitsIdx, r.modeIdx = re, re.SubexpIndex("bits"), re.SubexpIndex("mode")
		if r.KeySize != 0 && r.bitsIdx >= 0 {
			bad("set key_size or a (?P<bits>...) group, not both")
		}
		if r.Mode != "" && r.modeIdx >= 0 {
			bad("set mode or a (?P<mode>...) group, not both")
		}
		if len(m.Examples) == 0 {
			bad("regex rules need match.examples")
		}
		for i, ex := range m.Examples {
			if !r.hasKeyword(strings.ToLower(ex)) {
				bad("match.examples[%d] contains none of the keywords, so the pattern would never run on it", i)
			}
			ms, problems := r.matchAll([]byte(ex))
			if len(ms) == 0 {
				bad("match.examples[%d] does not match the pattern", i)
			}
			for _, p := range problems {
				bad("match.examples[%d]: %s", i, p)
			}
		}
	}
	return errs
}

// MinKeywordLen is the shortest keyword. The regex detector indexes keywords
// by their first three bytes.
const MinKeywordLen = 3

// validKeyword: printable ASCII (so lower-casing never changes its length),
// at least MinKeywordLen bytes, and so never spanning lines.
func validKeyword(k string) bool {
	if len(k) < MinKeywordLen {
		return false
	}
	for i := range len(k) {
		if k[i] < 0x20 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

func (r *Rule) hasKeyword(lower string) bool {
	for _, k := range r.Match.Keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

// maxKeyBits bounds a key size read from a (?P<bits>) group. Larger numbers
// are not key sizes (RSA-16384 is the largest seen in practice).
const maxKeyBits = 1 << 16

// LineMatch is what a regex rule found on one line.
type LineMatch struct {
	KeySize int    // from (?P<bits>), else the rule's key_size
	Mode    string // from (?P<mode>) upper-cased, else the rule's mode
}

// MatchAll runs a regex rule on one line and returns each distinct result,
// in order: "aes256-gcm,aes128-ctr" gives two, "aes128-ctr,aes128-ctr" one.
// It is the only place a pattern's captures are read, so a rule's examples
// are checked exactly as the detector will read real lines.
func (r *Rule) MatchAll(line []byte) []LineMatch {
	ms, _ := r.matchAll(line)
	return ms
}

// matchAll is MatchAll, plus a description of each capture that was present
// but unusable, for validating examples.
func (r *Rule) matchAll(line []byte) ([]LineMatch, []string) {
	var out []LineMatch
	var problems []string
	for _, loc := range r.re.FindAllSubmatchIndex(line, -1) {
		m, p := r.captures(line, loc)
		problems = append(problems, p...)
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out, problems
}

// captures reads the bits and mode groups of one match.
func (r *Rule) captures(line []byte, loc []int) (LineMatch, []string) {
	m := LineMatch{KeySize: r.KeySize, Mode: r.Mode}
	var problems []string
	if s, ok := group(line, loc, r.bitsIdx); ok {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= maxKeyBits {
			m.KeySize = n
		} else {
			problems = append(problems, fmt.Sprintf("bits group captured %q, not a key size", s))
		}
	}
	if s, ok := group(line, loc, r.modeIdx); ok {
		if up := strings.ToUpper(s); slices.Contains(Modes, up) {
			m.Mode = up
		} else {
			problems = append(problems, fmt.Sprintf("mode group captured %q, not one of %s", s, strings.Join(Modes, ", ")))
		}
	}
	return m, problems
}

// group returns the text of subexpression i, if it took part in the match.
func group(line []byte, loc []int, i int) (string, bool) {
	if i <= 0 || 2*i+1 >= len(loc) || loc[2*i] < 0 {
		return "", false
	}
	return string(line[loc[2*i]:loc[2*i+1]]), true
}
