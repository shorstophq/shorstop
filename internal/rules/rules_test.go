package rules

import (
	"slices"
	"strings"
	"testing"
)

func TestBuiltinLoads(t *testing.T) {
	p, err := Builtin()
	if err != nil {
		t.Fatalf("embedded rules.yaml is invalid:\n%v", err)
	}
	if p.Version != FormatVersion {
		t.Errorf("version = %d, want %d", p.Version, FormatVersion)
	}
	if n := len(p.ForDetector(DetectorGoAST)); n == 0 {
		t.Error("no goast rules")
	}
	for _, r := range p.ForDetector(DetectorRegex) {
		if r.Regexp() == nil {
			t.Errorf("rule %s: pattern not compiled", r.ID)
		}
	}
	p2, _ := Builtin()
	if p != p2 {
		t.Error("Builtin parsed the pack twice")
	}
}

func TestParseDefaults(t *testing.T) {
	p, err := Parse([]byte(`
version: 1
rules:
  - id: a
    description: d
    detector: goast
    algorithm: RSA
    match: { import: crypto/rsa }
  - id: b
    description: d
    detector: regex
    algorithm: RSA
    confidence: low
    match: { keywords: [RSA], pattern: 'rsa(?P<bits>\d+)', examples: [rsa2048] }
  - id: c
    description: d
    detector: regex
    algorithm: AES
    match: { keywords: [aes], pattern: '(?i)aes-(?P<mode>[a-z]+)', examples: [aes-gcm] }
`), "t.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Rules[0].Confidence; got != ConfidenceHigh {
		t.Errorf("goast default confidence = %q, want high", got)
	}
	if got := p.Rules[1].Confidence; got != ConfidenceLow {
		t.Errorf("explicit confidence = %q, want low", got)
	}
	if got := p.Rules[1].Match.Keywords[0]; got != "rsa" {
		t.Errorf("keyword = %q, want it lower-cased", got)
	}

	b, c := &p.Rules[1], &p.Rules[2]
	tests := []struct {
		r    *Rule
		line string
		want []LineMatch
	}{
		{b, "rsa2048", []LineMatch{{KeySize: 2048}}},
		{b, "rsa99999999", []LineMatch{{}}}, // over maxKeyBits: not a key size
		{b, "dsa2048", nil},
		{b, "rsa2048 rsa4096 rsa2048", []LineMatch{{KeySize: 2048}, {KeySize: 4096}}}, // distinct, in order
		{c, "AES-CBC", []LineMatch{{Mode: "CBC"}}},                                    // upper-cased
		{c, "aes-foo", []LineMatch{{}}},                                               // not a known mode: dropped
	}
	for _, tt := range tests {
		if got := tt.r.MatchAll([]byte(tt.line)); !slices.Equal(got, tt.want) {
			t.Errorf("rule %s MatchAll(%q) = %+v, want %+v", tt.r.ID, tt.line, got, tt.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	const ok = "    description: d\n    algorithm: RSA\n"
	tests := []struct {
		name string
		yaml string
		want []string // substrings that must all appear in the error
	}{
		{"empty", ``, []string{"empty rule file"}},
		{"no version", "rules: []\n", []string{"unsupported rule format version 0"}},
		{"future version", "version: 2\nrules: []\n", []string{"version 2"}},
		{"no rules", "version: 1\nrules: []\n", []string{"no rules"}},
		{"two documents", "version: 1\n---\nversion: 1\n", []string{"more than one YAML document"}},
		{"unknown top-level field", "version: 1\nrule: []\n", []string{"field rule not found"}},
		{"misspelt rule field", "version: 1\nrules:\n  - id: a\n    key_sise: 1\n", []string{"field key_sise not found"}},
		{
			"missing everything",
			"version: 1\nrules:\n  - match: {}\n",
			[]string{"t.yaml:3:", "missing id", "missing description", "missing algorithm", "missing detector"},
		},
		{
			"bad names",
			"version: 1\nrules:\n  - id: Bad_ID\n    description: d\n    detector: nope\n    algorithm: SHA1\n    primitive: cipher\n    confidence: sure\n",
			[]string{"id must be lowercase", `unknown detector "nope"`, `unknown algorithm "SHA1"`, `unknown primitive "cipher"`, `unknown confidence "sure"`},
		},
		{
			"duplicate id, reports both lines",
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: goast\n    match: { import: x }\n  - id: a\n" + ok + "    detector: goast\n    match: { import: x }\n",
			[]string{"t.yaml:8:", "duplicate id (first used on line 3)"},
		},
		{
			"goast field rules",
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: goast\n    key_size: 2048\n    languages: [go]\n    match: { key_size_arg: -1, pattern: x, keywords: [x] }\n",
			[]string{"need match.import", "key_size_arg needs match.call", "must not be negative", "not both", "are for regex rules, not goast", "goast rules are Go-only"},
		},
		{
			"regex field rules",
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: regex\n    languages: [cobol]\n    mode: XYZ\n    match: { import: crypto/rsa, keywords: ['' ] }\n",
			[]string{"need match.pattern", "for goast rules, not regex", `unknown language "cobol"`, `unknown mode "XYZ"`, `match.keywords[0] "" must be at least 3`},
		},
		{
			"bad keywords",
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: regex\n    match: { keywords: [ab, 'ключ'], pattern: x, examples: [x] }\n",
			[]string{`keywords[0] "ab"`, `keywords[1] "ключ"`},
		},
		{
			"regex needs keywords and examples",
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: regex\n    match: { pattern: rsa }\n",
			[]string{"need match.keywords", "need match.examples"},
		},
		{
			"examples are checked",
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: regex\n    match:\n      keywords: [rsa]\n      pattern: '(?i)rsa-(?P<bits>\\d+)-(?P<mode>\\w+)'\n      examples: [dsa, 'RSA-0-ecb', 'x', 'rsa-2048-foo']\n",
			[]string{
				"examples[0] does not match", "examples[2] contains none of the keywords",
				`examples[1]: bits group captured "0"`, `examples[3]: mode group captured "foo"`,
			},
		},
		{
			"deps rules",
			"version: 1\nrules:\n" +
				"  - { id: a, description: d, detector: deps, match: { ecosystem: npm } }\n" +
				"  - { id: b, description: d, detector: deps, match: { ecosystem: cpan, package: '*' } }\n" +
				"  - { id: c, description: d, detector: deps, match: { ecosystem: npm, package: 'a*b' } }\n" +
				"  - { id: e, description: d, detector: deps, match: { ecosystem: npm, package: 'forge*' } }\n" +
				"  - { id: f, description: d, detector: deps, languages: [go], match: { ecosystem: npm, package: x, pattern: y } }\n" +
				"  - { id: g, description: d, detector: regex, algorithm: RSA, match: { ecosystem: npm, keywords: [rsa], pattern: rsa, examples: [rsa] } }\n",
			[]string{
				`t.yaml:3: rule "a": deps rules need match.package`,
				`t.yaml:4: rule "b": unknown or missing match.ecosystem "cpan"`, `t.yaml:4: rule "b": deps rules need match.package`,
				`rule "c": match.package may only end in "*"`,
				`rule "e": match.package "forge*": a wildcard needs a separator`,
				`rule "f": deps rules take only`, `rule "f": languages is for regex rules`,
				`rule "g": match.ecosystem and match.package are for deps rules, not regex`,
			},
		},
		{
			"pattern matching everything",
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: regex\n    match: { keywords: [a], pattern: 'a*', examples: [a] }\n",
			[]string{"matches the empty string"},
		},
		{
			"mode and mode group",
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: regex\n    mode: ECB\n    match: { keywords: [a], pattern: 'a(?P<mode>x)', examples: [ax] }\n",
			[]string{"set mode or a (?P<mode>...) group"},
		},
		{
			"bad regex",
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: regex\n    match: { pattern: '(' }\n",
			[]string{"match.pattern: error parsing regexp"},
		},
		{
			"key_size and bits group",
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: regex\n    key_size: 2048\n    match: { pattern: '(?P<bits>\\d+)' }\n",
			[]string{"set key_size or a (?P<bits>...) group"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml), "t.yaml")
			if err == nil {
				t.Fatal("Parse succeeded, want error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error does not mention %q:\n%v", w, err)
				}
			}
		})
	}
}
