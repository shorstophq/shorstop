package rules

import (
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
    match: { pattern: 'rsa(?P<bits>\d+)' }
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
	if m := p.Rules[1].Regexp().FindStringSubmatch("rsa2048"); m == nil || m[p.Rules[1].Regexp().SubexpIndex("bits")] != "2048" {
		t.Errorf("bits group not captured: %v", m)
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
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: goast\n    key_size: 2048\n    match: { key_size_arg: -1, pattern: x }\n",
			[]string{"need match.import", "key_size_arg needs match.call", "must not be negative", "not both", "match.pattern is for regex"},
		},
		{
			"regex field rules",
			"version: 1\nrules:\n  - id: a\n" + ok + "    detector: regex\n    match: { import: crypto/rsa }\n",
			[]string{"need match.pattern", "for goast rules, not regex"},
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
