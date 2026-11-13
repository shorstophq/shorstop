package rules

import (
	"os"
	"testing"
)

// FuzzParse: --rules files and the rules: list in .shorstop.yaml come from
// the scanned repository. A pack that parses must also be safe to match
// with: its regular expressions run on every line of every file.
func FuzzParse(f *testing.F) {
	data, err := os.ReadFile("rules.yaml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data, []byte("x := rsa.GenerateKey(rand.Reader, 2048)"))
	f.Add([]byte("version: 1\nrules:\n  - id: my-rsa\n    detector: regex\n    algorithm: RSA\n    match:\n      pattern: 'RSA(\\d+)'\n      key-size-group: 1\n"), []byte("RSA1024 RSA99999999999999999999"))
	f.Fuzz(func(t *testing.T, data, line []byte) {
		p, err := Parse(data, "fuzz.yaml")
		if err != nil {
			return
		}
		for _, r := range p.Rules {
			if r.Regexp() != nil {
				r.MatchAll(line)
			}
		}
	})
}
