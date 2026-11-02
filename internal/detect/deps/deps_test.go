package deps

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/rules"
)

var update = flag.Bool("update", false, "rewrite the .golden files from the current output")

const fixtures = "../../../testdata/fixtures/deps"

func builtin(t testing.TB) *Detector {
	t.Helper()
	p, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return New(p.ForDetector(rules.DetectorDeps))
}

func format(found []detect.Finding, err error) string {
	var b strings.Builder
	for _, f := range found {
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%s\t%s\n", f.Line, f.RuleID, f.Algorithm, f.Confidence, f.PURL, f.Snippet)
	}
	if err != nil {
		fmt.Fprintf(&b, "error: %v\n", err)
	}
	return b.String()
}

// TestFixtures compares every fixture under testdata/fixtures/deps with
// golden/<path>.golden. Regenerate with -update and review the diff.
func TestFixtures(t *testing.T) {
	d := builtin(t)
	ran := 0
	err := filepath.WalkDir(fixtures, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			if e.Name() == "golden" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(fixtures, p)
		rel = filepath.ToSlash(rel)
		t.Run(rel, func(t *testing.T) {
			if !d.Supports(rel, false) {
				t.Fatalf("Supports(%q) = false", rel)
			}
			ran++
			src, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			got := format(d.Detect(context.Background(), detect.File{Path: rel, Content: src}))
			golden := filepath.Join(fixtures, "golden", filepath.FromSlash(rel)+".golden")
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if got != string(want) {
				t.Errorf("findings differ from %s\n--- got ---\n%s--- want ---\n%s", golden, got, want)
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if ran < 19 {
		t.Errorf("only %d fixtures ran", ran)
	}
}

func TestNormalizeAndPURL(t *testing.T) {
	tests := []struct {
		eco, name, version string
		norm, purl         string
	}{
		{"pypi", "PyCryptodome", "3.20.0", "pycryptodome", "pkg:pypi/pycryptodome@3.20.0"},
		{"pypi", "liboqs_python", "", "liboqs-python", "pkg:pypi/liboqs-python"},
		{"pypi", "zope.interface", "", "zope-interface", "pkg:pypi/zope-interface"},
		{"npm", "@noble/curves", "1.4.0", "@noble/curves", "pkg:npm/%40noble/curves@1.4.0"},
		{"maven", "org.bouncycastle:bcprov-jdk18on", "1.78.1", "org.bouncycastle:bcprov-jdk18on", "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1"},
		{"cargo", "ed25519_dalek", "2.1.0", "ed25519-dalek", "pkg:cargo/ed25519_dalek@2.1.0"},
		{"golang", "github.com/ProtonMail/go-crypto", "v1.0.0", "github.com/ProtonMail/go-crypto", "pkg:golang/github.com/ProtonMail/go-crypto@v1.0.0"},
		{"nuget", "BouncyCastle.Cryptography", "2.4.0+build.1", "bouncycastle.cryptography", "pkg:nuget/BouncyCastle.Cryptography@2.4.0%2Bbuild.1"},
	}
	for _, tt := range tests {
		if got := normalize(tt.eco, tt.name); got != tt.norm {
			t.Errorf("normalize(%s, %q) = %q, want %q", tt.eco, tt.name, got, tt.norm)
		}
		if got := purl(tt.eco, tt.name, tt.version); got != tt.purl {
			t.Errorf("purl(%s, %q, %q) = %q, want %q", tt.eco, tt.name, tt.version, got, tt.purl)
		}
	}
}

func TestMatch(t *testing.T) {
	d := builtin(t)
	tests := []struct {
		eco, name string
		want      []string
	}{
		{"maven", "org.bouncycastle:bcprov-jdk15on", []string{"dep-maven-bouncycastle-prov"}},
		{"maven", "org.bouncycastle:bcprovx", nil}, // the wildcard follows "bcprov-", not "bcprov"
		{"pypi", "PyCryptodome", []string{"dep-pypi-pycryptodome"}},
		{"pypi", "rsa-tools", nil},
		{"npm", "md5-hex", nil},
		{"npm", "Node-Forge", []string{"dep-npm-node-forge"}}, // npm names are lower-case; spellings in old files aren't
		{"golang", "github.com/protonmail/go-crypto", nil},    // Go module paths are case-sensitive
	}
	for _, tt := range tests {
		var got []string
		if ix := d.byEco[tt.eco]; ix != nil {
			for _, r := range ix.match(normalize(tt.eco, tt.name)) {
				got = append(got, r.ID)
			}
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("match(%s, %q) = %v, want %v", tt.eco, tt.name, got, tt.want)
		}
	}
}

func TestSupports(t *testing.T) {
	d := builtin(t)
	tests := []struct {
		path string
		want bool
	}{
		{"web/package.json", true},
		{"requirements-dev.txt", true},
		{"requirements/prod.txt", true},
		{"notes.txt", false},
		{"src/App.CSPROJ", true},
		{"go.sum", false},
		{"main.go", false},
	}
	for _, tt := range tests {
		if got := d.Supports(tt.path, false); got != tt.want {
			t.Errorf("Supports(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
	if d.Supports("package.json", true) {
		t.Error("binary files are not manifests")
	}
	if New(nil).Supports("package.json", false) {
		t.Error("a detector with no rules wants files")
	}
}

func TestMalformed(t *testing.T) {
	d := builtin(t)
	for _, name := range []string{"package.json", "package-lock.json", "pom.xml", "composer.lock", "pnpm-lock.yaml"} {
		found, err := d.Detect(context.Background(), detect.File{Path: name, Content: []byte("{ not: [valid")})
		if err == nil || len(found) != 0 {
			t.Errorf("%s: got %v, %v; want an error and no findings", name, found, err)
		}
	}
}
