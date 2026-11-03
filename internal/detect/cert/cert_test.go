package cert

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"crypto/x509"

	"github.com/shorstophq/shorstop/internal/detect"
	"github.com/shorstophq/shorstop/internal/rules"
)

var update = flag.Bool("update", false, "rewrite the .golden files from the current output")

const fixtures = "../../../testdata/fixtures/cert"

func load(t *testing.T, name string) detect.File {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	// The crawler's rule: a NUL byte in the first 8000 bytes means binary.
	head := src[:min(len(src), 8000)]
	return detect.File{Path: name, Content: src, Binary: bytes.IndexByte(head, 0) >= 0}
}

func format(found []detect.Finding, err error) string {
	var b strings.Builder
	for _, f := range found {
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s",
			f.Line, f.RuleID, f.Algorithm, f.Primitive, f.KeySize, f.ParameterSet,
			f.AssetType, f.MaterialType, f.Confidence, f.Snippet)
		if c := f.Cert; c != nil {
			fmt.Fprintf(&b, "\tsubject=%q issuer=%q valid=%s..%s", c.Subject, c.Issuer,
				c.NotBefore.Format(time.DateOnly), c.NotAfter.Format(time.DateOnly))
		}
		b.WriteByte('\n')
	}
	if err != nil {
		fmt.Fprintf(&b, "error: %v\n", err)
	}
	return b.String()
}

// TestFixtures runs every fixture the detector supports and compares the
// result with testdata/fixtures/cert/golden/<name>.golden. Regenerate with
// -update and review the diff.
func TestFixtures(t *testing.T) {
	d := New()
	entries, err := os.ReadDir(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == "gen.go" || name == "gen.sh" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			f := load(t, name)
			if !d.Supports(f.Path, f.Binary) {
				t.Fatalf("Supports(%q, binary=%v) = false", f.Path, f.Binary)
			}
			ran++
			got := format(d.Detect(context.Background(), f))
			golden := filepath.Join(fixtures, "golden", name+".golden")
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
	}
	if ran < 20 {
		t.Errorf("only %d fixtures ran", ran)
	}
}

// TestNoKeyMaterialInSnippets guards the one rule that matters most here: a
// report must never contain the secret it is warning about.
func TestNoKeyMaterialInSnippets(t *testing.T) {
	d := New()
	for _, name := range []string{"rsa-pkcs1.key", "ec-pkcs8.key", "embedded.go.txt", "id_rsa", "id_ed25519_enc", "encrypted-pkcs8.key"} {
		f := load(t, name)
		found, _ := d.Detect(context.Background(), f)
		if len(found) == 0 {
			t.Errorf("%s: no findings", name)
		}
		for _, fd := range found {
			if strings.Contains(fd.Snippet, "MII") || len(fd.Snippet) > 40 {
				t.Errorf("%s: snippet may contain key material: %q", name, fd.Snippet)
			}
		}
	}
}

func TestSupports(t *testing.T) {
	d := New()
	tests := []struct {
		path   string
		binary bool
		want   bool
	}{
		{"main.go", false, true}, // any text file: PEM can be embedded anywhere
		{"certs/ca.der", true, true},
		{"certs/CA.CRT", true, true},
		{"keys/store.p12", true, true},
		{"keys/store.pfx", false, true},
		{"image.png", true, false},
		{"tool.exe", true, false},
	}
	for _, tt := range tests {
		if got := d.Supports(tt.path, tt.binary); got != tt.want {
			t.Errorf("Supports(%q, %v) = %v, want %v", tt.path, tt.binary, got, tt.want)
		}
	}
}

// TestAlgorithmNamesAreKnown checks every name the mapping functions can
// produce against the closed set the classifier covers.
func TestAlgorithmNamesAreKnown(t *testing.T) {
	check := func(what, alg string) {
		if alg != "" && !slices.Contains(rules.Algorithms, alg) {
			t.Errorf("%s: %q is not in rules.Algorithms", what, alg)
		}
	}
	for a := x509.UnknownSignatureAlgorithm; a <= x509.MLDSA87+1; a++ {
		si := sigInfo(a)
		check(a.String(), si.signer)
		check(a.String(), si.hash)
	}
	for _, typ := range []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-rsa", "ssh-dss"} {
		check(typ, sshTypeInfo(typ).alg)
	}
	for _, typ := range []string{"RSA PRIVATE KEY", "DSA PRIVATE KEY", "EC PRIVATE KEY"} {
		check(typ, parsePrivateKey(typ, nil).Algorithm)
	}
	check("dh", "DH")
	check("ecc", "ECC")
}

func TestNoPEMMarkerIsCheap(t *testing.T) {
	found, err := New().Detect(context.Background(), detect.File{Path: "a.go", Content: []byte("package a\n")})
	if found != nil || err != nil {
		t.Errorf("got %v, %v; want nothing", found, err)
	}
}

func TestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New().Detect(ctx, load(t, "chain.pem"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
