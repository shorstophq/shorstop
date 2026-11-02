package config

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

const fixtures = "../../../testdata/fixtures/config"

func format(found []detect.Finding, err error) string {
	var b strings.Builder
	for _, f := range found {
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			f.Line, f.RuleID, f.Algorithm, f.Primitive, f.KeySize, f.Mode, f.ParameterSet,
			f.AssetType, f.Protocol, f.Snippet)
	}
	if err != nil {
		fmt.Fprintf(&b, "error: %v\n", err)
	}
	return b.String()
}

// TestFixtures compares every fixture under testdata/fixtures/config with
// golden/<path>.golden. Regenerate with -update and review the diff.
func TestFixtures(t *testing.T) {
	d := New()
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
	if ran < 11 {
		t.Errorf("only %d fixtures ran", ran)
	}
}

// names renders algos compactly for table tests: "ECDH", "AES-128-GCM", ...
func names(as []algo) []string {
	var out []string
	for _, a := range as {
		s := a.alg
		if a.bits != 0 {
			s += fmt.Sprintf("-%d", a.bits)
		}
		if a.mode != "" {
			s += "-" + a.mode
		}
		if a.param != "" {
			s += "(" + a.param + ")"
		}
		if a.prim != "" {
			s += "/" + a.prim
		}
		out = append(out, s)
	}
	return out
}

func TestCipherString(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		// Removals, reorderings, options and build-defined sets enable nothing.
		{"HIGH:!aNULL:!MD5:!3DES:-RC4:+SHA1:@SECLEVEL=2:DEFAULT", nil},
		// OpenSSL suite names.
		{"ECDHE-ECDSA-AES128-GCM-SHA256", []string{"ECDH/key-agree", "ECDSA/signature", "AES-128-GCM/block-cipher", "SHA-256/kdf"}},
		{"DHE-RSA-AES256-SHA", []string{"DH/key-agree", "RSA/signature", "AES-256-CBC/block-cipher", "SHA-1/mac"}},
		{"ECDHE-RSA-CHACHA20-POLY1305", []string{"ECDH/key-agree", "RSA/signature", "ChaCha20/ae"}},
		// No key exchange named: RSA key transport is implied.
		{"DES-CBC3-SHA", []string{"RSA/pke", "3DES-168-CBC/block-cipher", "SHA-1/mac"}},
		{"RC4-MD5", []string{"RSA/pke", "RC4/stream-cipher", "MD5/mac"}},
		{"AES128-SHA", []string{"RSA/pke", "AES-128-CBC/block-cipher", "SHA-1/mac"}},
		// IANA names, including TLS 1.3 (no key exchange in the name).
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", []string{"ECDH/key-agree", "RSA/signature", "AES-128-CBC/block-cipher", "SHA-1/mac"}},
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", []string{"RSA/pke", "3DES-168-CBC/block-cipher", "SHA-1/mac"}},
		{"TLS_AES_256_GCM_SHA384", []string{"AES-256-GCM/block-cipher", "SHA-384/kdf"}},
		// PSK key exchange is not public-key: no RSA implied.
		{"PSK-AES128-CBC-SHA", []string{"AES-128-CBC/block-cipher", "SHA-1/mac"}},
		// Single-algorithm terms, alone and combined with "+".
		{"EECDH+AESGCM:RC4", []string{"ECDH/key-agree", "AES-GCM/block-cipher", "RC4/stream-cipher"}},
		// Ciphers outside the closed set give their other parts only.
		{"ECDHE-RSA-CAMELLIA256-SHA384", []string{"ECDH/key-agree", "RSA/signature", "SHA-384/mac"}},
		// Not cipher suites.
		{"TLSv1.2:FOO-BAR", nil},
	}
	for _, tt := range tests {
		if got := names(cipherString(tt.in)); !slices.Equal(got, tt.want) {
			t.Errorf("cipherString(%q)\n got  %q\n want %q", tt.in, got, tt.want)
		}
	}
}

func TestProtocols(t *testing.T) {
	tests := []struct {
		in   string
		min  bool
		want []string
	}{
		{"TLSv1 TLSv1.2 TLSv1.3", false, []string{"TLSv1.0", "TLSv1.2", "TLSv1.3"}},
		{"all -SSLv3 -TLSv1 -TLSv1.1", false, []string{"TLSv1.2", "TLSv1.3"}},
		{"+TLSv1.3 +TLSv1.1", false, []string{"TLSv1.1", "TLSv1.3"}}, // oldest first
		{"SSLv3, !SSLv3, TLSv1.2", false, []string{"TLSv1.2"}},
		{"bogus", false, nil},
		{"TLSv1.1", true, []string{"TLSv1.1", "TLSv1.2", "TLSv1.3"}},
		{"'TLSv1.2'", true, []string{"TLSv1.2", "TLSv1.3"}},
		{"None", true, nil},
	}
	for _, tt := range tests {
		f := protocolList
		if tt.min {
			f = minProtocol
		}
		if got := f(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("(min=%v) %q = %q, want %q", tt.min, tt.in, got, tt.want)
		}
	}
}

func TestSSHLists(t *testing.T) {
	tests := []struct {
		in   string
		fn   func(string) []algo
		want []string
	}{
		{"sntrup761x25519-sha512@openssh.com,-ecdh-sha2-nistp256,+diffie-hellman-group14-sha1", sshKex,
			[]string{"sntrup761/kem", "X25519-255/key-agree", "DH-2048/key-agree", "SHA-1/hash"}},
		{"mlkem768x25519-sha256,diffie-hellman-group-exchange-sha256,ext-info-c", sshKex,
			[]string{"ML-KEM(ML-KEM-768)/kem", "X25519-255/key-agree", "DH/key-agree"}},
		{"aes128-ctr,aes256-gcm@openssh.com,3des-cbc,blowfish-cbc,arcfour", sshCipher,
			[]string{"AES-128-CTR/block-cipher", "AES-256-GCM/block-cipher", "3DES-168-CBC/block-cipher", "RC4/stream-cipher"}},
		{"hmac-sha1-etm@openssh.com,hmac-md5-96,umac-128@openssh.com", sshMAC, []string{"SHA-1/mac", "MD5/mac"}},
		{"ssh-rsa-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,^ssh-ed25519,ssh-*", sshKeyAlg,
			[]string{"RSA/signature", "SHA-1/hash", "ECDSA-256/signature", "EdDSA-255/signature"}},
	}
	for _, tt := range tests {
		if got := names(sshList(tt.in, tt.fn)); !slices.Equal(got, tt.want) {
			t.Errorf("sshList(%q)\n got  %q\n want %q", tt.in, got, tt.want)
		}
	}
}

func TestStatements(t *testing.T) {
	src := "a b;\n" +
		"# whole-line comment\n" +
		"ssl_ciphers 'X:'\n" +
		"   'Y'; # trailing comment\n" +
		"SSLProtocol all \\\n" +
		"   -SSLv3\n" +
		"key = 'v#1' # c\n" +
		"[ section ]\n" +
		"ssl_protocols TLSv1.2\n" + // nginx-like but no ";" anywhere after: kept as one line
		"next line\n"
	got := statements([]byte(src))
	want := []stmt{
		{key: "a", value: "b", line: 1},
		{key: "ssl_ciphers", value: "'X:'    'Y'", line: 3},
		{key: "sslprotocol", value: "all     -SSLv3", line: 5},
		{key: "key", value: "'v#1'", line: 7},
		{key: "ssl_protocols", value: "TLSv1.2", line: 9},
		{key: "next", value: "line", line: 10},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d statements, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.key != w.key || g.value != w.value || g.line != w.line {
			t.Errorf("statement %d = {%q %q %d}, want {%q %q %d}", i, g.key, g.value, g.line, w.key, w.value, w.line)
		}
	}
}

func TestSupports(t *testing.T) {
	d := New()
	tests := []struct {
		path string
		want bool
	}{
		{"etc/nginx/nginx.conf", true},
		{"etc/nginx/sites-enabled/example.com", true},
		{"etc/ssh/sshd_config", true},
		{"etc/ssh/sshd_config.d/10-legacy.conf", true},
		{"openssl.cnf", true},
		{"haproxy.cfg", true},
		{"deploy/secret.yaml", true},
		{"main.go", false},
		{"README.md", false},
	}
	for _, tt := range tests {
		if got := d.Supports(tt.path, false); got != tt.want {
			t.Errorf("Supports(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
	if d.Supports("nginx.conf", true) {
		t.Error("binary files are not configuration")
	}
}

// TestAlgorithmNamesAreKnown checks every name the tables can produce
// against the closed set the classifier covers.
func TestAlgorithmNamesAreKnown(t *testing.T) {
	var all []algo
	for _, as := range cipherKeywords {
		all = append(all, as...)
	}
	for _, as := range groupAlgos {
		all = append(all, as...)
	}
	for _, a := range mdNames {
		all = append(all, a)
	}
	for _, s := range []string{"ECDHE-ECDSA-AES128-GCM-SHA256", "DHE-DSS-DES-CBC3-SHA", "RC4-MD5", "TLS_CHACHA20_POLY1305_SHA256"} {
		all = append(all, parseSuite(s)...)
	}
	all = append(all, sshList("sntrup761x25519-sha512,mlkem768nistp256-sha256,diffie-hellman-group1-sha1", sshKex)...)
	all = append(all, sshList("chacha20-poly1305@openssh.com,rijndael-cbc@lysator.liu.se,arcfour", sshCipher)...)
	all = append(all, sshList("hmac-md5,hmac-sha2-512", sshMAC)...)
	all = append(all, sshList("ssh-dss,rsa-sha2-256,ssh-ed25519,ecdsa-sha2-nistp521", sshKeyAlg)...)
	for _, a := range all {
		if !slices.Contains(rules.Algorithms, a.alg) {
			t.Errorf("%q is not in rules.Algorithms", a.alg)
		}
		if a.prim != "" && !slices.Contains(rules.Primitives, a.prim) {
			t.Errorf("primitive %q is not in rules.Primitives", a.prim)
		}
		if a.mode != "" && !slices.Contains(rules.Modes, a.mode) {
			t.Errorf("mode %q is not in rules.Modes", a.mode)
		}
	}
}
