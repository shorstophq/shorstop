package report

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/shorstophq/shorstop/internal/crawler"
	"github.com/shorstophq/shorstop/internal/detect"
	"github.com/shorstophq/shorstop/internal/detect/cert"
	"github.com/shorstophq/shorstop/internal/detect/config"
	"github.com/shorstophq/shorstop/internal/detect/deps"
	"github.com/shorstophq/shorstop/internal/detect/goast"
	"github.com/shorstophq/shorstop/internal/detect/regex"
	"github.com/shorstophq/shorstop/internal/rules"
	"github.com/shorstophq/shorstop/pkg/cbom"
)

var update = flag.Bool("update", false, "rewrite the .golden files from the current output")

const testdata = "../../testdata"

var fixedOpts = CBOMOptions{
	ProjectName:  "fixture",
	ToolVersion:  "v0.0.0-test",
	Timestamp:    time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC),
	SerialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000",
}

// cdxSchema compiles the official CycloneDX 1.6 schema from the copies in
// testdata/cyclonedx, offline: each file is registered under its $id so the
// $refs between them resolve without the network.
func cdxSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat() // date-time, uri, ... are checked too
	for _, name := range []string{"bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"} {
		f, err := os.Open(filepath.Join(testdata, "cyclonedx", name))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource("http://cyclonedx.org/schema/"+name, doc); err != nil {
			t.Fatal(err)
		}
	}
	s, err := c.Compile("http://cyclonedx.org/schema/bom-1.6.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validate(t *testing.T, s *jsonschema.Schema, data []byte) {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(doc); err != nil {
		t.Fatalf("CBOM is not valid CycloneDX 1.6:\n%v", err)
	}
}

func allDetectors(t testing.TB) []detect.Detector {
	t.Helper()
	p, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return []detect.Detector{
		goast.New(p.ForDetector(rules.DetectorGoAST)), cert.New(), config.New(),
		deps.New(p.ForDetector(rules.DetectorDeps)), regex.New(p.ForDetector(rules.DetectorRegex)),
	}
}

// TestCBOMOfAllFixturesIsValid is the plan's acceptance test: every finding
// every detector makes on the fixtures renders into a schema-valid CBOM.
func TestCBOMOfAllFixturesIsValid(t *testing.T) {
	res, err := crawler.Scan(context.Background(), crawler.Options{
		Root: filepath.Join(testdata, "fixtures"), Workers: runtime.GOMAXPROCS(0), MaxFileSize: 2 << 20,
	}, allDetectors(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) < 300 {
		t.Fatalf("only %d findings: fixtures missing?", len(res.Findings))
	}
	var buf bytes.Buffer
	if err := WriteCBOM(&buf, CBOM(res.Findings, fixedOpts)); err != nil {
		t.Fatal(err)
	}
	validate(t, cdxSchema(t), buf.Bytes())

	// Every asset type is represented, so the schema check covers them all.
	var bom cbom.BOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range bom.Components {
		if c.CryptoProperties != nil {
			seen[c.CryptoProperties.AssetType] = true
		} else {
			seen[c.Type] = true
		}
	}
	for _, want := range []string{"algorithm", "certificate", "protocol", "related-crypto-material", "library"} {
		if !seen[want] {
			t.Errorf("no %s component in the fixtures' CBOM", want)
		}
	}
}

// goldenFindings covers each kind of component once.
func goldenFindings() []detect.Finding {
	notBefore := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	return []detect.Finding{
		{RuleID: "go-rsa-generate-key", Algorithm: "RSA", KeySize: 2048, File: "a.go", Line: 10, Snippet: "rsa.GenerateKey(r, 2048)", Confidence: "high"},
		{RuleID: "generic-rsa-bits", Algorithm: "RSA", KeySize: 2048, File: "README.md", Line: 3, Snippet: "rsa:2048", Confidence: "medium"},
		{RuleID: "generic-aes-cipher-string", Algorithm: "AES", Primitive: "block-cipher", KeySize: 128, Mode: "ECB", File: "b.js", Line: 2, Confidence: "medium"},
		{RuleID: "tls-group", Algorithm: "ML-KEM", Primitive: "kem", ParameterSet: "ML-KEM-768", File: "nginx.conf", Line: 8, Confidence: "high"},
		{RuleID: "cert-public-key", Algorithm: "RSA", KeySize: 2048, AssetType: detect.AssetCertificate, File: "ca.pem", Line: 1, Confidence: "high",
			Cert: &detect.Certificate{Subject: "CN=Old CA", Issuer: "CN=Old CA", NotBefore: notBefore, NotAfter: notBefore.AddDate(5, 0, 0)}},
		{RuleID: "cert-signature", Algorithm: "RSA", Primitive: "signature", File: "ca.pem", Line: 1, Confidence: "high"},
		{RuleID: "cert-signature-hash", Algorithm: "SHA-1", Primitive: "hash", File: "ca.pem", Line: 1, Confidence: "high"},
		{RuleID: "private-key-committed", Algorithm: "RSA", KeySize: 2048, AssetType: detect.AssetMaterial, MaterialType: detect.MaterialPrivateKey, File: "k.key", Line: 1, Snippet: "-----BEGIN RSA PRIVATE KEY-----", Confidence: "high"},
		{RuleID: "tls-protocol-version", AssetType: detect.AssetProtocol, Protocol: detect.TLSv10, File: "nginx.conf", Line: 5, Confidence: "high"},
		{RuleID: "dep-npm-node-rsa", Algorithm: "RSA", File: "package.json", Line: 4, PURL: "pkg:npm/node-rsa", Confidence: "low"},
		{RuleID: "dep-npm-node-rsa", Algorithm: "RSA", File: "package-lock.json", Line: 9, PURL: "pkg:npm/node-rsa@1.1.1", Confidence: "low"},
		{RuleID: "dep-npm-node-forge", File: "package.json", Line: 5, PURL: "pkg:npm/node-forge", Confidence: "low"},
	}
}

// TestCBOMGolden pins the exact output for a small set of findings, so any
// change to the CBOM's shape shows up as a reviewable diff.
func TestCBOMGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCBOM(&buf, CBOM(goldenFindings(), fixedOpts)); err != nil {
		t.Fatal(err)
	}
	validate(t, cdxSchema(t), buf.Bytes())
	golden := filepath.Join(testdata, "report", "cbom.golden.json")
	if *update {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("CBOM differs from %s; run with -update and review the diff", golden)
	}
}

func TestCBOMIsDeterministic(t *testing.T) {
	fs := goldenFindings()
	var a, b bytes.Buffer
	if err := WriteCBOM(&a, CBOM(fs, fixedOpts)); err != nil {
		t.Fatal(err)
	}
	slices.Reverse(fs) // scan order must not matter
	if err := WriteCBOM(&b, CBOM(fs, fixedOpts)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("the same findings in another order give a different CBOM")
	}
}

func TestCBOMSemantics(t *testing.T) {
	bom := CBOM(goldenFindings(), fixedOpts)
	byRef := map[string]cbom.Component{}
	for _, c := range bom.Components {
		byRef[c.BOMRef] = c
	}
	prop := func(c cbom.Component, name string) string {
		for _, p := range c.Properties {
			if p.Name == name {
				return p.Value
			}
		}
		return ""
	}

	rsa := byRef["crypto:algorithm:RSA-2048:unknown"]
	if rsa.Evidence == nil || len(rsa.Evidence.Occurrences) != 3 {
		t.Errorf("RSA-2048 should group a.go, README.md and the certificate's key: %+v", rsa.Evidence)
	}
	if got := prop(rsa, "shorstop:confidence"); got != "high" {
		t.Errorf("grouped confidence = %q, want the highest (high)", got)
	}

	var key, certC cbom.Component
	for ref, c := range byRef {
		switch {
		case strings.HasPrefix(ref, "crypto:private-key:"):
			key = c
		case strings.HasPrefix(ref, "crypto:certificate:"):
			certC = c
		}
	}
	if m := key.CryptoProperties.RelatedCryptoMaterialProperties; m.State != "compromised" || m.AlgorithmRef != "crypto:algorithm:RSA-2048:unknown" {
		t.Errorf("private key: %+v", m)
	}
	cp := certC.CryptoProperties.CertificateProperties
	if cp.SubjectPublicKeyRef != "crypto:algorithm:RSA-2048:unknown" || cp.SignatureAlgorithmRef != "crypto:algorithm:RSA:signature" {
		t.Errorf("certificate refs: %+v", cp)
	}
	if prop(certC, "shorstop:severity") != "critical" || prop(certC, "shorstop:expired") != "true" {
		t.Errorf("a SHA-1-signed, expired certificate: %v", certC.Properties)
	}

	lib := byRef["pkg:npm/node-rsa"]
	if lib.Type != cbom.TypeLibrary || lib.Version != "1.1.1" || lib.PURL != "pkg:npm/node-rsa@1.1.1" || len(lib.Evidence.Occurrences) != 2 {
		t.Errorf("library: %+v", lib)
	}
	var provides []string
	for _, d := range bom.Dependencies {
		if d.Ref == "pkg:npm/node-rsa" {
			provides = d.Provides
		}
	}
	if !slices.Equal(provides, []string{"crypto:algorithm:RSA:unknown"}) {
		t.Errorf("node-rsa provides %v", provides)
	}
	if p := byRef["crypto:protocol:tls:TLSv1.0"].CryptoProperties.ProtocolProperties; p.Type != "tls" || p.Version != "1.0" {
		t.Errorf("protocol: %+v", p)
	}
	if ap := byRef["crypto:algorithm:AES-128-ECB:block-cipher"].CryptoProperties.AlgorithmProperties; ap.Mode != "ecb" || ap.ClassicalSecurityLevel != 128 {
		t.Errorf("AES: %+v", ap)
	}
	if ap := byRef["crypto:algorithm:ML-KEM-768:kem"].CryptoProperties.AlgorithmProperties; ap.NISTQuantumSecurityLevel != 3 || ap.ParameterSetIdentifier != "ML-KEM-768" {
		t.Errorf("ML-KEM: %+v", ap)
	}
}

func TestHelpers(t *testing.T) {
	for _, tt := range []struct {
		f    detect.Finding
		want string
	}{
		{detect.Finding{Algorithm: "RSA", KeySize: 3072}, "RSA-3072"},
		{detect.Finding{Algorithm: "AES", KeySize: 256, Mode: "GCM"}, "AES-256-GCM"},
		{detect.Finding{Algorithm: "EdDSA", KeySize: 255}, "Ed25519"},
		{detect.Finding{Algorithm: "X25519", KeySize: 255}, "X25519"},
		{detect.Finding{Algorithm: "3DES", KeySize: 168, Mode: "CBC"}, "3DES-CBC"},
		{detect.Finding{Algorithm: "ML-KEM", ParameterSet: "ML-KEM-1024"}, "ML-KEM-1024"},
		{detect.Finding{Algorithm: "SHA-256"}, "SHA-256"},
	} {
		if got := algName(tt.f); got != tt.want {
			t.Errorf("algName(%+v) = %q, want %q", tt.f, got, tt.want)
		}
	}
	for in, want := range map[string]string{"": "", "GCM": "gcm", "ECB": "ecb", "XTS": "other", "SIV": "other"} {
		if got := cdxMode(in); got != want {
			t.Errorf("cdxMode(%q) = %q, want %q", in, got, want)
		}
	}
	if n, v := purlParts("pkg:npm/%40noble/curves@1.4.0"); n != "@noble/curves" || v != "1.4.0" {
		t.Errorf("purlParts: %q %q", n, v)
	}
	if n, v := purlParts("pkg:maven/org.bouncycastle/bcprov-jdk18on"); n != "org.bouncycastle/bcprov-jdk18on" || v != "" {
		t.Errorf("purlParts: %q %q", n, v)
	}
	s, err := NewSerialNumber()
	if err != nil || len(s) != len("urn:uuid:00000000-0000-4000-8000-000000000000") || s[23] != '4' {
		t.Errorf("NewSerialNumber() = %q, %v", s, err)
	}
}
