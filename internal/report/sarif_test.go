package report

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/shorstop/shorstop/internal/crawler"
	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/detect/cert"
	"github.com/shorstop/shorstop/internal/detect/config"
	"github.com/shorstop/shorstop/internal/rules"
)

func sarifSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	const id = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	f, err := os.Open(filepath.Join(testdata, "sarif", "sarif-schema-2.1.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func catalog(t *testing.T) Catalog {
	t.Helper()
	p, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return NewCatalog(p, cert.RuleDescriptions, config.RuleDescriptions)
}

func decodeSARIF(t *testing.T, data []byte) sarifLog {
	t.Helper()
	var l sarifLog
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

// TestSARIFOfAllFixturesIsValid renders every fixture finding as SARIF and
// validates it against the OASIS SARIF 2.1.0 schema. It also checks that
// every rule any detector emits has a real description: a rule ID with no
// catalog entry would show as "ShorStop rule x." in code scanning.
func TestSARIFOfAllFixturesIsValid(t *testing.T) {
	res, err := crawler.Scan(context.Background(), crawler.Options{
		Root: filepath.Join(testdata, "fixtures"), Workers: runtime.GOMAXPROCS(0), MaxFileSize: 2 << 20,
	}, allDetectors(t))
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog(t)
	for _, f := range res.Findings {
		if cat[f.RuleID] == "" {
			t.Errorf("rule %s (%s) has no description", f.RuleID, f.Detector)
		}
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, res.Findings, SARIFOptions{ToolVersion: "v0.0.0-test", Catalog: cat, IncludeInfo: true}); err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := sarifSchema(t).Validate(doc); err != nil {
		t.Fatalf("not valid SARIF 2.1.0:\n%v", err)
	}
	if l := decodeSARIF(t, buf.Bytes()); len(l.Runs[0].Results) != len(res.Findings) {
		t.Errorf("%d results for %d findings", len(l.Runs[0].Results), len(res.Findings))
	}
}

func TestSARIFGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, goldenFindings(), SARIFOptions{ToolVersion: "v0.0.0-test", Catalog: catalog(t)}); err != nil {
		t.Fatal(err)
	}
	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(buf.Bytes()))
	if err := sarifSchema(t).Validate(doc); err != nil {
		t.Fatalf("not valid SARIF 2.1.0:\n%v", err)
	}
	golden := filepath.Join(testdata, "report", "sarif.golden.json")
	if *update {
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
		t.Errorf("SARIF differs from %s; run with -update and review the diff", golden)
	}
}

func TestSARIFSemantics(t *testing.T) {
	fs := []detect.Finding{
		{RuleID: "go-rsa-generate-key", Algorithm: "RSA", KeySize: 4096, File: "a.go", Line: 3, Snippet: "x"},
		{RuleID: "go-rsa-generate-key", Algorithm: "RSA", KeySize: 1024, File: "a.go", Line: 9, Snippet: "y"},
		{RuleID: "go-sha256-import", Algorithm: "SHA-256", Primitive: "hash", File: "a.go", Line: 1},
		{RuleID: "cert-public-key", Algorithm: "RSA", KeySize: 2048, AssetType: detect.AssetCertificate, File: "certs/my ca.der"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, fs, SARIFOptions{Catalog: catalog(t)}); err != nil {
		t.Fatal(err)
	}
	run := decodeSARIF(t, buf.Bytes()).Runs[0]

	if len(run.Results) != 3 {
		t.Fatalf("got %d results; info findings (SHA-256) should be left out by default", len(run.Results))
	}
	var rsaRule sarifRule
	for _, r := range run.Tool.Driver.Rules {
		if r.ID == "go-rsa-generate-key" {
			rsaRule = r
		}
	}
	if rsaRule.Properties.SecuritySeverity != "9.5" || !strings.Contains(rsaRule.Help.Text, "Recommendation:") {
		t.Errorf("rule should carry the worst severity among its results (RSA-1024, critical): %+v", rsaRule)
	}
	levels := map[int]string{}
	for _, r := range run.Results {
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex %d does not point at %s", r.RuleIndex, r.RuleID)
		}
		if r.Locations[0].PhysicalLocation.Region != nil {
			levels[r.Locations[0].PhysicalLocation.Region.StartLine] = r.Level
		}
	}
	if levels[3] != "error" || levels[9] != "error" {
		t.Errorf("levels = %v", levels)
	}
	var der sarifPhysical
	for _, r := range run.Results {
		if strings.HasPrefix(r.Locations[0].PhysicalLocation.ArtifactLocation.URI, "certs/") {
			der = r.Locations[0].PhysicalLocation
		}
	}
	if der.ArtifactLocation.URI != "certs/my%20ca.der" || der.Region != nil {
		t.Errorf("binary file location = %+v; want an escaped URI and no region", der)
	}
}

// TestFingerprintIgnoresLine: moving code doesn't turn a known (or
// dismissed) alert into a new one.
func TestFingerprintIgnoresLine(t *testing.T) {
	f := detect.Finding{RuleID: "go-md5-import", Algorithm: "MD5", File: "a.go", Line: 3, Snippet: `"crypto/md5"`}
	g := f
	g.Line = 40
	if fingerprint(f) != fingerprint(g) {
		t.Error("fingerprint depends on the line number")
	}
	g.File = "b.go"
	if fingerprint(f) == fingerprint(g) {
		t.Error("fingerprint ignores the file")
	}
}

func TestSARIFEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, nil, SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"results": []`) || !strings.Contains(buf.String(), `"rules": []`) {
		t.Errorf("an empty scan must still be a valid log with empty arrays:\n%s", buf.String())
	}
}
