package baseline

import (
	"bytes"
	"testing"
	"time"

	"github.com/shorstophq/shorstop/internal/detect"
	"github.com/shorstophq/shorstop/internal/report"
)

func scan() []detect.Finding {
	return []detect.Finding{
		{RuleID: "go-md5-import", Algorithm: "MD5", Primitive: "hash", File: "a.go", Line: 3, Snippet: `"crypto/md5"`},
		{RuleID: "go-rsa-generate-key", Algorithm: "RSA", KeySize: 1024, File: "a.go", Line: 9, Snippet: "rsa.GenerateKey(r, 1024)"},
		{RuleID: "private-key-committed", Algorithm: "RSA", KeySize: 2048, AssetType: detect.AssetMaterial, MaterialType: detect.MaterialPrivateKey, File: "k.pem", Line: 1, Snippet: "-----BEGIN RSA PRIVATE KEY-----"},
	}
}

// Both output formats round-trip: a scan's own output, used as its
// baseline, makes every finding known.
func TestRoundTrip(t *testing.T) {
	fs := scan()
	var sarif, cbom bytes.Buffer
	if err := report.WriteSARIF(&sarif, fs, report.SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteCBOM(&cbom, report.CBOM(fs, report.CBOMOptions{Timestamp: time.Unix(0, 0)})); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"sarif": sarif.Bytes(), "cbom": cbom.Bytes()} {
		b, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b.Len() != len(fs) {
			t.Errorf("%s: baseline holds %d findings, want %d", name, b.Len(), len(fs))
		}
		fresh, known := b.Split(fs)
		if len(fresh) != 0 || len(known) != len(fs) {
			t.Errorf("%s: fresh %v known %d", name, fresh, len(known))
		}
	}
}

func TestSplit(t *testing.T) {
	var sarif bytes.Buffer
	if err := report.WriteSARIF(&sarif, scan(), report.SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	b, err := Parse(sarif.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	now := scan()
	now[0].Line = 30 // code moved: still known
	now[1].KeySize = 4096
	now[1].Snippet = "rsa.GenerateKey(r, 4096)" // changed: new
	now = append(now, now[0])                   // a second identical MD5 import: new
	now[3].Line = 31
	fresh, known := b.Split(now)
	if len(known) != 2 || len(fresh) != 2 || fresh[0].RuleID != "go-rsa-generate-key" || fresh[1].Line != 31 {
		t.Errorf("fresh %+v\nknown %+v", fresh, known)
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"not json", `{"hello": 1}`, `{"version": "2.0.0"}`} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%q) succeeded", in)
		}
	}
}
