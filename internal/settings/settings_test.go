package settings

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, FileName)
	content := "version: 1\nexclude: [third_party/, '*.min.js']\nfail-on: high\nbaseline: .shorstop/base.sarif\n" +
		"max-file-size: 4MB\nrules: [.shorstop/rules.yaml, /abs/rules.yaml]\ndisable: [generic-rsa-bits]\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	found, err := Find(dir)
	if err != nil || found != p {
		t.Fatalf("Find = %q, %v", found, err)
	}
	s, err := Load(found)
	if err != nil {
		t.Fatal(err)
	}
	if s.FailOn != "high" || s.MaxFileSize != "4MB" || !slices.Equal(s.Exclude, []string{"third_party/", "*.min.js"}) || !slices.Equal(s.Disable, []string{"generic-rsa-bits"}) {
		t.Errorf("got %+v", s)
	}
	if s.Baseline != filepath.Join(dir, ".shorstop", "base.sarif") {
		t.Errorf("baseline not resolved against the config's directory: %q", s.Baseline)
	}
	if s.Rules[0] != filepath.Join(dir, ".shorstop", "rules.yaml") || s.Rules[1] != filepath.FromSlash("/abs/rules.yaml") {
		t.Errorf("rules = %q", s.Rules)
	}
}

func TestFindNone(t *testing.T) {
	if p, err := Find(t.TempDir()); p != "" || err != nil {
		t.Errorf("Find in an empty dir = %q, %v", p, err)
	}
}

func TestParse(t *testing.T) {
	if s, err := Parse(nil); err != nil || s.Version != FormatVersion {
		t.Errorf("empty file: %+v, %v", s, err)
	}
	if s, err := Parse([]byte("fail-on: low\n")); err != nil || s.Version != FormatVersion {
		t.Errorf("version left out: %+v, %v", s, err)
	}
	for in, want := range map[string]string{
		"fail_on: high\n":           "field fail_on not found",
		"version: 2\n":              "unsupported config version 2",
		"exclude: just-a-string\n":  "cannot unmarshal",
		"fail-on: [high, medium]\n": "cannot unmarshal",
	} {
		if _, err := Parse([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want an error mentioning %q", in, err, want)
		}
	}
}
