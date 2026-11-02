package crawler

import (
	"strings"
	"testing"
)

func TestRuleMatch(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		isDir   bool
		want    bool
	}{
		// No slash: matches the name at any depth.
		{"*.log", "x.log", false, true},
		{"*.log", "a/b/x.log", false, true},
		{"*.log", "x.txt", false, false},
		// Leading slash: anchored to the .gitignore's directory.
		{"/build", "build", true, true},
		{"/build", "a/build", true, false},
		// Middle slash: anchored too.
		{"doc/frotz", "doc/frotz", false, true},
		{"doc/frotz", "a/doc/frotz", false, false},
		// Trailing slash: directories only.
		{"tmp/", "tmp", true, true},
		{"tmp/", "tmp", false, false},
		{"tmp/", "a/tmp", true, true},
		// "**" forms.
		{"**/foo", "foo", false, true},
		{"**/foo", "a/b/foo", false, true},
		{"a/**/b", "a/b", false, true},
		{"a/**/b", "a/x/y/b", false, true},
		{"a/**/b", "a/x/c", false, false},
		{"abc/**", "abc/x/y", false, true},
		{"abc/**", "abc", true, false},
		// Character classes, including gitignore's "[!...]" negation.
		{"[!a]bc", "xbc", false, true},
		{"[!a]bc", "abc", false, false},
		{"file?.txt", "file1.txt", false, true},
		// Escapes and whitespace.
		{`\#notcomment`, "#notcomment", false, true},
		{`\!important`, "!important", false, true},
		{"spaces.txt   ", "spaces.txt", false, true},
		{`trail\ `, "trail ", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"~"+tt.path, func(t *testing.T) {
			r, ok := parseRule(tt.pattern)
			if !ok {
				t.Fatalf("parseRule(%q) rejected the pattern", tt.pattern)
			}
			if got := r.match(strings.Split(tt.path, "/"), tt.isDir); got != tt.want {
				t.Errorf("match(%q, isDir=%v) = %v, want %v", tt.path, tt.isDir, got, tt.want)
			}
		})
	}
}

func TestParseRuleRejects(t *testing.T) {
	for _, line := range []string{"", "   ", "# comment", "/", "!", "[unclosed"} {
		if _, ok := parseRule(line); ok {
			t.Errorf("parseRule(%q) accepted, want rejected", line)
		}
	}
}

func TestParseRuleNegate(t *testing.T) {
	r, ok := parseRule("!keep.log")
	if !ok || !r.negate {
		t.Fatalf("parseRule(\"!keep.log\") = %+v, %v; want a negated rule", r, ok)
	}
}

func TestIgnoreStackPrecedence(t *testing.T) {
	rules := func(lines ...string) []rule {
		var rs []rule
		for _, l := range lines {
			r, ok := parseRule(l)
			if !ok {
				t.Fatalf("bad test pattern %q", l)
			}
			rs = append(rs, r)
		}
		return rs
	}

	var s ignoreStack
	check := func(path string, want bool) {
		t.Helper()
		s.popTo(path)
		if got := s.ignored(strings.Split(path, "/"), false); got != want {
			t.Errorf("ignored(%q) = %v, want %v", path, got, want)
		}
	}

	// Same order as a depth-first walk: root files, then into sub/, then out again.
	s.push("", rules("*.log", "!keep.log"))
	check("x.log", true)     // root rule
	check("keep.log", false) // later rule in the same file wins

	s.popTo("sub")
	s.push("sub", rules("keep.log", "!*.log"))
	check("sub/x.log", false)    // deeper file overrides root
	check("sub/keep.log", false) // last match in the deeper file wins

	check("other/keep.log", false) // sub/ rules no longer apply
	if len(s) != 1 {
		t.Errorf("after leaving sub/, stack has %d frames, want 1", len(s))
	}
}

func TestParseExcludes(t *testing.T) {
	if _, err := parseExcludes([]string{"*.min.js", "testdata/"}); err != nil {
		t.Errorf("valid excludes rejected: %v", err)
	}
	if _, err := parseExcludes([]string{"!keep"}); err == nil {
		t.Error("negated exclude accepted, want error")
	}
	if _, err := parseExcludes([]string{"[bad"}); err == nil {
		t.Error("malformed exclude accepted, want error")
	}
}
