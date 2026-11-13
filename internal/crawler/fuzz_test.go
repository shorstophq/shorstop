package crawler

import (
	"strings"
	"testing"
)

// FuzzIgnore: .gitignore files come from the scanned repository, and each
// rule is matched against every path in the tree. No pattern may panic,
// matching must not depend on more than the pattern and the path, and the
// memoized "**" matcher must agree with plain backtracking.
func FuzzIgnore(f *testing.F) {
	f.Add("vendor/\n*.min.js\n!keep.min.js\n/build\n**/testdata/**\n", "a/vendor/x.min.js")
	f.Add("[!a-z]*.txt\n\\#not-a-comment\nfoo\\ \n", "dir/1.txt")
	f.Add("**/**/**/a/**/b\n", "a/a/a/a/a/b")
	f.Fuzz(func(t *testing.T, file, p string) {
		var rules []rule
		for _, line := range strings.Split(file, "\n") {
			if r, ok := parseRule(line); ok {
				rules = append(rules, r)
			}
		}
		parts := strings.Split(strings.Trim(p, "/"), "/")
		if len(parts) > 64 {
			parts = parts[:64] // deeper than any real tree
		}
		for _, r := range rules {
			if strings.Count(strings.Join(r.segments, "/"), "**") <= 3 { // keep the naive matcher fast
				if got, want := matchSegments(r.segments, parts), naiveMatchSegments(r.segments, parts); got != want {
					t.Fatalf("matchSegments(%q, %q) = %v, backtracking says %v", r.segments, parts, got, want)
				}
			}
		}
		for _, dir := range []bool{false, true} {
			a, am := lastMatch(rules, parts, dir)
			b, bm := lastMatch(rules, parts, dir)
			if a != b || am != bm {
				t.Fatal("matching is not deterministic")
			}
		}
	})
}
