package crawler

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// maxIgnoreFileSize caps how much of a .gitignore is read. The scanned repo is
// untrusted input, so a huge .gitignore must not exhaust memory.
const maxIgnoreFileSize = 1 << 20

// rule is one parsed line of a .gitignore file, or one --exclude pattern.
type rule struct {
	segments []string // pattern split on "/"; "**" is kept as its own segment
	negate   bool     // "!pattern": re-include what an earlier rule excluded
	dirOnly  bool     // "pattern/": matches directories only
	anchored bool     // pattern contained a "/" other than a trailing one
}

// parseRule parses one line using gitignore syntax. It returns false for
// blank lines, comments and malformed patterns.
func parseRule(line string) (rule, bool) {
	line = strings.TrimSuffix(line, "\r")
	line = trimTrailingSpaces(line)
	if line == "" || line[0] == '#' {
		return rule{}, false
	}

	var r rule
	switch {
	case line[0] == '!':
		r.negate = true
		line = line[1:]
	case strings.HasPrefix(line, `\!`), strings.HasPrefix(line, `\#`):
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		r.dirOnly = true
		line = strings.TrimRight(line, "/")
	}
	if strings.HasPrefix(line, "/") {
		r.anchored = true
		line = strings.TrimLeft(line, "/")
	}
	if line == "" {
		return rule{}, false
	}
	if strings.Contains(line, "/") {
		r.anchored = true
	}

	r.segments = strings.Split(line, "/")
	for i, s := range r.segments {
		// gitignore negates a character class with "[!...]"; path.Match uses "[^...]".
		s = strings.ReplaceAll(s, "[!", "[^")
		if _, err := path.Match(s, ""); err != nil {
			return rule{}, false
		}
		r.segments[i] = s
	}
	return r, true
}

// trimTrailingSpaces removes trailing spaces unless they are escaped with "\".
func trimTrailingSpaces(s string) string {
	for strings.HasSuffix(s, " ") && !strings.HasSuffix(s, `\ `) {
		s = s[:len(s)-1]
	}
	return s
}

// match reports whether the rule matches a path, given as its segments
// relative to the directory the rule came from.
func (r rule) match(parts []string, isDir bool) bool {
	if r.dirOnly && !isDir {
		return false
	}
	if !r.anchored {
		ok, _ := path.Match(r.segments[0], parts[len(parts)-1])
		return ok
	}
	return matchSegments(r.segments, parts)
}

// matchSegments matches pattern segments against path segments, treating a
// "**" segment as zero or more path segments.
func matchSegments(pat, parts []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			if len(pat) == 1 {
				// Trailing "/**" matches everything inside, but not the directory itself.
				return len(parts) > 0
			}
			for i := 0; i <= len(parts); i++ {
				if matchSegments(pat[1:], parts[i:]) {
					return true
				}
			}
			return false
		}
		if len(parts) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], parts[0]); !ok {
			return false
		}
		pat, parts = pat[1:], parts[1:]
	}
	return len(parts) == 0
}

// lastMatch applies gitignore precedence within one rule list: the last
// matching rule wins. matched is false when no rule matched.
func lastMatch(rules []rule, parts []string, isDir bool) (ignored, matched bool) {
	for i := len(rules) - 1; i >= 0; i-- {
		if rules[i].match(parts, isDir) {
			return !rules[i].negate, true
		}
	}
	return false, false
}

// frame holds the rules from one directory's .gitignore.
type frame struct {
	dir   string // slash path relative to the scan root; "" is the root
	depth int    // number of segments in dir
	rules []rule
}

// ignoreStack holds the .gitignore rules of the directory being walked and its
// ancestors, innermost last. Because the walk is depth-first, a stack always
// holds exactly the files that apply to the current path.
type ignoreStack []frame

func (s *ignoreStack) push(dir string, rules []rule) {
	if len(rules) == 0 {
		return
	}
	depth := 0
	if dir != "" {
		depth = strings.Count(dir, "/") + 1
	}
	*s = append(*s, frame{dir: dir, depth: depth, rules: rules})
}

// popTo removes frames that are not ancestors of p.
func (s *ignoreStack) popTo(p string) {
	for len(*s) > 0 {
		top := (*s)[len(*s)-1]
		if top.dir == "" || strings.HasPrefix(p, top.dir+"/") {
			return
		}
		*s = (*s)[:len(*s)-1]
	}
}

// ignored reports whether the path is excluded. Deeper .gitignore files take
// precedence over shallower ones, as in git.
func (s ignoreStack) ignored(parts []string, isDir bool) bool {
	for i := len(s) - 1; i >= 0; i-- {
		if ignored, ok := lastMatch(s[i].rules, parts[s[i].depth:], isDir); ok {
			return ignored
		}
	}
	return false
}

// readIgnoreFile parses a .gitignore. A missing file is not an error.
func readIgnoreFile(name string) ([]rule, error) {
	f, err := os.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxIgnoreFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxIgnoreFileSize {
		return nil, fmt.Errorf("larger than %d bytes, not applied", maxIgnoreFileSize)
	}

	var rules []rule
	for line := range strings.Lines(string(data)) {
		if r, ok := parseRule(strings.TrimSuffix(line, "\n")); ok {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

// parseExcludes parses --exclude patterns. They use gitignore syntax relative
// to the scan root, but negation is not allowed: an exclude always wins.
func parseExcludes(patterns []string) ([]rule, error) {
	rules := make([]rule, 0, len(patterns))
	for _, p := range patterns {
		r, ok := parseRule(p)
		if !ok {
			return nil, fmt.Errorf("invalid --exclude pattern %q", p)
		}
		if r.negate {
			return nil, fmt.Errorf("--exclude pattern %q: negation (!) is not supported", p)
		}
		rules = append(rules, r)
	}
	return rules, nil
}
