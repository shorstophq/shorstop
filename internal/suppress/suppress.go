// Package suppress applies inline "shorstop:ignore" comments to findings.
//
// Syntax, in any comment style the file's language uses:
//
//	rsa.GenerateKey(r, 2048) // shorstop:ignore go-rsa-generate-key reason="legacy partner API"
//
//	# shorstop:ignore generic-3des,generic-rc4 reason="vendor default, disabled at runtime"
//	ssl_ciphers 3DES:RC4;
//
// A marker covers findings on its own line, and on the next line when the
// marker's line holds nothing but a comment. Rule IDs are comma-separated;
// a marker with no IDs covers every finding on the line. The reason is
// optional but recorded, so reports can show why something was accepted.
package suppress

import (
	"bytes"
	"regexp"
	"slices"
	"strings"

	"github.com/shorstop/shorstop/internal/detect"
)

// Marker is the text that starts a suppression.
const Marker = "shorstop:ignore"

// marker is one parsed shorstop:ignore comment.
type marker struct {
	rules  []string // empty means every rule
	reason string
	line   int
}

func (m marker) covers(ruleID string) bool {
	return len(m.rules) == 0 || slices.Contains(m.rules, ruleID)
}

var (
	ruleIDs = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*(?:,[a-z0-9]+(?:-[a-z0-9]+)*)*`)
	reason  = regexp.MustCompile(`\breason\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))`)
)

// parse reads the marker on a line, if any.
func parse(line []byte, n int) (marker, bool) {
	i := bytes.Index(line, []byte(Marker))
	if i < 0 {
		return marker{}, false
	}
	rest := string(line[i+len(Marker):])
	// "shorstop:ignored" or "shorstop:ignore-foo" is not the marker.
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return marker{}, false
	}
	rest = strings.TrimSpace(rest)
	m := marker{line: n}
	if ids := ruleIDs.FindString(rest); ids != "" && !strings.HasPrefix(rest, "reason") {
		m.rules = strings.Split(ids, ",")
	}
	if r := reason.FindStringSubmatch(rest); r != nil {
		m.reason = r[1] + r[2] + r[3]
	}
	return m, true
}

// commentOnly reports whether a line holds nothing but a comment, so its
// marker applies to the next line too.
func commentOnly(line []byte) bool {
	t := bytes.TrimSpace(line)
	for _, start := range []string{"//", "#", "/*", "*", "--", ";", "<!--", "%", "'", "REM ", "rem "} {
		if bytes.HasPrefix(t, []byte(start)) {
			return true
		}
	}
	return false
}

// Apply marks the findings in fs that a shorstop:ignore comment in content
// covers, setting their Suppression. It returns fs. Files without the
// marker cost one search; binary files (line 0) are never suppressed.
func Apply(content []byte, fs []detect.Finding) []detect.Finding {
	if len(fs) == 0 || !bytes.Contains(content, []byte(Marker)) {
		return fs
	}
	// Markers by the line they cover.
	covering := make(map[int][]marker)
	for n, line := range bytes.Split(content, []byte("\n")) {
		m, ok := parse(line, n+1)
		if !ok {
			continue
		}
		covering[n+1] = append(covering[n+1], m)
		if commentOnly(line) {
			covering[n+2] = append(covering[n+2], m)
		}
	}
	for i := range fs {
		if fs[i].Line < 1 {
			continue
		}
		for _, m := range covering[fs[i].Line] {
			if m.covers(fs[i].RuleID) {
				fs[i].Suppression = &detect.Suppression{Reason: m.reason, Line: m.line}
				break
			}
		}
	}
	return fs
}
