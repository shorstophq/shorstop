package deps

import (
	"bytes"
	"regexp"
	"strings"
)

// splitLines returns content's lines without their "\n" or "\r\n".
func splitLines(content []byte) [][]byte {
	lines := bytes.Split(content, []byte("\n"))
	for i, l := range lines {
		lines[i] = bytes.TrimSuffix(l, []byte("\r"))
	}
	return lines
}

// lineAt returns the 1-based line of byte offset off.
func lineAt(content []byte, off int) int {
	return 1 + bytes.Count(content[:off], []byte("\n"))
}

// jsonKeyLine returns the line of the first `"key":` in a JSON document, or
// 0. encoding/json doesn't report positions, so lines are found by text;
// a key that also appears as a string value elsewhere is skipped because
// the ":" must follow it.
func jsonKeyLine(content []byte, key string) int {
	needle := []byte(`"` + jsonEscape(key) + `"`)
	for off := 0; ; {
		i := bytes.Index(content[off:], needle)
		if i < 0 {
			return 0
		}
		at := off + i
		rest := bytes.TrimLeft(content[at+len(needle):], " \t\r\n")
		if len(rest) > 0 && rest[0] == ':' {
			return lineAt(content, at)
		}
		off = at + len(needle)
	}
}

// jsonValueLine returns the line of the first `"field": "value"` pair, or 0.
func jsonValueLine(content []byte, field, value string) int {
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(jsonEscape(field)) + `"\s*:\s*"` + regexp.QuoteMeta(jsonEscape(value)) + `"`)
	if loc := re.FindIndex(content); loc != nil {
		return lineAt(content, loc[0])
	}
	return 0
}

// jsonEscape escapes the characters JSON writers escape in names: "/" is
// left alone (most writers don't escape it), quotes and backslashes are.
func jsonEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// exactSemver matches an exact version such as 1.3.1 or 2.0.0-rc.1, as
// opposed to a range (^1.3.0, ~2, >=1 <2, *).
var exactSemver = regexp.MustCompile(`^v?\d+(\.\d+){1,3}([-+][0-9A-Za-z.+-]+)?$`)

func exact(v string) string {
	v = strings.TrimSpace(v)
	if exactSemver.MatchString(v) {
		return v
	}
	return ""
}
