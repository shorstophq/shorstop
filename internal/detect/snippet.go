package detect

import (
	"bytes"
	"unicode/utf8"
)

// MaxSnippet is the longest Finding.Snippet, in characters (runes).
const MaxSnippet = 120

// Snippet returns line n (1-based) of content with surrounding whitespace
// removed, cut to MaxSnippet characters. It returns "" if there is no line n.
func Snippet(content []byte, n int) string {
	if n < 1 {
		return ""
	}
	for i := 1; i < n; i++ {
		nl := bytes.IndexByte(content, '\n')
		if nl < 0 {
			return ""
		}
		content = content[nl+1:]
	}
	if nl := bytes.IndexByte(content, '\n'); nl >= 0 {
		content = content[:nl]
	}
	content = bytes.TrimSpace(content)

	if utf8.RuneCount(content) <= MaxSnippet {
		return string(bytes.ToValidUTF8(content, []byte("�")))
	}
	// Cut on a rune boundary so a multi-byte character is never split.
	cut, runes := 0, 0
	for cut < len(content) && runes < MaxSnippet-1 {
		_, size := utf8.DecodeRune(content[cut:])
		cut += size
		runes++
	}
	return string(bytes.ToValidUTF8(content[:cut], []byte("�"))) + "…"
}
