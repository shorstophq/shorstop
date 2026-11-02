package detect

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSnippet(t *testing.T) {
	src := []byte("first\n\t  second line  \r\nthird")
	tests := []struct {
		n    int
		want string
	}{
		{0, ""},
		{1, "first"},
		{2, "second line"}, // tabs, spaces and the \r of CRLF trimmed
		{3, "third"},       // last line has no newline
		{4, ""},
	}
	for _, tt := range tests {
		if got := Snippet(src, tt.n); got != tt.want {
			t.Errorf("Snippet(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestSnippetTruncates(t *testing.T) {
	long := strings.Repeat("é", 200) // 2 bytes per rune: a byte cut would split one
	got := Snippet([]byte(long), 1)
	if n := utf8.RuneCountInString(got); n != MaxSnippet {
		t.Errorf("got %d runes, want %d", n, MaxSnippet)
	}
	if !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
		t.Errorf("bad truncation: %q", got)
	}
	if got := Snippet([]byte(strings.Repeat("a", MaxSnippet)), 1); got != strings.Repeat("a", MaxSnippet) {
		t.Error("a line of exactly MaxSnippet runes was cut")
	}
	if got := Snippet([]byte("ok\xff"), 1); !utf8.ValidString(got) {
		t.Errorf("invalid UTF-8 passed through: %q", got)
	}
}
