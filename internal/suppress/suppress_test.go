package suppress

import (
	"strings"
	"testing"

	"github.com/shorstophq/shorstop/internal/detect"
)

func TestApply(t *testing.T) {
	src := strings.Join([]string{
		/* 1 */ `rsa.GenerateKey(r, 2048) // shorstop:ignore go-rsa-generate-key reason="legacy partner API"`,
		/* 2 */ `# shorstop:ignore generic-3des,generic-rc4 reason='vendor default'`,
		/* 3 */ `ssl_ciphers 3DES:RC4;`,
		/* 4 */ `h = md5(x)  # shorstop:ignore`,
		/* 5 */ `h2 = sha1(x)`,
		/* 6 */ `x = md5(y) // shorstop:ignore go-md5-import`,
		/* 7 */ `y = md5(z) // shorstop:ignored, not a marker`,
		/* 8 */ `-- shorstop:ignore reason=accepted-risk`,
		/* 9 */ `SELECT md5(pw)`,
	}, "\n")
	fs := []detect.Finding{
		{RuleID: "go-rsa-generate-key", Line: 1}, // own line, matching ID
		{RuleID: "go-rsa-import", Line: 1},       // own line, other ID
		{RuleID: "generic-3des", Line: 3},        // comment-only line above
		{RuleID: "generic-aes", Line: 3},         // ... but not this rule
		{RuleID: "php-md5", Line: 4},             // no IDs: every rule on the line
		{RuleID: "php-sha1", Line: 5},            // line 4 has code, so it doesn't reach line 5
		{RuleID: "php-md5", Line: 6},             // own line, other ID
		{RuleID: "php-md5", Line: 7},             // "shorstop:ignored" is not the marker
		{RuleID: "sql-md5", Line: 9},             // comment-only line above, no IDs, bare reason
		{RuleID: "cert-public-key", Line: 0},     // binary file: never
	}
	Apply([]byte(src), fs)
	want := []struct {
		suppressed bool
		reason     string
	}{
		{true, "legacy partner API"}, {false, ""}, {true, "vendor default"}, {false, ""}, {true, ""},
		{false, ""}, {false, ""}, {false, ""}, {true, "accepted-risk"}, {false, ""},
	}
	for i, w := range want {
		got := fs[i].Suppression
		if (got != nil) != w.suppressed || (got != nil && got.Reason != w.reason) {
			t.Errorf("finding %d (%s line %d): suppression %+v, want suppressed=%v reason=%q", i, fs[i].RuleID, fs[i].Line, got, w.suppressed, w.reason)
		}
	}
	if fs[2].Suppression.Line != 2 {
		t.Errorf("suppression line = %d, want the comment's line 2", fs[2].Suppression.Line)
	}
}

func TestApplyWithoutMarker(t *testing.T) {
	fs := []detect.Finding{{RuleID: "x", Line: 1}}
	Apply([]byte("no marker here"), fs)
	if fs[0].Suppression != nil {
		t.Error("suppressed without a marker")
	}
}
