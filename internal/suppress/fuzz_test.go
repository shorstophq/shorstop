package suppress

import (
	"bytes"
	"testing"

	"github.com/shorstophq/shorstop/internal/detect"
)

// FuzzApply: shorstop:ignore comments are written by whoever wrote the
// scanned file. Apply must keep every finding (suppressed ones stay in the
// CBOM) and only ever set Suppression to a marker on the finding's line or
// the line above it.
func FuzzApply(f *testing.F) {
	f.Add([]byte("x := md5.New() // shorstop:ignore go-md5-import -- legacy checksum\n"), "go-md5-import")
	f.Add([]byte("# shorstop:ignore\nssl_protocols TLSv1;\n"), "tls-protocol-version")
	f.Add([]byte("// shorstop:ignore a,b,c --\n\n"), "b")
	f.Fuzz(func(t *testing.T, content []byte, rule string) {
		lines := bytes.Count(content, []byte("\n")) + 2
		var fs []detect.Finding
		for n := 0; n <= lines; n++ {
			fs = append(fs, detect.Finding{RuleID: rule, Line: n})
		}
		out := Apply(content, fs)
		if len(out) != len(fs) {
			t.Fatalf("Apply returned %d findings for %d", len(out), len(fs))
		}
		for _, fd := range out {
			if s := fd.Suppression; s != nil && (fd.Line < 1 || (s.Line != fd.Line && s.Line != fd.Line-1)) {
				t.Fatalf("finding on line %d suppressed by a marker on line %d", fd.Line, s.Line)
			}
		}
	})
}
