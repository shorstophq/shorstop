package baseline

import (
	"os"
	"testing"
)

// FuzzParse: a --baseline file is often a CI artifact from another run,
// downloaded and passed in; whatever it holds must not panic.
func FuzzParse(f *testing.F) {
	for _, p := range []string{"../../testdata/report/sarif.golden.json", "../../testdata/report/cbom.golden.json"} {
		data, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"version":"2.1.0","runs":[{"results":[{"partialFingerprints":{"shorstop/v1":"x"}}]}]}`))
	f.Add([]byte(`{"bomFormat":"CycloneDX","components":[{"evidence":{"occurrences":[{"bom-ref":"x"}]}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := Parse(data)
		if err == nil && b.Len() < 0 {
			t.Fatalf("negative size %d", b.Len())
		}
	})
}
