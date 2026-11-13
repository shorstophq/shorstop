package settings

import (
	"os"
	"testing"
)

// FuzzParse: .shorstop.yaml is read from the scanned repository, so a pull
// request can put anything in it.
func FuzzParse(f *testing.F) {
	data, err := os.ReadFile("../../.shorstop.yaml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte("version: 1\nexclude: [\"vendor/**\"]\nfail-on: high\nmax-file-size: 4MB\n"))
	f.Add([]byte("max-file-size: 1e400GB\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
