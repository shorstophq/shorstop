package goast

import (
	"testing"

	"github.com/shorstophq/shorstop/internal/detect/detecttest"
)

// FuzzDetect: Go source from untrusted repositories, including files that
// don't parse (the detector keeps what did).
func FuzzDetect(f *testing.F) {
	names := []string{"main.go"}
	seeds := map[string]int{}
	for _, n := range []string{"broken", "calls", "clean", "dot", "imports", "pqc"} {
		seeds["testdata/fixtures/go/"+n+".go"] = 0
	}
	detecttest.Seed(f, names, seeds)
	d := builtin(f)
	f.Fuzz(func(t *testing.T, _ uint8, content []byte) {
		detecttest.Check(t, d, detecttest.File("main.go", content))
	})
}
