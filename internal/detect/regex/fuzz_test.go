package regex

import (
	"testing"

	"github.com/shorstophq/shorstop/internal/detect/detecttest"
)

// FuzzDetect: source and config text in every language the rule pack
// covers. The first argument picks the file name, which decides the rules.
func FuzzDetect(f *testing.F) {
	names := []string{"crypto.py", "crypto.js", "crypto.ts", "Crypto.java", "Crypto.cs", "crypto.c", "crypto.php", "crypto.rb", "crypto.rs", "Dockerfile", "nginx.conf", "sshd_config"}
	seeds := map[string]int{}
	for i, file := range []string{"python/crypto.py", "javascript/crypto.js", "typescript/crypto.ts", "java/Crypto.java", "csharp/Crypto.cs", "c/crypto.c", "php/crypto.php", "ruby/crypto.rb", "rust/crypto.rs", "generic/Dockerfile", "generic/nginx.conf", "generic/sshd_config"} {
		seeds["testdata/fixtures/"+file] = i
	}
	detecttest.Seed(f, names, seeds)
	d := builtin(f)
	f.Fuzz(func(t *testing.T, name uint8, content []byte) {
		detecttest.Check(t, d, detecttest.File(names[int(name)%len(names)], content))
	})
}
