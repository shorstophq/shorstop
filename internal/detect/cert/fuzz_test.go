package cert

import (
	"testing"

	"github.com/shorstophq/shorstop/internal/detect/detecttest"
)

// FuzzDetect: PEM, DER and SSH public keys come from untrusted repositories,
// so no input may panic or break the finding contract. The first argument
// picks the file name, which decides how the content is parsed.
func FuzzDetect(f *testing.F) {
	names := []string{"key.pem", "cert.der", "id_rsa.pub", "authorized_keys", "main.go"}
	dir := "testdata/fixtures/cert/"
	detecttest.Seed(f, names, map[string]int{
		dir + "chain.pem": 0, dir + "rsa-pkcs1.key": 0, dir + "ec-pkcs8.key": 0, dir + "ed25519.pem": 0,
		dir + "encrypted-pkcs8.key": 0, dir + "mldsa-pkcs8.key": 0, dir + "mldsa65.pem": 0, dir + "public.pem": 0,
		dir + "request.csr": 0, dir + "dhparam.pem": 0, dir + "legacy-sha1.pem": 0, dir + "bad.pem": 0, dir + "id_rsa": 0,
		dir + "id_ed25519_enc": 0, dir + "cert.der": 1, dir + "junk.der": 1, dir + "id_rsa.pub": 2,
		dir + "authorized_keys": 3, dir + "embedded.go.txt": 4,
	})
	d := New()
	f.Fuzz(func(t *testing.T, name uint8, content []byte) {
		detecttest.Check(t, d, detecttest.File(names[int(name)%len(names)], content))
	})
}
