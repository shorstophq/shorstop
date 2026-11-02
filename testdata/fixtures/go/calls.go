// Fixture: call rules and key sizes read from arguments.
package fixture

import (
	"crypto/des"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	r2 "crypto/rsa"
)

const bits = 3072

func keys() {
	rsa.GenerateKey(rand.Reader, 2048)
	r2.GenerateKey(rand.Reader, 0x1000) // aliased import, hex literal
	rsa.GenerateKey(rand.Reader, bits)  // a constant: key size unknown (0)
	rsa.GenerateKey(rand.Reader)        // too few arguments: no panic, size unknown
	f := rsa.GenerateKey                // a reference, not a call: not reported
	_ = f
	des.NewTripleDESCipher(nil)
	des.NewCipher(nil)
	ecdh.X25519()
	ecdh.P256() // no rule for P256 beyond the import
}
