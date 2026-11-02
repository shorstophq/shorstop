// Fixture: every kind of import the goast rules match on.
package fixture

import (
	"crypto/aes"
	"crypto/dsa" //nolint:staticcheck // deprecated, on purpose
	"crypto/ecdsa"
	"crypto/elliptic"
	_ "crypto/md5" // blank import still counts: it registers MD5
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"

	ed "crypto/ed25519" // alias
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/md4"
)

var _ = []any{aes.BlockSize, dsa.L1024N160, ecdsa.Sign, elliptic.P256, rc4.NewCipher,
	sha1.Sum, sha256.Sum256, sha3.Sum256, sha512.Sum512, fmt.Println, ed.Sign,
	curve25519.X25519, md4.New}
