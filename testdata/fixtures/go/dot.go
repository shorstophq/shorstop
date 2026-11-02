// Fixture: a dot import makes calls bare identifiers.
package fixture

import (
	"crypto/rand"
	. "crypto/rsa"
)

func dot() {
	GenerateKey(rand.Reader, 1024)
}
