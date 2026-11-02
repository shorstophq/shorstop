// Fixture: a syntax error after the imports. The import findings and the
// call before the error are still reported, along with the parse error.
package fixture

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
)

func before() { rsa.GenerateKey(rand.Reader, 2048); md5.New() }

func broken( {
