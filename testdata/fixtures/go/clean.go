// Fixture: no crypto. The strings and comments below must not match:
// import "crypto/rsa"
package fixture

import "strings"

var s = strings.ToUpper(`import "crypto/md5"; rsa.GenerateKey(nil, 512)`)

type rsa struct{}

func (rsa) GenerateKey(int) {}

func local() { rsa{}.GenerateKey(512) }
