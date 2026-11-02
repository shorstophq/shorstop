// Fixture: post-quantum imports are reported too, as progress.
package fixture

import (
	"crypto/mldsa"
	"crypto/mlkem"
)

var _ = []any{mlkem.GenerateKey768, mldsa.MLDSA65}
