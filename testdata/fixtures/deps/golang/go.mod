module example.com/fixture

go 1.27

require golang.org/x/crypto v0.58.0

require (
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/google/uuid v1.6.0
	filippo.io/edwards25519 v1.1.0
)

replace golang.org/x/crypto => ../crypto
