//go:build ignore

// gen writes the Go-generated certificate and key fixtures. The OpenSSH and
// OpenSSL ones come from gen.sh, which runs this first. All keys here are
// throwaway test keys: they protect nothing.
//
//	go run gen.go
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

var (
	notBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
)

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

// cert creates a certificate for pub, signed by signer. With parent nil it
// is self-signed; otherwise parent names the issuer.
func cert(cn string, pub crypto.PublicKey, signer crypto.Signer, sig x509.SignatureAlgorithm, parent *x509.Certificate) []byte {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"ShorStop Fixtures"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SignatureAlgorithm:    sig,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if parent == nil {
		parent = tmpl
	}
	return must(x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer))
}

func write(name string, blocks ...*pem.Block) {
	var out []byte
	for _, b := range blocks {
		out = append(out, pem.EncodeToMemory(b)...)
	}
	if err := os.WriteFile(name, out, 0o644); err != nil {
		log.Fatal(err)
	}
}

func main() {
	rsaKey := must(rsa.GenerateKey(rand.Reader, 2048))
	ecKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	_, edKey := must2(ed25519.GenerateKey(rand.Reader))
	mlKey := must(mldsa.GenerateKey(mldsa.MLDSA65()))

	rsaCert := cert("rsa-sha256", rsaKey.Public(), rsaKey, x509.SHA256WithRSA, nil)
	write("rsa2048.crt", &pem.Block{Type: "CERTIFICATE", Bytes: rsaCert})
	write("ecdsa-p256.pem", &pem.Block{Type: "CERTIFICATE", Bytes: cert("ecdsa", ecKey.Public(), ecKey, x509.ECDSAWithSHA384, nil)})
	write("ed25519.pem", &pem.Block{Type: "CERTIFICATE", Bytes: cert("ed25519", edKey.Public(), edKey, x509.PureEd25519, nil)})
	write("mldsa65.pem", &pem.Block{Type: "CERTIFICATE", Bytes: cert("ml-dsa-65", mlKey.Public(), mlKey, x509.MLDSA65, nil)})
	// An ML-DSA certificate signed by an RSA CA: the chain still depends on RSA.
	write("chain.pem",
		&pem.Block{Type: "CERTIFICATE", Bytes: cert("pqc-leaf-rsa-issuer", mlKey.Public(), rsaKey, x509.SHA256WithRSA, must(x509.ParseCertificate(rsaCert)))},
		&pem.Block{Type: "CERTIFICATE", Bytes: rsaCert})
	if err := os.WriteFile("cert.der", cert("der", ecKey.Public(), ecKey, x509.ECDSAWithSHA256, nil), 0o644); err != nil {
		log.Fatal(err)
	}

	write("rsa-pkcs1.key", &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	write("ec-pkcs8.key", &pem.Block{Type: "PRIVATE KEY", Bytes: must(x509.MarshalPKCS8PrivateKey(ecKey))})
	write("mldsa-pkcs8.key", &pem.Block{Type: "PRIVATE KEY", Bytes: must(x509.MarshalPKCS8PrivateKey(mlKey))})
	write("public.pem", &pem.Block{Type: "PUBLIC KEY", Bytes: must(x509.MarshalPKIXPublicKey(edKey.Public()))})
	csr := must(x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr"}}, rsaKey))
	write("request.csr", &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	// A valid PEM wrapper around bytes that aren't a certificate: a warning.
	write("bad.pem", &pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER at all")})
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		log.Fatal(err)
	}
	return a, b
}
