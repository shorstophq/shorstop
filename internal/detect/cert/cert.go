// Package cert finds certificates, keys and key material committed to a
// repository: PEM blocks in any text file, DER certificates and keys,
// PKCS#12 key stores, and OpenSSH public keys.
//
// It needs no rules: a certificate or key states its own algorithm.
package cert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys still turn up in repositories; we must recognise them
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/rules"
)

// Name is the detector's name.
const Name = "cert"

// Built-in rule IDs. Like rule-pack IDs, they appear in suppressions and
// baselines, so they must never be renamed or reused.
const (
	RuleCertPublicKey     = "cert-public-key"       // a certificate's subject public key
	RuleCertSignature     = "cert-signature"        // the algorithm the issuer signed it with
	RuleCertSignatureHash = "cert-signature-hash"   // the hash inside that signature algorithm
	RulePrivateKey        = "private-key-committed" // a private key, or a store that holds them
	RulePublicKey         = "public-key"            // a standalone public key, CSR or SSH key
	RuleDHParameters      = "dh-parameters"         // Diffie-Hellman parameters
)

// derExts are extensions whose binary content is parsed as DER.
var derExts = map[string]bool{".der": true, ".cer": true, ".crt": true}

// keyStoreExts are PKCS#12 key stores. They are reported, not parsed: they
// normally hold private keys and are password-protected.
var keyStoreExts = map[string]bool{".p12": true, ".pfx": true}

var pemBegin = []byte("-----BEGIN ")

// Detector is the certificate and key detector. It has no state, so it is
// safe for concurrent use.
type Detector struct{}

// New returns the detector.
func New() *Detector { return &Detector{} }

// Name implements detect.Detector.
func (*Detector) Name() string { return Name }

// Supports implements detect.Detector. Every text file is wanted, because PEM
// blocks are embedded in source code and configuration as often as they sit
// in .pem files; Detect rejects files without a PEM marker cheaply. Binary
// files are wanted only with a DER or PKCS#12 extension.
func (*Detector) Supports(p string, binary bool) bool {
	ext := strings.ToLower(path.Ext(p))
	if keyStoreExts[ext] {
		return true
	}
	if binary {
		return derExts[ext]
	}
	return true
}

// Detect implements detect.Detector.
func (*Detector) Detect(ctx context.Context, f detect.File) ([]detect.Finding, error) {
	ext := strings.ToLower(path.Ext(f.Path))
	switch {
	case keyStoreExts[ext]:
		return []detect.Finding{privateKey("", 0, "PKCS#12 key store", rules.ConfidenceMedium)}, nil
	case f.Binary:
		return detectDER(f.Content)
	}

	var out []detect.Finding
	var errs []error
	if isSSHPublicKeyFile(f.Path) {
		out = append(out, detectSSHPublicKeys(f.Content)...)
	}
	if bytes.Contains(f.Content, pemBegin) {
		found, err := FindPEM(ctx, f.Content)
		out = append(out, found...)
		errs = append(errs, err)
	}
	return out, errors.Join(errs...)
}

// FindPEM reports every PEM block in content, with lines relative to
// content. Each "-----BEGIN" marker is decoded on its own, so one malformed
// block doesn't hide the ones after it. Other detectors use it for PEM they
// have decoded themselves, such as base64 values in a Kubernetes Secret.
func FindPEM(ctx context.Context, content []byte) ([]detect.Finding, error) {
	var out []detect.Finding
	var errs []error
	line, counted := 1, 0 // line number of offset `counted`
	for off := 0; ; {
		i := bytes.Index(content[off:], pemBegin)
		if i < 0 {
			break
		}
		start := off + i
		off = start + len(pemBegin)
		typ, ok := blockType(content[off:])
		if !ok {
			continue
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		line += bytes.Count(content[counted:start], []byte("\n"))
		counted = start
		marker := "-----BEGIN " + typ + "-----"

		// A block that fails to decode is usually a placeholder in docs, or
		// a key embedded in a string with escaped newlines.
		block, _ := pem.Decode(content[start:])
		if block != nil && block.Type != typ {
			block = nil
		}
		found, err := parseBlock(typ, block)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %s: %w", line, typ, err))
		}
		for i := range found {
			found[i].Line = line
			found[i].Snippet = marker // never the line: it may hold key material
		}
		out = append(out, found...)
	}
	return out, errors.Join(errs...)
}

// blockType reads the type after "-----BEGIN " up to the closing "-----".
// Types are uppercase letters, digits and spaces ("RSA PRIVATE KEY").
func blockType(b []byte) (string, bool) {
	end := bytes.Index(b, []byte("-----"))
	if end <= 0 || end > 64 {
		return "", false
	}
	for _, c := range b[:end] {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != ' ' {
			return "", false
		}
	}
	return string(b[:end]), true
}

// parseBlock turns one PEM block into findings. block is nil when only the
// marker was readable; private keys are still reported then, from the
// marker alone, and other types are skipped.
func parseBlock(typ string, block *pem.Block) ([]detect.Finding, error) {
	if strings.Contains(typ, "PRIVATE KEY") {
		return []detect.Finding{parsePrivateKey(typ, block)}, nil
	}
	if block == nil {
		return nil, nil
	}
	switch typ {
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return certFindings(c), nil
	case "CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, err
		}
		return []detect.Finding{publicKey(csr.PublicKey)}, nil
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return []detect.Finding{publicKey(pub)}, nil
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return []detect.Finding{publicKey(pub)}, nil
	case "DH PARAMETERS":
		return []detect.Finding{{
			RuleID: RuleDHParameters, Algorithm: "DH", Primitive: "key-agree",
			Confidence: rules.ConfidenceHigh,
		}}, nil
	}
	return nil, nil
}

// parsePrivateKey reports a private key, reading its algorithm when it can.
// It never fails: a committed private key is reported even when it is
// encrypted, corrupt or in a format we can't read.
func parsePrivateKey(typ string, block *pem.Block) detect.Finding {
	if block != nil {
		var key any
		var err error
		switch typ {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY":
			key, err = ssh.ParseRawPrivateKey(pem.EncodeToMemory(block))
			// An encrypted OpenSSH key still carries its public key in clear.
			var pme *ssh.PassphraseMissingError
			if errors.As(err, &pme) && pme.PublicKey != nil {
				if ck, ok := pme.PublicKey.(ssh.CryptoPublicKey); ok {
					return privateKeyFrom(ck.CryptoPublicKey())
				}
			}
		}
		if err == nil && key != nil {
			if pub := publicOf(key); pub != nil {
				return privateKeyFrom(pub)
			}
		}
	}
	// Marker only: the type prefix names the algorithm for PKCS#1/SEC 1.
	alg := ""
	switch {
	case strings.HasPrefix(typ, "RSA "):
		alg = "RSA"
	case strings.HasPrefix(typ, "DSA "):
		alg = "DSA"
	case strings.HasPrefix(typ, "EC "):
		alg = "ECC" // as in privateKeyFrom
	}
	return privateKey(alg, 0, "", rules.ConfidenceMedium)
}

// privateKeyFrom reports a parsed private key by its public half.
func privateKeyFrom(pub crypto.PublicKey) detect.Finding {
	ki := keyInfo(pub)
	f := privateKey(ki.alg, ki.bits, "", rules.ConfidenceHigh)
	f.Primitive, f.ParameterSet = ki.primitive, ki.param
	if ki.alg == "ECDSA" {
		// Go parses every EC private key as *ecdsa.PrivateKey, but the key
		// itself doesn't say whether it signs (ECDSA) or agrees keys (ECDH).
		f.Algorithm, f.Primitive = "ECC", ""
	}
	return f
}

func privateKey(alg string, bits int, snippet, confidence string) detect.Finding {
	return detect.Finding{
		RuleID:       RulePrivateKey,
		Algorithm:    alg,
		KeySize:      bits,
		AssetType:    detect.AssetMaterial,
		MaterialType: detect.MaterialPrivateKey,
		Snippet:      snippet,
		Confidence:   confidence,
	}
}

func publicKey(pub crypto.PublicKey) detect.Finding {
	ki := keyInfo(pub)
	return detect.Finding{
		RuleID:       RulePublicKey,
		Algorithm:    ki.alg,
		Primitive:    ki.primitive,
		KeySize:      ki.bits,
		ParameterSet: ki.param,
		AssetType:    detect.AssetMaterial,
		MaterialType: detect.MaterialPublicKey,
		Confidence:   rules.ConfidenceHigh,
	}
}

// certFindings reports a certificate as up to three findings: its own public
// key (the certificate asset), the issuer's signature algorithm, and the hash
// inside that signature algorithm. They are separate because each can be
// weak on its own: an ML-DSA key signed by an RSA CA is still RSA-dependent.
func certFindings(c *x509.Certificate) []detect.Finding {
	ki := keyInfo(c.PublicKey)
	out := []detect.Finding{{
		RuleID:       RuleCertPublicKey,
		Algorithm:    ki.alg,
		Primitive:    ki.primitive,
		KeySize:      ki.bits,
		ParameterSet: ki.param,
		AssetType:    detect.AssetCertificate,
		Cert: &detect.Certificate{
			Subject:   c.Subject.String(),
			Issuer:    c.Issuer.String(),
			NotBefore: c.NotBefore,
			NotAfter:  c.NotAfter,
		},
		Confidence: rules.ConfidenceHigh,
	}}
	si := sigInfo(c.SignatureAlgorithm)
	if si.signer != "" {
		out = append(out, detect.Finding{
			RuleID: RuleCertSignature, Algorithm: si.signer, Primitive: "signature",
			ParameterSet: si.param, Confidence: rules.ConfidenceHigh,
		})
	}
	if si.hash != "" {
		out = append(out, detect.Finding{
			RuleID: RuleCertSignatureHash, Algorithm: si.hash, Primitive: "hash",
			Confidence: rules.ConfidenceHigh,
		})
	}
	return out
}

// detectDER parses a binary file as DER: certificates first (one or more,
// concatenated), then the key encodings. A DER file is short and has no
// lines, so findings get line 0 and a descriptive snippet.
func detectDER(content []byte) ([]detect.Finding, error) {
	if certs, err := x509.ParseCertificates(content); err == nil && len(certs) > 0 {
		var out []detect.Finding
		for _, c := range certs {
			out = append(out, certFindings(c)...)
		}
		return withSnippet(out, "DER certificate"), nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(content); err == nil {
		return withSnippet([]detect.Finding{privateKeyFrom(publicOf(key))}, "DER private key"), nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(content); err == nil {
		return withSnippet([]detect.Finding{privateKeyFrom(key.Public())}, "DER private key"), nil
	}
	if key, err := x509.ParseECPrivateKey(content); err == nil {
		return withSnippet([]detect.Finding{privateKeyFrom(key.Public())}, "DER private key"), nil
	}
	if pub, err := x509.ParsePKIXPublicKey(content); err == nil {
		return withSnippet([]detect.Finding{publicKey(pub)}, "DER public key"), nil
	}
	return nil, errors.New("not a DER certificate or key")
}

func withSnippet(fs []detect.Finding, s string) []detect.Finding {
	for i := range fs {
		fs[i].Snippet = s
	}
	return fs
}

// isSSHPublicKeyFile reports whether a path is where OpenSSH keeps public
// keys. Other files are not searched for "ssh-rsa AAAA..." lines: those are
// common in documentation, and in known_hosts they are other people's keys.
func isSSHPublicKeyFile(p string) bool {
	base := path.Base(p)
	return strings.HasSuffix(base, ".pub") || strings.HasPrefix(base, "authorized_keys")
}

// detectSSHPublicKeys reports each OpenSSH public key line, with its line
// number. Lines that don't parse are skipped: .pub files also hold PEM keys,
// which FindPEM handles.
func detectSSHPublicKeys(content []byte) []detect.Finding {
	var out []detect.Finding
	for n, raw := range bytes.Split(content, []byte("\n")) {
		ln := bytes.TrimSpace(raw)
		if len(ln) == 0 || ln[0] == '#' {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(ln)
		if err != nil {
			continue
		}
		var ki keyDetails
		if c, ok := pk.(*ssh.Certificate); ok {
			pk = c.Key
		}
		if ck, ok := pk.(ssh.CryptoPublicKey); ok {
			ki = keyInfo(ck.CryptoPublicKey())
		}
		if ki.alg == "" {
			ki = sshTypeInfo(pk.Type())
		}
		f := publicKey(nil)
		f.Algorithm, f.Primitive, f.KeySize = ki.alg, ki.primitive, ki.bits
		f.Line = n + 1
		f.Snippet = pk.Type()
		out = append(out, f)
	}
	return out
}

// sshTypeInfo names the algorithm of an SSH key type that has no
// crypto.PublicKey form, such as FIDO security keys
// ("sk-ssh-ed25519@openssh.com").
func sshTypeInfo(t string) keyDetails {
	switch {
	case strings.Contains(t, "ed25519"):
		return keyDetails{alg: "EdDSA", primitive: "signature", bits: 255}
	case strings.Contains(t, "nistp256"):
		return keyDetails{alg: "ECDSA", primitive: "signature", bits: 256}
	case strings.Contains(t, "ecdsa"):
		return keyDetails{alg: "ECDSA", primitive: "signature"}
	case strings.Contains(t, "rsa"):
		return keyDetails{alg: "RSA"}
	case strings.Contains(t, "dss"):
		return keyDetails{alg: "DSA", primitive: "signature"}
	}
	return keyDetails{}
}

// keyDetails is what a public key says about its algorithm.
type keyDetails struct {
	alg, primitive, param string
	bits                  int
}

// keyInfo describes a public key. Unknown key types give zero keyDetails:
// the finding is still reported, with an unknown algorithm.
func keyInfo(pub crypto.PublicKey) keyDetails {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		// RSA keys sign and encrypt; the key alone doesn't say which.
		return keyDetails{alg: "RSA", bits: k.N.BitLen()}
	case *ecdsa.PublicKey:
		return keyDetails{alg: "ECDSA", primitive: "signature", bits: k.Curve.Params().BitSize}
	case ed25519.PublicKey:
		return keyDetails{alg: "EdDSA", primitive: "signature", bits: 255}
	case *dsa.PublicKey:
		return keyDetails{alg: "DSA", primitive: "signature", bits: k.P.BitLen()}
	case *ecdh.PublicKey:
		switch k.Curve() {
		case ecdh.X25519():
			return keyDetails{alg: "X25519", primitive: "key-agree", bits: 255}
		case ecdh.P256():
			return keyDetails{alg: "ECDH", primitive: "key-agree", bits: 256}
		case ecdh.P384():
			return keyDetails{alg: "ECDH", primitive: "key-agree", bits: 384}
		case ecdh.P521():
			return keyDetails{alg: "ECDH", primitive: "key-agree", bits: 521}
		}
		return keyDetails{alg: "ECDH", primitive: "key-agree"}
	case *mldsa.PublicKey:
		return keyDetails{alg: "ML-DSA", primitive: "signature", param: k.Parameters().String()}
	}
	return keyDetails{}
}

// publicOf returns the public half of a parsed private key, or nil.
func publicOf(key any) crypto.PublicKey {
	switch k := key.(type) {
	case interface{ Public() crypto.PublicKey }:
		return k.Public()
	case *dsa.PrivateKey: // has no Public method
		return &k.PublicKey
	}
	return nil
}

// sigDetails is what an X.509 signature algorithm is made of.
type sigDetails struct{ signer, hash, param string }

// sigInfo splits a signature algorithm into the signer and the hash.
// Ed25519 and ML-DSA sign the message directly, so they have no hash.
func sigInfo(a x509.SignatureAlgorithm) sigDetails {
	switch a {
	case x509.MD2WithRSA:
		return sigDetails{signer: "RSA", hash: "MD2"}
	case x509.MD5WithRSA:
		return sigDetails{signer: "RSA", hash: "MD5"}
	case x509.SHA1WithRSA:
		return sigDetails{signer: "RSA", hash: "SHA-1"}
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
		return sigDetails{signer: "RSA", hash: "SHA-256"}
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
		return sigDetails{signer: "RSA", hash: "SHA-384"}
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		return sigDetails{signer: "RSA", hash: "SHA-512"}
	case x509.DSAWithSHA1:
		return sigDetails{signer: "DSA", hash: "SHA-1"}
	case x509.DSAWithSHA256:
		return sigDetails{signer: "DSA", hash: "SHA-256"}
	case x509.ECDSAWithSHA1:
		return sigDetails{signer: "ECDSA", hash: "SHA-1"}
	case x509.ECDSAWithSHA256:
		return sigDetails{signer: "ECDSA", hash: "SHA-256"}
	case x509.ECDSAWithSHA384:
		return sigDetails{signer: "ECDSA", hash: "SHA-384"}
	case x509.ECDSAWithSHA512:
		return sigDetails{signer: "ECDSA", hash: "SHA-512"}
	case x509.PureEd25519:
		return sigDetails{signer: "EdDSA"}
	case x509.MLDSA44:
		return sigDetails{signer: "ML-DSA", param: "ML-DSA-44"}
	case x509.MLDSA65:
		return sigDetails{signer: "ML-DSA", param: "ML-DSA-65"}
	case x509.MLDSA87:
		return sigDetails{signer: "ML-DSA", param: "ML-DSA-87"}
	}
	return sigDetails{}
}
