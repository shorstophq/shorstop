// Package classify rates a finding: its quantum-risk status, how severe it
// is, why, and what to use instead.
//
// Classify is a pure function of one detect.Finding. It never looks at the
// file or at other findings, so it is trivially testable, deterministic, and
// safe to call from any reporter.
package classify

import (
	"fmt"

	"github.com/shorstop/shorstop/internal/detect"
)

// Status is a finding's risk class.
type Status string

const (
	// QuantumVulnerable: secure today, broken by Shor's algorithm on a large
	// quantum computer (RSA, DH, DSA, elliptic curves).
	QuantumVulnerable Status = "QUANTUM_VULNERABLE"
	// Weakened: Grover's algorithm halves its effective strength (AES-128).
	Weakened Status = "WEAKENED"
	// Broken: insecure today, quantum computer or not (MD5, SHA-1
	// signatures, DES, 3DES, RC4, short keys, SSL, TLS 1.0/1.1).
	Broken Status = "BROKEN"
	// InsecureMode: a sound cipher used in a mode that leaks (ECB).
	InsecureMode Status = "INSECURE_MODE"
	// Acceptable: fine now and after quantum computers (AES-256, SHA-2, SHA-3).
	Acceptable Status = "ACCEPTABLE"
	// QuantumSafe: post-quantum cryptography, shown as migration progress.
	QuantumSafe Status = "QUANTUM_SAFE"
	// Unknown: not enough is known to rate it, such as a crypto toolkit
	// dependency or AES of unknown key size.
	Unknown Status = "UNKNOWN"
)

// Severity orders findings for triage and for --fail-on.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info" // nothing to fix: acceptable or quantum-safe
)

// Rank orders severities: Critical highest, Info lowest, 0 for anything else.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	}
	return 0
}

// Result is the rating of one finding.
type Result struct {
	Status         Status
	Severity       Severity
	Reason         string // why, in one sentence
	Recommendation string // what to do; "" when nothing needs doing
	// NISTLevel is the NIST post-quantum security category (1-5) where NIST
	// defines one for the algorithm and size (AES-128/192/256, SHA-256/384,
	// ML-KEM, ML-DSA), for CycloneDX nistQuantumSecurityLevel. 0 means not
	// quantum-safe, or no category defined.
	NISTLevel int
}

// Recommendations, shared by several rules.
const (
	recKEM       = "Migrate key exchange and encryption to ML-KEM (FIPS 203); for TLS, enable the hybrid X25519MLKEM768 group."
	recSignature = "Plan a migration of signatures to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)."
	recPublicKey = "Migrate to ML-KEM (FIPS 203) for key exchange and encryption, and ML-DSA (FIPS 204) for signatures; for TLS, enable X25519MLKEM768."
	recHash      = "Use SHA-256 or stronger (SHA-384, SHA-3)."
	recCipher    = "Use AES-256-GCM (or ChaCha20-Poly1305)."
	recTLS       = "Allow only TLS 1.2 and 1.3."
	recKey       = "Treat the key as compromised: revoke and rotate it, remove it from the repository history, and keep keys in a secret manager."
)

// Classify rates one finding. The order of the checks is the order of
// precedence: a committed private key is critical whatever its algorithm,
// and ECB is insecure whatever the AES key size.
func Classify(f detect.Finding) Result {
	// 1. Committed private keys: a secret exposed today.
	if f.AssetType == detect.AssetMaterial && f.MaterialType == detect.MaterialPrivateKey {
		r := Result{
			Status:         Unknown,
			Severity:       Critical,
			Reason:         "A private key is committed to the repository: anyone who can read the repository has the key.",
			Recommendation: recKey,
		}
		if f.Algorithm != "" {
			r.Status = algorithm(f).Status
		}
		return r
	}

	// 2. TLS/SSL protocol versions.
	if f.AssetType == detect.AssetProtocol {
		return protocol(f.Protocol)
	}

	r := algorithm(f)

	// 3. Dependencies are hints: the library is present, its use unknown.
	if f.PURL != "" {
		if r.Severity.Rank() > Low.Rank() {
			r.Severity = Low
		}
		r.Reason = "Dependency: " + r.Reason
	}
	return r
}

// protocol rates an enabled TLS/SSL version.
func protocol(v string) Result {
	switch v {
	case detect.SSLv2, detect.SSLv3:
		return Result{Status: Broken, Severity: Critical,
			Reason:         v + " is broken (DROWN, POODLE) and prohibited by RFC 6176 and RFC 7568.",
			Recommendation: recTLS}
	case detect.TLSv10, detect.TLSv11:
		// Deprecated rather than practically broken: the known attacks
		// (BEAST, Lucky 13) are mitigated in current stacks, so high, not
		// critical.
		return Result{Status: Broken, Severity: High,
			Reason:         v + " is deprecated by RFC 8996 and rejected by modern clients and PCI DSS.",
			Recommendation: recTLS}
	case detect.TLSv12, detect.TLSv13:
		return Result{Status: Acceptable, Severity: Info,
			Reason: v + " is current; its key exchange is rated separately."}
	}
	return Result{Status: Unknown, Severity: Low, Reason: fmt.Sprintf("Unrecognised protocol version %q.", v)}
}

// algorithm rates a finding by its algorithm, key size, mode and primitive.
func algorithm(f detect.Finding) Result {
	switch f.Algorithm {
	case "RSA", "DSA", "DH":
		if f.KeySize > 0 && f.KeySize < 2048 {
			return shortKey(f, 2048)
		}
		return quantumVulnerable(f)
	case "ECC", "ECDSA", "ECDH":
		if f.KeySize > 0 && f.KeySize < 224 {
			return shortKey(f, 224)
		}
		return quantumVulnerable(f)
	case "EdDSA", "X25519":
		return quantumVulnerable(f)

	case "ML-KEM", "ML-DSA", "SLH-DSA":
		return Result{Status: QuantumSafe, Severity: Info,
			Reason:    f.Algorithm + " is NIST-standardised post-quantum cryptography (FIPS 203/204/205).",
			NISTLevel: pqcLevel(f.ParameterSet)}
	case "sntrup761":
		return Result{Status: QuantumSafe, Severity: Info,
			Reason: "sntrup761 (Streamlined NTRU Prime) resists quantum attacks but is not NIST-standardised; OpenSSH pairs it with X25519."}

	case "AES":
		if f.Mode == "ECB" {
			return Result{Status: InsecureMode, Severity: High,
				Reason:         "ECB mode encrypts equal blocks to equal ciphertext, leaking patterns in the data.",
				Recommendation: "Use AES-GCM (or another authenticated mode)."}
		}
		switch f.KeySize {
		case 128:
			return Result{Status: Weakened, Severity: Medium,
				Reason:         "Grover's algorithm halves AES-128's effective strength to about 64 bits against a quantum attacker.",
				Recommendation: "Use AES-256.", NISTLevel: 1}
		case 192:
			return Result{Status: Acceptable, Severity: Info, Reason: "AES-192 keeps about 96-bit strength against Grover's algorithm.", NISTLevel: 3}
		case 256:
			return Result{Status: Acceptable, Severity: Info, Reason: "AES-256 keeps about 128-bit strength against Grover's algorithm.", NISTLevel: 5}
		}
		return Result{Status: Unknown, Severity: Low,
			Reason:         "AES with an unknown key size: AES-128 is weakened by Grover's algorithm, AES-256 is not.",
			Recommendation: "Make sure the key is 256 bits."}
	case "ChaCha20":
		return Result{Status: Acceptable, Severity: Info, Reason: "ChaCha20 uses 256-bit keys, which keep about 128-bit strength against Grover's algorithm."}

	case "DES", "3DES", "RC4":
		return Result{Status: Broken, Severity: Critical,
			Reason:         brokenCipher[f.Algorithm],
			Recommendation: recCipher}

	case "MD2", "MD4", "MD5", "SHA-1":
		// HMAC and key derivation need preimage resistance, which MD5 and
		// SHA-1 still have; it is collisions that are broken. Reporting
		// HMAC-SHA-1 as broken would overstate the risk.
		if f.Primitive == "mac" || f.Primitive == "kdf" {
			return Result{Status: Acceptable, Severity: Low,
				Reason:         "HMAC-" + f.Algorithm + " is not broken by the known collision attacks, but it is deprecated.",
				Recommendation: "Prefer HMAC-SHA-256."}
		}
		return Result{Status: Broken, Severity: Critical,
			Reason:         f.Algorithm + " has practical collision attacks: signatures and integrity checks that rely on it can be forged.",
			Recommendation: recHash}
	case "SHA-224", "SHA-512", "SHA-3":
		return Result{Status: Acceptable, Severity: Info, Reason: f.Algorithm + " is not meaningfully weakened by quantum computers."}
	case "SHA-256":
		return Result{Status: Acceptable, Severity: Info, Reason: "SHA-256 is not meaningfully weakened by quantum computers.", NISTLevel: 2}
	case "SHA-384":
		return Result{Status: Acceptable, Severity: Info, Reason: "SHA-384 is not meaningfully weakened by quantum computers.", NISTLevel: 4}

	case "":
		return Result{Status: Unknown, Severity: Low,
			Reason:         "A cryptographic library or object whose algorithms aren't known.",
			Recommendation: "Check which algorithms it is used with."}
	}
	return Result{Status: Unknown, Severity: Low, Reason: fmt.Sprintf("Unrated algorithm %q.", f.Algorithm)}
}

var brokenCipher = map[string]string{
	"DES":  "DES's 56-bit key can be brute-forced in hours.",
	"3DES": "3DES's 64-bit block allows practical collision attacks (Sweet32), and NIST disallowed it after 2023.",
	"RC4":  "RC4's keystream biases allow plaintext recovery; RFC 7465 prohibits it in TLS.",
}

// quantumVulnerable rates public-key cryptography broken by Shor's
// algorithm. Key exchange and encryption are high: traffic recorded today
// can be decrypted later ("harvest now, decrypt later"). Signatures are
// medium: they only need replacing before a quantum computer exists. When
// the use is unknown (an import, a certificate's key), the higher rating
// applies.
func quantumVulnerable(f detect.Finding) Result {
	r := Result{Status: QuantumVulnerable, Severity: High}
	switch f.Primitive {
	case "signature":
		r.Severity = Medium
		r.Reason = f.Algorithm + " signatures can be forged with Shor's algorithm on a large quantum computer."
		r.Recommendation = recSignature
	case "key-agree", "pke", "kem":
		r.Reason = f.Algorithm + " key exchange is broken by Shor's algorithm; data encrypted today can be recorded and decrypted later."
		r.Recommendation = recKEM
	default:
		r.Reason = f.Algorithm + " is broken by Shor's algorithm; if it protects key exchange or encryption, data encrypted today can be recorded and decrypted later."
		r.Recommendation = recPublicKey
	}
	return r
}

// shortKey rates a public key below today's classical minimum (NIST SP
// 800-131A): broken now, not only by quantum computers.
func shortKey(f detect.Finding, minBits int) Result {
	return Result{Status: Broken, Severity: Critical,
		Reason:         fmt.Sprintf("%d-bit %s is below the %d-bit minimum (NIST SP 800-131A) and within reach of classical attacks.", f.KeySize, f.Algorithm, minBits),
		Recommendation: quantumVulnerable(f).Recommendation}
}

// pqcLevel is the NIST security category of an ML-KEM or ML-DSA parameter
// set, or 0 when it is unknown.
func pqcLevel(param string) int {
	switch param {
	case "ML-KEM-512":
		return 1
	case "ML-DSA-44":
		return 2
	case "ML-KEM-768", "ML-DSA-65":
		return 3
	case "ML-KEM-1024", "ML-DSA-87":
		return 5
	}
	return 0
}
