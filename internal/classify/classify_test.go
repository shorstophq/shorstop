package classify

import (
	"strings"
	"testing"

	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/rules"
)

func TestClassify(t *testing.T) {
	alg := func(a, prim string, bits int, mode string) detect.Finding {
		return detect.Finding{Algorithm: a, Primitive: prim, KeySize: bits, Mode: mode}
	}
	tests := []struct {
		name   string
		f      detect.Finding
		status Status
		sev    Severity
		level  int
	}{
		// The plan's matrix, row by row.
		{"RSA any size, key exchange", alg("RSA", "pke", 4096, ""), QuantumVulnerable, High, 0},
		{"DH", alg("DH", "key-agree", 2048, ""), QuantumVulnerable, High, 0},
		{"DSA signature", alg("DSA", "signature", 2048, ""), QuantumVulnerable, Medium, 0},
		{"ECDSA signature", alg("ECDSA", "signature", 256, ""), QuantumVulnerable, Medium, 0},
		{"ECDH", alg("ECDH", "key-agree", 384, ""), QuantumVulnerable, High, 0},
		{"EdDSA", alg("EdDSA", "signature", 255, ""), QuantumVulnerable, Medium, 0},
		{"X25519", alg("X25519", "key-agree", 255, ""), QuantumVulnerable, High, 0},
		{"AES-128", alg("AES", "block-cipher", 128, "GCM"), Weakened, Medium, 1},
		{"AES-256", alg("AES", "block-cipher", 256, "GCM"), Acceptable, Info, 5},
		{"SHA-256", alg("SHA-256", "hash", 0, ""), Acceptable, Info, 2},
		{"SHA-384", alg("SHA-384", "hash", 0, ""), Acceptable, Info, 4},
		{"SHA-512", alg("SHA-512", "hash", 0, ""), Acceptable, Info, 0},
		{"SHA-3", alg("SHA-3", "hash", 0, ""), Acceptable, Info, 0},
		{"MD5", alg("MD5", "hash", 0, ""), Broken, Critical, 0},
		{"SHA-1 hash", alg("SHA-1", "hash", 0, ""), Broken, Critical, 0},
		{"DES", alg("DES", "block-cipher", 56, "CBC"), Broken, Critical, 0},
		{"3DES", alg("3DES", "block-cipher", 168, "CBC"), Broken, Critical, 0},
		{"RC4", alg("RC4", "stream-cipher", 0, ""), Broken, Critical, 0},
		{"AES-ECB, any size", alg("AES", "block-cipher", 256, "ECB"), InsecureMode, High, 0},
		{"AES-ECB, unknown size", alg("AES", "block-cipher", 0, "ECB"), InsecureMode, High, 0},
		{"ML-KEM-768", detect.Finding{Algorithm: "ML-KEM", Primitive: "kem", ParameterSet: "ML-KEM-768"}, QuantumSafe, Info, 3},
		{"ML-DSA-87", detect.Finding{Algorithm: "ML-DSA", Primitive: "signature", ParameterSet: "ML-DSA-87"}, QuantumSafe, Info, 5},
		{"SLH-DSA", alg("SLH-DSA", "signature", 0, ""), QuantumSafe, Info, 0},

		// Gaps the matrix doesn't cover.
		{"RSA of unknown use defaults to high", alg("RSA", "", 0, ""), QuantumVulnerable, High, 0},
		{"RSA-1024 is broken now", alg("RSA", "pke", 1024, ""), Broken, Critical, 0},
		{"DH-1024 (Logjam)", alg("DH", "key-agree", 1024, ""), Broken, Critical, 0},
		{"RSA-2048 is not short", alg("RSA", "signature", 2048, ""), QuantumVulnerable, Medium, 0},
		{"P-192 is short", alg("ECDSA", "signature", 192, ""), Broken, Critical, 0},
		{"HMAC-SHA-1 is not broken", alg("SHA-1", "mac", 0, ""), Acceptable, Low, 0},
		{"HMAC-MD5 is not broken", alg("MD5", "mac", 0, ""), Acceptable, Low, 0},
		{"SHA-1 in key derivation", alg("SHA-1", "kdf", 0, ""), Acceptable, Low, 0},
		{"MD4", alg("MD4", "hash", 0, ""), Broken, Critical, 0},
		{"AES-192", alg("AES", "block-cipher", 192, "CBC"), Acceptable, Info, 3},
		{"AES of unknown size", alg("AES", "block-cipher", 0, ""), Unknown, Low, 0},
		{"ChaCha20", alg("ChaCha20", "ae", 0, ""), Acceptable, Info, 0},
		{"sntrup761", alg("sntrup761", "kem", 0, ""), QuantumSafe, Info, 0},
		{"unknown algorithm", alg("", "", 0, ""), Unknown, Low, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Classify(tt.f)
			if r.Status != tt.status || r.Severity != tt.sev || r.NISTLevel != tt.level {
				t.Errorf("got %s/%s/level %d, want %s/%s/level %d (%s)", r.Status, r.Severity, r.NISTLevel, tt.status, tt.sev, tt.level, r.Reason)
			}
		})
	}
}

func TestPrivateKeys(t *testing.T) {
	key := func(a string) detect.Finding {
		return detect.Finding{Algorithm: a, AssetType: detect.AssetMaterial, MaterialType: detect.MaterialPrivateKey}
	}
	for _, tt := range []struct {
		alg    string
		status Status
	}{
		{"RSA", QuantumVulnerable},
		{"ML-DSA", QuantumSafe}, // a quantum-safe key is still a leaked secret
		{"", Unknown},           // encrypted or undecodable
	} {
		r := Classify(key(tt.alg))
		if r.Severity != Critical || r.Status != tt.status || !strings.Contains(r.Recommendation, "rotate") {
			t.Errorf("private key %q: got %+v, want critical, %s, rotate", tt.alg, r, tt.status)
		}
	}
	// A public key or certificate is not a secret.
	pub := detect.Finding{Algorithm: "RSA", AssetType: detect.AssetMaterial, MaterialType: detect.MaterialPublicKey}
	if r := Classify(pub); r.Severity == Critical {
		t.Errorf("public key rated critical: %+v", r)
	}
}

func TestProtocols(t *testing.T) {
	for _, tt := range []struct {
		v      string
		status Status
		sev    Severity
	}{
		{detect.SSLv2, Broken, Critical},
		{detect.SSLv3, Broken, Critical},
		{detect.TLSv10, Broken, High},
		{detect.TLSv11, Broken, High},
		{detect.TLSv12, Acceptable, Info},
		{detect.TLSv13, Acceptable, Info},
		{"TLSv9", Unknown, Low},
	} {
		r := Classify(detect.Finding{AssetType: detect.AssetProtocol, Protocol: tt.v})
		if r.Status != tt.status || r.Severity != tt.sev {
			t.Errorf("%s: got %s/%s, want %s/%s", tt.v, r.Status, r.Severity, tt.status, tt.sev)
		}
	}
}

func TestDependenciesAreLow(t *testing.T) {
	for _, tt := range []struct {
		alg string
		sev Severity
	}{
		{"MD5", Low},     // broken, but only a hint: is md5 actually called?
		{"RSA", Low},     // quantum-vulnerable, same
		{"", Low},        // toolkit
		{"ML-KEM", Info}, // quantum-safe stays info: lowering never raises
	} {
		r := Classify(detect.Finding{Algorithm: tt.alg, PURL: "pkg:npm/x@1"})
		if r.Severity != tt.sev || !strings.HasPrefix(r.Reason, "Dependency: ") {
			t.Errorf("dependency %q: got %+v, want %s", tt.alg, r, tt.sev)
		}
	}
}

// TestEveryAlgorithmIsRated fails when an algorithm is added to
// rules.Algorithms without a rating here.
func TestEveryAlgorithmIsRated(t *testing.T) {
	for _, a := range rules.Algorithms {
		for _, prim := range []string{"", "signature", "key-agree", "hash"} {
			r := Classify(detect.Finding{Algorithm: a, Primitive: prim})
			if strings.HasPrefix(r.Reason, "Unrated") || r.Status == "" || r.Severity == "" {
				t.Errorf("%s (%q): not rated: %+v", a, prim, r)
			}
		}
	}
}

// TestResultsAreComplete: every rating explains itself, and every rating
// that asks for work says what to do.
func TestResultsAreComplete(t *testing.T) {
	var fs []detect.Finding
	for _, a := range rules.Algorithms {
		for _, prim := range []string{"", "signature", "key-agree", "hash", "mac"} {
			for _, bits := range []int{0, 128, 1024, 4096} {
				fs = append(fs, detect.Finding{Algorithm: a, Primitive: prim, KeySize: bits}, detect.Finding{Algorithm: a, KeySize: bits, Mode: "ECB"})
			}
		}
	}
	for _, v := range []string{detect.SSLv3, detect.TLSv10, detect.TLSv13} {
		fs = append(fs, detect.Finding{AssetType: detect.AssetProtocol, Protocol: v})
	}
	for _, f := range fs {
		r := Classify(f)
		if r.Reason == "" {
			t.Errorf("%+v: no reason", f)
		}
		if r.Severity.Rank() >= Medium.Rank() && r.Recommendation == "" {
			t.Errorf("%+v rated %s with no recommendation", f, r.Severity)
		}
		if r.Severity.Rank() == 0 {
			t.Errorf("%+v: severity %q has no rank", f, r.Severity)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	order := []Severity{Info, Low, Medium, High, Critical}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Errorf("%s does not rank above %s", order[i], order[i-1])
		}
	}
	if Severity("bogus").Rank() != 0 {
		t.Error("unknown severity has a rank")
	}
}
