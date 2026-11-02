// Package cbom holds the CycloneDX 1.6 types for a Cryptographic Bill of
// Materials. It is public so the ShorStop backend can decode exactly what
// the CLI writes.
//
// Only the parts of the specification that ShorStop produces are modelled.
// Field names, nesting and enum values follow the official JSON schema
// (bom-1.6.schema.json), which the tests validate against.
package cbom

// SpecVersion is the CycloneDX version these types follow.
const SpecVersion = "1.6"

// BOM is a CycloneDX document.
type BOM struct {
	Schema       string       `json:"$schema,omitempty"`
	BOMFormat    string       `json:"bomFormat"`   // always "CycloneDX"
	SpecVersion  string       `json:"specVersion"` // SpecVersion
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// Metadata describes the BOM itself.
type Metadata struct {
	Timestamp string     `json:"timestamp"` // RFC 3339
	Tools     Tools      `json:"tools"`
	Component *Component `json:"component,omitempty"` // the scanned project
}

// Tools lists the tools that made the BOM (CycloneDX 1.5+ object form).
type Tools struct {
	Components []Component `json:"components"`
}

// Component types used by ShorStop.
const (
	TypeCryptoAsset = "cryptographic-asset"
	TypeLibrary     = "library"
	TypeApplication = "application"
)

// Component is one entry of the BOM: a crypto asset, a library, the tool or
// the scanned project.
type Component struct {
	BOMRef           string            `json:"bom-ref,omitempty"`
	Type             string            `json:"type"`
	Name             string            `json:"name"`
	Version          string            `json:"version,omitempty"`
	PURL             string            `json:"purl,omitempty"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *Evidence         `json:"evidence,omitempty"`
	Properties       []Property        `json:"properties,omitempty"` // shorstop:* rating
}

// CryptoProperties is the crypto-specific part of a cryptographic-asset.
type CryptoProperties struct {
	AssetType                       string                           `json:"assetType"` // algorithm | certificate | protocol | related-crypto-material
	AlgorithmProperties             *AlgorithmProperties             `json:"algorithmProperties,omitempty"`
	CertificateProperties           *CertificateProperties           `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterialProperties *RelatedCryptoMaterialProperties `json:"relatedCryptoMaterialProperties,omitempty"`
	ProtocolProperties              *ProtocolProperties              `json:"protocolProperties,omitempty"`
	OID                             string                           `json:"oid,omitempty"`
}

// AlgorithmProperties describes an algorithm asset.
type AlgorithmProperties struct {
	// Primitive is one of drbg, mac, block-cipher, stream-cipher, signature,
	// hash, pke, xof, kdf, key-agree, kem, ae, combiner, other, unknown.
	Primitive              string `json:"primitive"`
	ParameterSetIdentifier string `json:"parameterSetIdentifier,omitempty"` // "2048", "ML-KEM-768"
	// Mode is one of cbc, ecb, ccm, gcm, cfb, ofb, ctr, other, unknown.
	Mode                   string `json:"mode,omitempty"`
	ClassicalSecurityLevel int    `json:"classicalSecurityLevel,omitempty"` // bits
	// NISTQuantumSecurityLevel is the NIST PQC security category, 0-6; 0
	// means not quantum-safe (or no category defined).
	NISTQuantumSecurityLevel int `json:"nistQuantumSecurityLevel"`
}

// CertificateProperties describes a certificate asset.
type CertificateProperties struct {
	SubjectName           string `json:"subjectName,omitempty"`
	IssuerName            string `json:"issuerName,omitempty"`
	NotValidBefore        string `json:"notValidBefore,omitempty"` // RFC 3339
	NotValidAfter         string `json:"notValidAfter,omitempty"`  // RFC 3339
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string `json:"certificateFormat,omitempty"` // "X.509"
}

// RelatedCryptoMaterialProperties describes a key or other crypto material.
type RelatedCryptoMaterialProperties struct {
	Type         string `json:"type"`            // private-key, public-key, ...
	State        string `json:"state,omitempty"` // e.g. "compromised"
	AlgorithmRef string `json:"algorithmRef,omitempty"`
	Size         int    `json:"size,omitempty"` // bits
}

// ProtocolProperties describes a protocol asset.
type ProtocolProperties struct {
	Type    string `json:"type"`              // tls, ssh, ipsec, ike, sstp, wpa, other, unknown
	Version string `json:"version,omitempty"` // "1.2", or "3.0" for SSLv3
}

// Evidence lists where a component was found.
type Evidence struct {
	Occurrences []Occurrence `json:"occurrences"`
}

// Occurrence is one place a component was found.
type Occurrence struct {
	Location          string `json:"location"`       // slash-separated path in the scanned tree
	Line              int    `json:"line,omitempty"` // 1-based; absent for binary files
	AdditionalContext string `json:"additionalContext,omitempty"`
}

// Property is a name/value pair. ShorStop's are namespaced "shorstop:".
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// Dependency links a component to what it depends on and, for libraries,
// the crypto assets it provides.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
	Provides  []string `json:"provides,omitempty"`
}
