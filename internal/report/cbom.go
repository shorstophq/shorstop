// Package report renders scan findings: a CycloneDX CBOM, SARIF, a
// terminal table and Markdown. Every format starts from the same
// []detect.Finding and rates it with classify.Classify, so they agree.
package report

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/shorstop/shorstop/internal/classify"
	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/pkg/cbom"
)

// CBOMOptions are the parts of a CBOM that don't come from findings.
type CBOMOptions struct {
	ProjectName  string    // the scanned project, for metadata.component
	ToolVersion  string    // ShorStop's version
	Timestamp    time.Time // when the scan ran; also decides "expired"
	SerialNumber string    // "urn:uuid:..."; NewSerialNumber makes one. Empty omits it.
}

const projectRef = "project"

// CBOM builds a CycloneDX 1.6 BOM from findings.
//
// Findings are grouped into components: one per distinct algorithm (by
// name, size, mode and primitive), certificate, public key, protocol
// version and library, with every place it was seen as an occurrence; each
// committed private key is its own component. bom-refs are derived from the
// asset itself, never from scan order, so two scans of the same code give
// the same refs and can be diffed. The output is deterministic for given
// options.
func CBOM(fs []detect.Finding, opts CBOMOptions) *cbom.BOM {
	b := &builder{comps: make(map[string]*entry), provides: make(map[string][]string), at: opts.Timestamp}
	certSigs := certSignatures(fs)
	for _, f := range fs {
		switch {
		case f.PURL != "":
			b.library(f)
		case f.AssetType == detect.AssetCertificate:
			b.certificate(f, certSigs[locKey{f.File, f.Line}])
		case f.AssetType == detect.AssetMaterial:
			b.material(f)
		case f.AssetType == detect.AssetProtocol:
			b.protocol(f)
		case f.Algorithm != "":
			b.algorithm(f, true)
		}
	}

	bom := &cbom.BOM{
		Schema:       "http://cyclonedx.org/schema/bom-1.6.schema.json",
		BOMFormat:    "CycloneDX",
		SpecVersion:  cbom.SpecVersion,
		SerialNumber: opts.SerialNumber,
		Version:      1,
		Metadata: cbom.Metadata{
			Timestamp: opts.Timestamp.UTC().Format(time.RFC3339),
			Tools: cbom.Tools{Components: []cbom.Component{{
				Type: cbom.TypeApplication, Name: "shorstop", Version: opts.ToolVersion,
			}}},
			Component: &cbom.Component{BOMRef: projectRef, Type: cbom.TypeApplication, Name: cmp.Or(opts.ProjectName, "project")},
		},
		Components: []cbom.Component{},
	}

	refs := make([]string, 0, len(b.comps))
	for ref := range b.comps {
		refs = append(refs, ref)
	}
	slices.Sort(refs)
	var libs []string
	for _, ref := range refs {
		e := b.comps[ref]
		bom.Components = append(bom.Components, e.component())
		if e.c.Type == cbom.TypeLibrary {
			libs = append(libs, ref)
		}
	}
	if len(libs) > 0 {
		bom.Dependencies = append(bom.Dependencies, cbom.Dependency{Ref: projectRef, DependsOn: libs})
		for _, lib := range libs {
			d := cbom.Dependency{Ref: lib}
			if p := b.provides[lib]; len(p) > 0 {
				d.Provides = slices.Compact(slices.Sorted(slices.Values(p)))
			}
			bom.Dependencies = append(bom.Dependencies, d)
		}
	}
	return bom
}

// WriteCBOM writes bom as indented JSON.
func WriteCBOM(w io.Writer, bom *cbom.BOM) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // keep "->" and "<" readable in snippets
	return enc.Encode(bom)
}

// NewSerialNumber returns a random (version 4) UUID URN for a BOM.
func NewSerialNumber() (string, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", err
	}
	u[6] = u[6]&0x0f | 0x40 // version 4
	u[8] = u[8]&0x3f | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(u[:])
	return "urn:uuid:" + h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// builder accumulates components by bom-ref.
type builder struct {
	comps    map[string]*entry
	provides map[string][]string // library ref -> algorithm refs it provides
	at       time.Time
}

// entry is a component under construction.
type entry struct {
	c      cbom.Component
	occs   []cbom.Occurrence
	rules  []string
	conf   string
	rating classify.Result
	extra  []cbom.Property // component-specific properties, e.g. shorstop:expired
}

// get returns the entry for ref, creating it with c and rating if new. A
// later finding with a worse rating raises the entry's rating.
func (b *builder) get(ref string, c cbom.Component, rating classify.Result) *entry {
	e, ok := b.comps[ref]
	if !ok {
		c.BOMRef = ref
		e = &entry{c: c, rating: rating}
		b.comps[ref] = e
	} else if rating.Severity.Rank() > e.rating.Severity.Rank() {
		e.rating = rating
	}
	return e
}

// seen records that f is evidence for e.
func (e *entry) seen(f detect.Finding) {
	ctx := f.RuleID
	if f.Snippet != "" {
		ctx += ": " + f.Snippet
	}
	o := cbom.Occurrence{Location: f.File, Line: f.Line, AdditionalContext: ctx}
	if !slices.Contains(e.occs, o) {
		e.occs = append(e.occs, o)
	}
	if !slices.Contains(e.rules, f.RuleID) {
		e.rules = append(e.rules, f.RuleID)
	}
	if confRank[f.Confidence] > confRank[e.conf] {
		e.conf = f.Confidence
	}
}

var confRank = map[string]int{"low": 1, "medium": 2, "high": 3}

// component finishes the entry: sorted evidence and the shorstop:* rating.
func (e *entry) component() cbom.Component {
	c := e.c
	if len(e.occs) > 0 {
		occs := slices.Clone(e.occs)
		slices.SortFunc(occs, func(a, b cbom.Occurrence) int {
			return cmp.Or(cmp.Compare(a.Location, b.Location), cmp.Compare(a.Line, b.Line), cmp.Compare(a.AdditionalContext, b.AdditionalContext))
		})
		c.Evidence = &cbom.Evidence{Occurrences: occs}
	}
	r := e.rating
	c.Properties = []cbom.Property{
		{Name: "shorstop:status", Value: string(r.Status)},
		{Name: "shorstop:severity", Value: string(r.Severity)},
		{Name: "shorstop:reason", Value: r.Reason},
	}
	if r.Recommendation != "" {
		c.Properties = append(c.Properties, cbom.Property{Name: "shorstop:recommendation", Value: r.Recommendation})
	}
	if e.conf != "" {
		c.Properties = append(c.Properties, cbom.Property{Name: "shorstop:confidence", Value: e.conf})
	}
	if len(e.rules) > 0 {
		c.Properties = append(c.Properties, cbom.Property{Name: "shorstop:rules", Value: strings.Join(slices.Sorted(slices.Values(e.rules)), ",")})
	}
	c.Properties = append(c.Properties, e.extra...)
	return c
}

// algorithm adds (or extends) the component for f's algorithm and returns
// its ref. evidence says whether f's location is evidence for it: it is for
// code that uses the algorithm, not for a library that merely provides it.
func (b *builder) algorithm(f detect.Finding, evidence bool) string {
	name := algName(f)
	prim := cmp.Or(f.Primitive, "unknown")
	ref := "crypto:algorithm:" + name + ":" + prim
	ap := &cbom.AlgorithmProperties{
		Primitive:              prim,
		ParameterSetIdentifier: f.ParameterSet,
		Mode:                   cdxMode(f.Mode),
		ClassicalSecurityLevel: classicalLevel(f),
	}
	if ap.ParameterSetIdentifier == "" && f.KeySize > 0 {
		ap.ParameterSetIdentifier = strconv.Itoa(f.KeySize)
	}
	// Rate the algorithm itself, not the finding's context (a dependency
	// hint or a committed key is rated on its own component).
	rating := classify.Classify(detect.Finding{Algorithm: f.Algorithm, Primitive: f.Primitive, KeySize: f.KeySize, Mode: f.Mode, ParameterSet: f.ParameterSet})
	ap.NISTQuantumSecurityLevel = rating.NISTLevel
	e := b.get(ref, cbom.Component{
		Type: cbom.TypeCryptoAsset, Name: name,
		CryptoProperties: &cbom.CryptoProperties{AssetType: detect.AssetAlgorithm, AlgorithmProperties: ap},
	}, rating)
	if evidence {
		e.seen(f)
	}
	return ref
}

// locKey is a finding's location.
type locKey struct {
	file string
	line int
}

// certSig is the signature of one certificate: the algorithm that signed it
// (cert-signature) and the hash inside it (cert-signature-hash).
type certSig struct{ alg, hash *detect.Finding }

// certSignatures maps each location holding exactly one certificate to its
// signature findings, so the certificate can reference the algorithm that
// signed it and be rated by its weakest part. Locations with several
// certificates (a DER file of concatenated certificates is all line 0) are
// left out: which signature belongs to which certificate can't be told.
func certSignatures(fs []detect.Finding) map[locKey]certSig {
	certs := make(map[locKey]int)
	sigs := make(map[locKey]certSig)
	for i := range fs {
		k := locKey{fs[i].File, fs[i].Line}
		switch {
		case fs[i].AssetType == detect.AssetCertificate:
			certs[k]++
		case fs[i].RuleID == "cert-signature":
			s := sigs[k]
			s.alg = &fs[i]
			sigs[k] = s
		case fs[i].RuleID == "cert-signature-hash":
			s := sigs[k]
			s.hash = &fs[i]
			sigs[k] = s
		}
	}
	for k := range sigs {
		if certs[k] != 1 {
			delete(sigs, k)
		}
	}
	return sigs
}

// certificate adds a certificate component. The same certificate (same
// subject, issuer, validity and key) in several files is one component.
func (b *builder) certificate(f detect.Finding, sig certSig) {
	c := f.Cert
	if c == nil {
		c = &detect.Certificate{}
	}
	id := strings.Join([]string{c.Subject, c.Issuer, c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), f.Algorithm, strconv.Itoa(f.KeySize), f.ParameterSet}, "|")
	ref := "crypto:certificate:" + shortHash(id)

	props := &cbom.CertificateProperties{
		SubjectName: c.Subject, IssuerName: c.Issuer, CertificateFormat: "X.509",
	}
	if !c.NotBefore.IsZero() {
		props.NotValidBefore = c.NotBefore.UTC().Format(time.RFC3339)
	}
	if !c.NotAfter.IsZero() {
		props.NotValidAfter = c.NotAfter.UTC().Format(time.RFC3339)
	}
	if f.Algorithm != "" {
		props.SubjectPublicKeyRef = b.algorithm(f, true)
	}
	rating := classify.Classify(f)
	if sig.alg != nil {
		props.SignatureAlgorithmRef = b.algorithm(*sig.alg, false)
	}
	// A certificate is as weak as its weakest part: key, signer or hash.
	for _, part := range []*detect.Finding{sig.alg, sig.hash} {
		if part == nil {
			continue
		}
		if r := classify.Classify(*part); r.Severity.Rank() > rating.Severity.Rank() {
			rating = r
		}
	}
	name := c.Subject
	if name == "" {
		name = "certificate"
	}
	e := b.get(ref, cbom.Component{
		Type: cbom.TypeCryptoAsset, Name: name,
		CryptoProperties: &cbom.CryptoProperties{AssetType: detect.AssetCertificate, CertificateProperties: props},
	}, rating)
	e.seen(f)
	if !c.NotAfter.IsZero() && !b.at.IsZero() && c.NotAfter.Before(b.at) && len(e.extra) == 0 {
		e.extra = append(e.extra, cbom.Property{Name: "shorstop:expired", Value: "true"})
	}
}

// material adds a key. Each committed private key is its own component in
// state "compromised" (anyone with the repository has it); public keys of
// the same algorithm and size are grouped.
func (b *builder) material(f detect.Finding) {
	props := &cbom.RelatedCryptoMaterialProperties{Type: cmp.Or(f.MaterialType, "unknown"), Size: f.KeySize}
	if f.Algorithm != "" {
		props.AlgorithmRef = b.algorithm(f, false)
	}
	name := cmp.Or(algName(f), "unknown-algorithm")
	var ref string
	if f.MaterialType == detect.MaterialPrivateKey {
		props.State = "compromised"
		ref = "crypto:private-key:" + shortHash(fmt.Sprintf("%s:%d:%s", f.File, f.Line, name))
		name += " private key"
	} else {
		ref = "crypto:" + props.Type + ":" + name
		name += " " + strings.ReplaceAll(props.Type, "-", " ")
	}
	e := b.get(ref, cbom.Component{
		Type: cbom.TypeCryptoAsset, Name: name,
		CryptoProperties: &cbom.CryptoProperties{AssetType: detect.AssetMaterial, RelatedCryptoMaterialProperties: props},
	}, classify.Classify(f))
	e.seen(f)
}

// protocol adds an enabled TLS/SSL version.
func (b *builder) protocol(f detect.Finding) {
	version := f.Protocol
	switch {
	case strings.HasPrefix(version, "TLSv"):
		version = strings.TrimPrefix(version, "TLSv")
	case strings.HasPrefix(version, "SSLv"):
		version = strings.TrimPrefix(version, "SSLv") + ".0"
	}
	e := b.get("crypto:protocol:tls:"+f.Protocol, cbom.Component{
		Type: cbom.TypeCryptoAsset, Name: f.Protocol,
		CryptoProperties: &cbom.CryptoProperties{
			AssetType:          detect.AssetProtocol,
			ProtocolProperties: &cbom.ProtocolProperties{Type: "tls", Version: version},
		},
	}, classify.Classify(f))
	e.seen(f)
}

// library adds a dependency as a library component, keyed by its purl
// without version (so the manifest's range and the lockfile's exact version
// are one library), and records which algorithm it provides when the rule
// names one.
func (b *builder) library(f detect.Finding) {
	name, version := purlParts(f.PURL)
	// An npm scope is written %40, so the only "@" in a purl starts the version.
	ref := f.PURL
	if i := strings.LastIndex(f.PURL, "@"); i > 0 {
		ref = f.PURL[:i]
	}
	e := b.get(ref, cbom.Component{Type: cbom.TypeLibrary, Name: name, PURL: ref}, classify.Classify(f))
	if version != "" && e.c.Version == "" {
		e.c.Version, e.c.PURL = version, f.PURL
	}
	e.seen(f)
	if f.Algorithm != "" {
		b.provides[ref] = append(b.provides[ref], b.algorithm(f, false))
	}
}

// purlParts returns the display name and version of a purl:
// "pkg:npm/%40noble/curves@1.4.0" -> "@noble/curves", "1.4.0".
func purlParts(p string) (name, version string) {
	rest := strings.TrimPrefix(p, "pkg:")
	_, rest, _ = strings.Cut(rest, "/")
	if i := strings.LastIndex(rest, "@"); i > 0 {
		rest, version = rest[:i], rest[i+1:]
	}
	if u, err := url.PathUnescape(rest); err == nil {
		rest = u
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	return rest, version
}

// algName is a component name: "RSA-2048", "AES-128-GCM", "ML-KEM-768",
// "Ed25519", "SHA-256". The size is left out where the algorithm has only
// one (X25519, DES, 3DES).
func algName(f detect.Finding) string {
	if f.Algorithm == "" {
		return ""
	}
	name := f.Algorithm
	switch {
	case f.ParameterSet != "":
		name = f.ParameterSet
		if !strings.HasPrefix(f.ParameterSet, f.Algorithm) {
			name = f.Algorithm + "-" + f.ParameterSet
		}
	case f.Algorithm == "EdDSA" && f.KeySize == 255:
		name = "Ed25519"
	case f.KeySize > 0 && f.Algorithm != "X25519" && f.Algorithm != "DES" && f.Algorithm != "3DES":
		name += "-" + strconv.Itoa(f.KeySize)
	}
	if f.Mode != "" {
		name += "-" + f.Mode
	}
	return name
}

// cdxMode maps rules.Modes to CycloneDX's mode enum, which has no XTS,
// OCB, EAX or SIV.
func cdxMode(m string) string {
	switch m {
	case "":
		return ""
	case "CBC", "ECB", "CCM", "GCM", "CFB", "OFB", "CTR":
		return strings.ToLower(m)
	}
	return "other"
}

// classicalLevel is the classical security strength in bits, where it is
// well defined: AES and other ciphers by key size; RSA, DSA and DH by NIST
// SP 800-57 Part 1 Table 2; elliptic curves at half the field size; hashes
// by collision resistance. 0 means unknown, or broken in practice.
func classicalLevel(f detect.Finding) int {
	switch f.Algorithm {
	case "AES":
		return f.KeySize
	case "ChaCha20":
		return 256
	case "3DES":
		return 112
	case "RSA", "DSA", "DH":
		for _, t := range []struct{ bits, level int }{{15360, 256}, {7680, 192}, {3072, 128}, {2048, 112}, {1024, 80}} {
			if f.KeySize >= t.bits {
				return t.level
			}
		}
	case "ECC", "ECDSA", "ECDH":
		return f.KeySize / 2
	case "EdDSA", "X25519":
		return 128
	case "SHA-224":
		return 112
	case "SHA-256":
		return 128
	case "SHA-384":
		return 192
	case "SHA-512":
		return 256
	}
	return 0
}

// shortHash is a stable 16-hex-digit identifier for a ref.
func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
