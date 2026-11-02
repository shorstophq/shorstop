package config

import (
	"strings"

	"github.com/shorstop/shorstop/internal/detect"
)

// algo is one algorithm a configuration value enables.
type algo struct {
	alg, prim, mode, param string
	bits                   int
}

// tlsVersions is every TLS/SSL version, oldest first.
var tlsVersions = []string{detect.SSLv2, detect.SSLv3, detect.TLSv10, detect.TLSv11, detect.TLSv12, detect.TLSv13}

// apacheAll is what Apache's SSLProtocol "all" enables. SSLv3 is not in it:
// OpenSSL 1.1.0 and later are built without SSLv3, and Apache 2.4 only
// adds it when the library has it.
var apacheAll = []string{detect.TLSv10, detect.TLSv11, detect.TLSv12, detect.TLSv13}

// parseVersion reads a version as nginx, Apache, HAProxy, PostgreSQL and
// OpenSSL spell it ("TLSv1", "TLSv1.0", "tlsv12" is not accepted).
func parseVersion(s string) (string, bool) {
	switch strings.ToUpper(strings.Trim(s, `'"`)) {
	case "SSLV2":
		return detect.SSLv2, true
	case "SSLV3":
		return detect.SSLv3, true
	case "TLSV1", "TLSV1.0":
		return detect.TLSv10, true
	case "TLSV1.1":
		return detect.TLSv11, true
	case "TLSV1.2":
		return detect.TLSv12, true
	case "TLSV1.3":
		return detect.TLSv13, true
	}
	return "", false
}

// protocolList returns the versions a protocol list enables, oldest first.
// It handles nginx ("TLSv1.2 TLSv1.3") and Apache ("all -SSLv3 +TLSv1.3"):
// "+" or no prefix adds, "-" or "!" removes, "all" adds apacheAll.
func protocolList(v string) []string {
	on := make(map[string]bool)
	for _, tok := range splitAny(v, " ,:") {
		op := byte('+')
		if strings.ContainsRune("+-!", rune(tok[0])) {
			op, tok = tok[0], tok[1:]
		}
		var vs []string
		if strings.EqualFold(tok, "all") {
			vs = apacheAll
		} else if ver, ok := parseVersion(tok); ok {
			vs = []string{ver}
		}
		for _, ver := range vs {
			on[ver] = op == '+'
		}
	}
	var out []string
	for _, ver := range tlsVersions {
		if on[ver] {
			out = append(out, ver)
		}
	}
	return out
}

// minProtocol returns the versions a minimum version enables: it and every
// newer one.
func minProtocol(v string) []string {
	ver, ok := parseVersion(v)
	if !ok {
		return nil
	}
	for i, x := range tlsVersions {
		if x == ver {
			return tlsVersions[i:]
		}
	}
	return nil
}

// cipherKeywords are the single-word OpenSSL cipher-string terms that name
// one algorithm. Terms that name a set chosen by the OpenSSL build (HIGH,
// MEDIUM, DEFAULT, ALL, ...) aren't here: expanding them would need the
// library's own table, so they add nothing.
var cipherKeywords = map[string][]algo{
	"RC4":      {{alg: "RC4", prim: "stream-cipher"}},
	"3DES":     {{alg: "3DES", prim: "block-cipher", bits: 168, mode: "CBC"}},
	"DES":      {{alg: "DES", prim: "block-cipher", bits: 56, mode: "CBC"}},
	"MD5":      {{alg: "MD5", prim: "mac"}},
	"SHA1":     {{alg: "SHA-1", prim: "mac"}},
	"SHA":      {{alg: "SHA-1", prim: "mac"}},
	"SHA256":   {{alg: "SHA-256", prim: "mac"}},
	"SHA384":   {{alg: "SHA-384", prim: "mac"}},
	"RSA":      {{alg: "RSA", prim: "pke"}},
	"KRSA":     {{alg: "RSA", prim: "pke"}},
	"ARSA":     {{alg: "RSA", prim: "signature"}},
	"ECDH":     {{alg: "ECDH", prim: "key-agree"}},
	"ECDHE":    {{alg: "ECDH", prim: "key-agree"}},
	"EECDH":    {{alg: "ECDH", prim: "key-agree"}},
	"KECDHE":   {{alg: "ECDH", prim: "key-agree"}},
	"KEECDH":   {{alg: "ECDH", prim: "key-agree"}},
	"DH":       {{alg: "DH", prim: "key-agree"}},
	"DHE":      {{alg: "DH", prim: "key-agree"}},
	"EDH":      {{alg: "DH", prim: "key-agree"}},
	"KDHE":     {{alg: "DH", prim: "key-agree"}},
	"KEDH":     {{alg: "DH", prim: "key-agree"}},
	"ECDSA":    {{alg: "ECDSA", prim: "signature"}},
	"AECDSA":   {{alg: "ECDSA", prim: "signature"}},
	"DSS":      {{alg: "DSA", prim: "signature"}},
	"ADSS":     {{alg: "DSA", prim: "signature"}},
	"AES":      {{alg: "AES", prim: "block-cipher"}},
	"AES128":   {{alg: "AES", prim: "block-cipher", bits: 128}},
	"AES256":   {{alg: "AES", prim: "block-cipher", bits: 256}},
	"AESGCM":   {{alg: "AES", prim: "block-cipher", mode: "GCM"}},
	"AESCCM":   {{alg: "AES", prim: "block-cipher", mode: "CCM"}},
	"AESCCM8":  {{alg: "AES", prim: "block-cipher", mode: "CCM"}},
	"CHACHA20": {{alg: "ChaCha20", prim: "ae"}},
}

// cipherString returns the algorithms an OpenSSL cipher string enables, as
// used by nginx ssl_ciphers, Apache SSLCipherSuite, HAProxy, PostgreSQL and
// openssl.cnf CipherString/Ciphersuites. Terms starting with "!" or "-"
// remove suites and "+" only reorders them, so none of them enable
// anything; "@" terms (@SECLEVEL, @STRENGTH) are options. "EECDH+AESGCM"
// requires both parts, so each part is reported.
func cipherString(v string) []algo {
	var out []algo
	for _, tok := range splitAny(v, ": ,") {
		if strings.ContainsRune("!-+@", rune(tok[0])) {
			continue
		}
		for _, part := range strings.Split(tok, "+") {
			up := strings.ToUpper(part)
			if as, ok := cipherKeywords[up]; ok {
				out = append(out, as...)
				continue
			}
			out = append(out, parseSuite(up)...)
		}
	}
	return out
}

// parseSuite reads one cipher-suite name, in OpenSSL form
// ("ECDHE-RSA-AES128-GCM-SHA256", "DES-CBC3-SHA") or IANA form
// ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", TLS 1.3's "TLS_AES_256_GCM_SHA384").
// s is upper case. Unknown names and parts give nothing.
func parseSuite(s string) []algo {
	iana := strings.HasPrefix(s, "TLS_") || strings.HasPrefix(s, "SSL_")
	if iana {
		s = s[4:]
	}
	toks := strings.Split(strings.ReplaceAll(s, "_", "-"), "-")
	if len(toks) < 2 {
		return nil
	}
	next := func(i int) string {
		if i+1 < len(toks) {
			return toks[i+1]
		}
		return ""
	}

	var out []algo
	sawKx, sawCipher, aead := false, false, false
	for i := 0; i < len(toks); i++ {
		switch t := toks[i]; t {
		case "ECDHE", "ECDH", "EECDH", "AECDH":
			out, sawKx = append(out, algo{alg: "ECDH", prim: "key-agree"}), true
		case "DHE", "DH", "EDH", "ADH":
			out, sawKx = append(out, algo{alg: "DH", prim: "key-agree"}), true
		case "RSA":
			// After a key exchange, RSA signs (ECDHE-RSA-...). On its own
			// (TLS_RSA_WITH_...) it also transports the key.
			if sawKx {
				out = append(out, algo{alg: "RSA", prim: "signature"})
			} else {
				out, sawKx = append(out, algo{alg: "RSA", prim: "pke"}), true
			}
		case "ECDSA":
			out = append(out, algo{alg: "ECDSA", prim: "signature"})
		case "DSS":
			out = append(out, algo{alg: "DSA", prim: "signature"})
		case "PSK", "SRP", "KRB5", "ANON":
			sawKx = true // not public-key: no RSA is implied
		case "AES128", "AES256", "AES":
			bits := 128
			switch {
			case t == "AES256":
				bits = 256
			case t == "AES" && (next(i) == "128" || next(i) == "256"):
				if next(i) == "256" {
					bits = 256
				}
				i++
			case t == "AES":
				bits = 0
			}
			mode := "CBC" // TLS AES suites without an AEAD mode are CBC
			switch next(i) {
			case "GCM":
				mode, aead = "GCM", true
				i++
			case "CCM", "CCM8":
				mode, aead = "CCM", true
				i++
			case "CBC":
				i++
			}
			out, sawCipher = append(out, algo{alg: "AES", prim: "block-cipher", bits: bits, mode: mode}), true
		case "3DES":
			out, sawCipher = append(out, algo{alg: "3DES", prim: "block-cipher", bits: 168, mode: "CBC"}), true
			for next(i) == "EDE" || next(i) == "CBC" {
				i++
			}
		case "DES":
			if next(i) == "CBC3" {
				out = append(out, algo{alg: "3DES", prim: "block-cipher", bits: 168, mode: "CBC"})
			} else {
				out = append(out, algo{alg: "DES", prim: "block-cipher", bits: 56, mode: "CBC"})
			}
			sawCipher = true
			if next(i) == "CBC3" || next(i) == "CBC" {
				i++
			}
		case "RC4":
			out, sawCipher = append(out, algo{alg: "RC4", prim: "stream-cipher"}), true
			if next(i) == "128" || next(i) == "40" {
				i++
			}
		case "CHACHA20":
			out, sawCipher, aead = append(out, algo{alg: "ChaCha20", prim: "ae"}), true, true
			if next(i) == "POLY1305" {
				i++
			}
		case "NULL", "CAMELLIA", "CAMELLIA128", "CAMELLIA256", "ARIA", "ARIA128", "ARIA256", "SEED", "IDEA":
			sawCipher = true // a cipher outside the closed algorithm set: nothing to report
		case "SHA", "MD5", "SHA256", "SHA384":
			name := map[string]string{"SHA": "SHA-1", "MD5": "MD5", "SHA256": "SHA-256", "SHA384": "SHA-384"}[t]
			// In AEAD suites the hash only drives the key derivation; in the
			// others it is the record MAC (HMAC), which SHA-1 and MD5 still
			// are safe for, unlike signatures. The primitive lets the
			// classifier tell the two apart.
			prim := "mac"
			if aead {
				prim = "kdf"
			}
			out = append(out, algo{alg: name, prim: prim})
		}
	}
	if !sawCipher {
		return nil // not a cipher-suite name after all
	}
	// OpenSSL names with no key exchange ("AES128-SHA", "DES-CBC3-SHA") use
	// RSA key transport. TLS 1.3 names (IANA, no WITH) have none at all.
	if !iana && !sawKx {
		out = append([]algo{{alg: "RSA", prim: "pke"}}, out...)
	}
	return out
}

// groupList returns the algorithms a TLS key-exchange group list enables
// (nginx ssl_ecdh_curve, OpenSSL Groups/Curves). Hybrid post-quantum groups
// give both halves.
func groupList(v string) []algo {
	var out []algo
	for _, tok := range splitAny(v, ": ,") {
		if tok[0] == '-' || tok[0] == '!' {
			continue
		}
		tok = strings.TrimLeft(tok, "?*") // OpenSSL 3.5: "?" optional, "*" key share
		out = append(out, groupAlgos[strings.ToUpper(tok)]...)
	}
	return out
}

var (
	x25519   = algo{alg: "X25519", prim: "key-agree", bits: 255}
	p256     = algo{alg: "ECDH", prim: "key-agree", bits: 256}
	p384     = algo{alg: "ECDH", prim: "key-agree", bits: 384}
	p521     = algo{alg: "ECDH", prim: "key-agree", bits: 521}
	mlkem512 = algo{alg: "ML-KEM", prim: "kem", param: "ML-KEM-512"}
	mlkem768 = algo{alg: "ML-KEM", prim: "kem", param: "ML-KEM-768"}
	mlkem1k  = algo{alg: "ML-KEM", prim: "kem", param: "ML-KEM-1024"}
)

var groupAlgos = map[string][]algo{
	"X25519":             {x25519},
	"X25519MLKEM768":     {x25519, mlkem768},
	"SECP256R1MLKEM768":  {p256, mlkem768},
	"SECP384R1MLKEM1024": {p384, mlkem1k},
	"MLKEM512":           {mlkem512},
	"MLKEM768":           {mlkem768},
	"MLKEM1024":          {mlkem1k},
	"P-256":              {p256},
	"PRIME256V1":         {p256},
	"SECP256R1":          {p256},
	"P-384":              {p384},
	"SECP384R1":          {p384},
	"P-521":              {p521},
	"SECP521R1":          {p521},
	"FFDHE2048":          {{alg: "DH", prim: "key-agree", bits: 2048}},
	"FFDHE3072":          {{alg: "DH", prim: "key-agree", bits: 3072}},
	"FFDHE4096":          {{alg: "DH", prim: "key-agree", bits: 4096}},
	"FFDHE6144":          {{alg: "DH", prim: "key-agree", bits: 6144}},
	"FFDHE8192":          {{alg: "DH", prim: "key-agree", bits: 8192}},
}

// splitAny splits s at any of the separator bytes, dropping empty fields
// and surrounding quotes.
func splitAny(s, seps string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(seps, r) || r == '\t' })
	out := f[:0]
	for _, x := range f {
		if x = strings.Trim(x, `'"`); x != "" {
			out = append(out, x)
		}
	}
	return out
}
