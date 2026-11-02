package config

import (
	"strconv"
	"strings"
)

// sshList returns the algorithms an OpenSSH algorithm list enables
// (KexAlgorithms, Ciphers, MACs, HostKeyAlgorithms, ...). Items are comma
// separated; "+" appends and "^" prepends to the default list, so their
// items are enabled; "-" removes, so its items are not. Wildcard patterns
// are skipped: they select from a list we don't have.
func sshList(v string, name func(string) []algo) []algo {
	var out []algo
	for _, tok := range strings.Split(v, ",") {
		tok = strings.Trim(strings.TrimSpace(tok), `'"`)
		if tok == "" || tok[0] == '-' || strings.ContainsAny(tok, "*?!") {
			continue
		}
		tok = strings.TrimLeft(tok, "+^")
		out = append(out, name(strings.ToLower(tok))...)
	}
	return out
}

// dhGroupBits are the sizes of the fixed SSH Diffie-Hellman groups (RFC
// 4253, RFC 8268).
var dhGroupBits = map[string]int{"1": 1024, "14": 2048, "15": 3072, "16": 4096, "17": 6144, "18": 8192}

var sha1Hash = algo{alg: "SHA-1", prim: "hash"}

// sshKex names the algorithms of an SSH key-exchange method.
func sshKex(n string) []algo {
	n = strings.TrimSuffix(strings.TrimSuffix(n, "@libssh.org"), "@openssh.com")
	switch n {
	case "curve25519-sha256":
		return []algo{x25519}
	case "sntrup761x25519-sha512":
		return []algo{{alg: "sntrup761", prim: "kem"}, x25519}
	case "mlkem768x25519-sha256":
		return []algo{mlkem768, x25519}
	case "mlkem768nistp256-sha256":
		return []algo{mlkem768, p256}
	case "mlkem1024nistp384-sha384":
		return []algo{mlkem1k, p384}
	}
	if rest, ok := strings.CutPrefix(n, "ecdh-sha2-nistp"); ok {
		bits, _ := strconv.Atoi(rest)
		return []algo{{alg: "ECDH", prim: "key-agree", bits: bits}}
	}
	if rest, ok := strings.CutPrefix(n, "diffie-hellman-group"); ok {
		dh := algo{alg: "DH", prim: "key-agree"}
		if num, _, ok := strings.Cut(rest, "-"); ok {
			dh.bits = dhGroupBits[num] // 0 for "exchange": the server picks the size
		}
		if strings.HasSuffix(n, "-sha1") {
			return []algo{dh, sha1Hash}
		}
		return []algo{dh}
	}
	return nil // ext-info-c, kex-strict-*, gss-*: not algorithms
}

// sshCipher names the algorithm of an SSH cipher. Blowfish and CAST-128
// are outside the closed algorithm set and give nothing.
func sshCipher(n string) []algo {
	n = strings.TrimSuffix(n, "@openssh.com")
	switch n {
	case "3des-cbc":
		return []algo{{alg: "3DES", prim: "block-cipher", bits: 168, mode: "CBC"}}
	case "chacha20-poly1305":
		return []algo{{alg: "ChaCha20", prim: "ae"}}
	case "arcfour", "arcfour128", "arcfour256":
		return []algo{{alg: "RC4", prim: "stream-cipher"}}
	case "rijndael-cbc@lysator.liu.se":
		return []algo{{alg: "AES", prim: "block-cipher", bits: 256, mode: "CBC"}}
	}
	// aes128-ctr, aes256-cbc, aes256-gcm (after the suffix is trimmed)
	if rest, ok := strings.CutPrefix(n, "aes"); ok {
		size, mode, ok := strings.Cut(rest, "-")
		bits, err := strconv.Atoi(size)
		if ok && err == nil && (mode == "ctr" || mode == "cbc" || mode == "gcm") {
			return []algo{{alg: "AES", prim: "block-cipher", bits: bits, mode: strings.ToUpper(mode)}}
		}
	}
	return nil
}

// sshMAC names the hash of an SSH MAC. UMAC is not a hash and gives nothing.
func sshMAC(n string) []algo {
	n = strings.TrimSuffix(strings.TrimSuffix(n, "@openssh.com"), "-etm")
	switch n {
	case "hmac-sha1", "hmac-sha1-96":
		return []algo{{alg: "SHA-1", prim: "mac"}}
	case "hmac-md5", "hmac-md5-96":
		return []algo{{alg: "MD5", prim: "mac"}}
	case "hmac-sha2-256":
		return []algo{{alg: "SHA-256", prim: "mac"}}
	case "hmac-sha2-512":
		return []algo{{alg: "SHA-512", prim: "mac"}}
	}
	return nil
}

// sshKeyAlg names the algorithms of an SSH public-key signature algorithm
// (HostKeyAlgorithms, PubkeyAcceptedAlgorithms, ...). Certificate and
// security-key variants are reduced to the key they use.
func sshKeyAlg(n string) []algo {
	n = strings.TrimSuffix(n, "-cert-v01@openssh.com")
	n = strings.TrimSuffix(n, "@openssh.com")
	n = strings.TrimPrefix(strings.TrimPrefix(n, "webauthn-"), "sk-")
	switch n {
	case "ssh-rsa":
		// The original ssh-rsa signature hashes with SHA-1.
		return []algo{{alg: "RSA", prim: "signature"}, sha1Hash}
	case "rsa-sha2-256":
		return []algo{{alg: "RSA", prim: "signature"}, {alg: "SHA-256", prim: "hash"}}
	case "rsa-sha2-512":
		return []algo{{alg: "RSA", prim: "signature"}, {alg: "SHA-512", prim: "hash"}}
	case "ssh-dss":
		return []algo{{alg: "DSA", prim: "signature"}, sha1Hash}
	case "ssh-ed25519":
		return []algo{{alg: "EdDSA", prim: "signature", bits: 255}}
	}
	if rest, ok := strings.CutPrefix(n, "ecdsa-sha2-nistp"); ok {
		bits, _ := strconv.Atoi(rest)
		return []algo{{alg: "ECDSA", prim: "signature", bits: bits}}
	}
	return nil
}
