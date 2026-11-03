// Package config reads cryptographic settings from server configuration:
// TLS protocol versions, cipher strings and key-exchange groups (nginx,
// Apache, HAProxy, PostgreSQL, stunnel, openssl.cnf), OpenSSH algorithm
// lists, openssl.cnf key defaults, and certificates and keys stored base64
// in Kubernetes Secrets.
//
// Unlike the regex detector it understands each directive: "!3DES" in a
// cipher string disables 3DES, so it is not reported. Comments are skipped,
// so findings describe the configuration in effect.
package config

import (
	"bytes"
	"context"
	"path"
	"strings"

	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/rules"
)

// Name is the detector's name.
const Name = "config"

// Built-in rule IDs. Like rule-pack IDs, they appear in suppressions and
// baselines, so they must never be renamed or reused. Kubernetes Secret
// findings keep the cert detector's IDs (private-key-committed, ...).
const (
	RuleTLSProtocol = "tls-protocol-version" // an enabled TLS/SSL version
	RuleTLSCipher   = "tls-cipher"           // an algorithm enabled by a cipher string
	RuleTLSGroup    = "tls-group"            // an enabled key-exchange group
	RuleSSHKex      = "ssh-kex"
	RuleSSHCipher   = "ssh-cipher"
	RuleSSHMAC      = "ssh-mac"
	RuleSSHKeyAlg   = "ssh-key-algorithm"
	RuleOpenSSLBits = "openssl-default-bits" // openssl.cnf default_bits: RSA key size
	RuleOpenSSLMD   = "openssl-default-md"   // openssl.cnf default_md: signing hash
)

// RuleDescriptions describes each built-in rule, for reports that list
// rules (SARIF). Every Rule* constant must have an entry.
var RuleDescriptions = map[string]string{
	RuleTLSProtocol: "A TLS or SSL version enabled in server configuration.",
	RuleTLSCipher:   "An algorithm enabled by a TLS cipher string (nginx, Apache, HAProxy, PostgreSQL, stunnel, openssl.cnf).",
	RuleTLSGroup:    "A TLS key-exchange group (curve or finite-field group) enabled in server configuration.",
	RuleSSHKex:      "An SSH key-exchange method enabled in OpenSSH configuration.",
	RuleSSHCipher:   "An SSH cipher enabled in OpenSSH configuration.",
	RuleSSHMAC:      "An SSH MAC enabled in OpenSSH configuration.",
	RuleSSHKeyAlg:   "An SSH host-key or public-key signature algorithm enabled in OpenSSH configuration.",
	RuleOpenSSLBits: "The RSA key size openssl.cnf gives new keys by default (default_bits).",
	RuleOpenSSLMD:   "The hash openssl.cnf signs certificates and requests with by default (default_md).",
}

const (
	maxStmtLines    = 20 // longest multi-line statement followed (nginx ";", "\" continuation)
	directiveKeyMax = 64 // longest directive name read
)

// kind says how a directive's value is read.
type kind int

const (
	kProtocols   kind = iota + 1 // list of versions to enable/disable
	kMinProtocol                 // a minimum version
	kCiphers                     // OpenSSL cipher string
	kGroups                      // key-exchange groups
	kSSHKex
	kSSHCipher
	kSSHMAC
	kSSHKeyAlg
	kDefaultBits
	kDefaultMD
	kOpenSSLConfCmd // Apache SSLOpenSSLConfCmd <command> <value>
)

// tlsDirectives are recognised in every supported file, by lower-case name.
// Names are distinctive enough not to clash between the formats.
var tlsDirectives = map[string]kind{
	// nginx (and its proxy/grpc/uwsgi upstream variants); PostgreSQL
	// uses ssl_ciphers and ssl_ecdh_curve too.
	"ssl_protocols": kProtocols, "proxy_ssl_protocols": kProtocols, "grpc_ssl_protocols": kProtocols, "uwsgi_ssl_protocols": kProtocols,
	"ssl_ciphers": kCiphers, "proxy_ssl_ciphers": kCiphers, "grpc_ssl_ciphers": kCiphers, "uwsgi_ssl_ciphers": kCiphers,
	"ssl_ecdh_curve": kGroups,
	// Apache mod_ssl
	"sslprotocol": kProtocols, "sslproxyprotocol": kProtocols,
	"sslciphersuite": kCiphers, "sslproxyciphersuite": kCiphers,
	"sslopensslconfcmd": kOpenSSLConfCmd,
	// HAProxy
	"ssl-default-bind-ciphers": kCiphers, "ssl-default-server-ciphers": kCiphers,
	"ssl-default-bind-ciphersuites": kCiphers, "ssl-default-server-ciphersuites": kCiphers,
	"ssl-min-ver": kMinProtocol,
	// PostgreSQL
	"ssl_min_protocol_version": kMinProtocol,
	// openssl.cnf (system_default_sect and friends), stunnel
	"cipherstring": kCiphers, "ciphersuites": kCiphers, "minprotocol": kMinProtocol,
	"groups": kGroups, "curves": kGroups,
	"default_bits": kDefaultBits, "default_md": kDefaultMD,
}

// sshDirectives are recognised only in OpenSSH files: "Ciphers" means
// something else in stunnel and openssl.cnf.
var sshDirectives = map[string]kind{
	"kexalgorithms":     kSSHKex,
	"ciphers":           kSSHCipher,
	"macs":              kSSHMAC,
	"hostkeyalgorithms": kSSHKeyAlg, "pubkeyacceptedalgorithms": kSSHKeyAlg, "pubkeyacceptedkeytypes": kSSHKeyAlg,
	"casignaturealgorithms": kSSHKeyAlg, "hostbasedacceptedalgorithms": kSSHKeyAlg, "hostbasedacceptedkeytypes": kSSHKeyAlg,
}

// Detector is the configuration detector. It has no state, so it is safe
// for concurrent use.
type Detector struct{}

// New returns the detector.
func New() *Detector { return &Detector{} }

// Name implements detect.Detector.
func (*Detector) Name() string { return Name }

// Supports implements detect.Detector: configuration files by name, and
// YAML for Kubernetes Secrets.
func (*Detector) Supports(p string, binary bool) bool {
	return !binary && (isConfigFile(p) || isYAML(p))
}

func isYAML(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

// isConfigFile: *.conf, *.cnf, *.cfg, OpenSSH config files, and nginx's
// sites-available/sites-enabled, whose files usually have no extension.
func isConfigFile(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".conf", ".cnf", ".cfg":
		return true
	}
	if isSSHFile(p) {
		return true
	}
	switch path.Base(path.Dir(p)) {
	case "sites-available", "sites-enabled":
		return true
	}
	return false
}

// isSSHFile: sshd_config, ssh_config, and the files they include from
// sshd_config.d and ssh_config.d.
func isSSHFile(p string) bool {
	base := path.Base(p)
	if strings.HasPrefix(base, "sshd_config") || strings.HasPrefix(base, "ssh_config") {
		return true
	}
	dir := path.Base(path.Dir(p))
	return dir == "sshd_config.d" || dir == "ssh_config.d"
}

// Detect implements detect.Detector.
func (*Detector) Detect(ctx context.Context, f detect.File) ([]detect.Finding, error) {
	if isYAML(f.Path) {
		return k8sSecrets(ctx, f.Content)
	}
	ssh := isSSHFile(f.Path)
	var out []detect.Finding
	for _, s := range statements(f.Content) {
		k, ok := tlsDirectives[s.key]
		if !ok && ssh {
			k, ok = sshDirectives[s.key]
		}
		if !ok && !ssh && s.key == "ciphers" {
			k, ok = kCiphers, true // stunnel and others: an OpenSSL cipher string
		}
		if !ok {
			continue
		}
		for _, fd := range interpret(k, s.value) {
			fd.Line = s.line
			fd.Snippet = detect.SnippetOf(s.first)
			fd.Confidence = rules.ConfidenceHigh
			out = append(out, fd)
		}
	}
	// Many suites on one line share algorithms (ECDH, SHA-1 ...): list each once.
	return detect.Dedupe(out), ctx.Err()
}

// interpret turns one directive's value into findings, without line or
// snippet.
func interpret(k kind, v string) []detect.Finding {
	switch k {
	case kProtocols:
		return protocols(protocolList(v))
	case kMinProtocol:
		return protocols(minProtocol(v))
	case kCiphers:
		// Apache: "SSLCipherSuite TLSv1.3 TLS_AES_..." names the protocol first.
		if first, rest, ok := strings.Cut(strings.TrimSpace(v), " "); ok {
			if _, isVer := parseVersion(first); isVer || strings.EqualFold(first, "SSL") || strings.EqualFold(first, "TLS") {
				v = rest
			}
		}
		return algos(RuleTLSCipher, cipherString(v))
	case kGroups:
		return algos(RuleTLSGroup, groupList(v))
	case kSSHKex:
		return algos(RuleSSHKex, sshList(v, sshKex))
	case kSSHCipher:
		return algos(RuleSSHCipher, sshList(v, sshCipher))
	case kSSHMAC:
		return algos(RuleSSHMAC, sshList(v, sshMAC))
	case kSSHKeyAlg:
		return algos(RuleSSHKeyAlg, sshList(v, sshKeyAlg))
	case kDefaultBits:
		// openssl req generates an RSA key of this size unless told otherwise.
		bits := 0
		for _, c := range strings.TrimSpace(v) {
			if c < '0' || c > '9' {
				return nil
			}
			bits = bits*10 + int(c-'0')
			if bits > 1<<16 {
				return nil
			}
		}
		if bits == 0 {
			return nil
		}
		return algos(RuleOpenSSLBits, []algo{{alg: "RSA", bits: bits}})
	case kDefaultMD:
		if a, ok := mdNames[strings.ToLower(strings.TrimSpace(v))]; ok {
			return algos(RuleOpenSSLMD, []algo{a})
		}
	case kOpenSSLConfCmd:
		cmd, rest, _ := strings.Cut(strings.TrimSpace(v), " ")
		switch strings.ToLower(cmd) {
		case "groups", "curves":
			return interpret(kGroups, rest)
		case "cipherstring", "ciphersuites":
			return interpret(kCiphers, rest)
		case "minprotocol":
			return interpret(kMinProtocol, rest)
		}
	}
	return nil
}

// mdNames are the openssl.cnf default_md values that name an algorithm.
var mdNames = map[string]algo{
	"md5":      {alg: "MD5", prim: "hash"},
	"sha1":     {alg: "SHA-1", prim: "hash"},
	"sha224":   {alg: "SHA-224", prim: "hash"},
	"sha256":   {alg: "SHA-256", prim: "hash"},
	"sha384":   {alg: "SHA-384", prim: "hash"},
	"sha512":   {alg: "SHA-512", prim: "hash"},
	"sha3-256": {alg: "SHA-3", prim: "hash"},
	"sha3-384": {alg: "SHA-3", prim: "hash"},
	"sha3-512": {alg: "SHA-3", prim: "hash"},
}

func protocols(vs []string) []detect.Finding {
	out := make([]detect.Finding, 0, len(vs))
	for _, v := range vs {
		out = append(out, detect.Finding{RuleID: RuleTLSProtocol, AssetType: detect.AssetProtocol, Protocol: v})
	}
	return out
}

func algos(rule string, as []algo) []detect.Finding {
	out := make([]detect.Finding, 0, len(as))
	for _, a := range as {
		out = append(out, detect.Finding{
			RuleID: rule, Algorithm: a.alg, Primitive: a.prim, KeySize: a.bits, Mode: a.mode, ParameterSet: a.param,
		})
	}
	return out
}

// stmt is one configuration directive.
type stmt struct {
	key   string // lower case
	value string // without the trailing ";" or the "=" separator
	line  int    // where the directive starts
	first []byte // its first physical line, for the snippet
}

// statements splits content into directives. It handles the shared shape of
// the supported formats: "key value", "key = value", "key value;" (nginx,
// which may continue over several lines until the ";"), and "\" line
// continuation (Apache, openssl.cnf). Comments ("#" at the start of a line
// or after whitespace, outside quotes) are removed. [section] headers and
// nginx "{" / "}" are not directives and are skipped.
func statements(content []byte) []stmt {
	lines := bytes.Split(content, []byte("\n"))
	var out []stmt
	for i := 0; i < len(lines); i++ {
		first := bytes.TrimRight(lines[i], "\r")
		text := stripComment(string(first))
		start := i
		// "\" continuation.
		for strings.HasSuffix(text, `\`) && i+1 < len(lines) && i-start < maxStmtLines {
			i++
			text = text[:len(text)-1] + " " + stripComment(string(bytes.TrimRight(lines[i], "\r")))
		}
		key, value, eq, ok := splitDirective(text)
		if !ok {
			continue
		}
		// nginx: a directive without "=" runs to its ";", maybe lines later.
		// Only nginx names contain "ssl_" without using "=" (PostgreSQL's
		// ssl_ciphers has one). Lines are joined only if a ";" turns up.
		if !eq && strings.Contains(key, "ssl_") && !strings.Contains(value, ";") {
			acc := value
			for j := i + 1; j < len(lines) && j-start < maxStmtLines; j++ {
				more := stripComment(string(bytes.TrimRight(lines[j], "\r")))
				acc += " " + more
				if strings.Contains(more, ";") {
					value, i = acc, j
					break
				}
			}
		}
		if semi := strings.IndexByte(value, ';'); semi >= 0 && !eq {
			value = value[:semi]
		}
		out = append(out, stmt{key: key, value: strings.TrimSpace(value), line: start + 1, first: first})
	}
	return out
}

// splitDirective splits "key value" or "key = value". The key is letters,
// digits, "_", "-" and "."; eq reports whether "=" separated it.
func splitDirective(line string) (key, value string, eq, ok bool) {
	line = strings.TrimSpace(line)
	n := 0
	for n < len(line) && n < directiveKeyMax && isKeyByte(line[n]) {
		n++
	}
	if n == 0 {
		return "", "", false, false
	}
	key, rest := strings.ToLower(line[:n]), strings.TrimSpace(line[n:])
	if r, found := strings.CutPrefix(rest, "="); found {
		rest, eq = strings.TrimSpace(r), true
	}
	return key, rest, eq, true
}

func isKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
}

// stripComment removes a "#" comment: one at the start of the line or after
// whitespace, outside single or double quotes. "#" inside a value
// ("abc#def") is kept.
func stripComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}
