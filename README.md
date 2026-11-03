# ShorStop: post-quantum cryptography scanner

[![ci](https://github.com/shorstophq/shorstop/actions/workflows/ci.yml/badge.svg)](https://github.com/shorstophq/shorstop/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

ShorStop finds the cryptography in your code, certificates, server configuration and
dependencies that a quantum computer will break (RSA, elliptic curves, Diffie-Hellman),
along with the crypto that is already broken today (MD5, SHA-1, DES, RC4, short keys, old TLS).
It reports what it finds as a **CycloneDX 1.6 CBOM** (Cryptographic Bill of Materials),
**SARIF** for GitHub code scanning, Markdown, or a terminal table. Each finding comes with a
rating and the post-quantum replacement to migrate to (ML-KEM, ML-DSA, SLH-DSA).

The name comes from Shor's algorithm, the quantum algorithm that breaks RSA and ECC.

> **Status: pre-release.** The scanner, rules and output formats work and are tested, but
> there are no binary releases, Docker image or GitHub Action yet. Expect rule IDs and
> output details to change before `v1.0`.

## Quick start

ShorStop needs Go 1.27 or newer to install from source:

```sh
go install github.com/shorstophq/shorstop/cmd/shorstop@latest
shorstop scan .
```

Output from a small sample project:

```text
CRITICAL · 2
  MD5 · BROKEN · 1 place
    MD5 has practical collision attacks: signatures and integrity checks that rely on it can be forged.
    → Use SHA-256 or stronger (SHA-384, SHA-3).
      app/auth.py:5   py-hashlib-md5
  RSA-1024 · BROKEN · 1 place
    1024-bit RSA is below the 2048-bit minimum (NIST SP 800-131A) and within reach of classical attacks.
    → Migrate to ML-KEM (FIPS 203) for key exchange and encryption, and ML-DSA (FIPS 204) for signatures; for TLS, enable X25519MLKEM768.
      app/keys.go:10   go-rsa-generate-key

HIGH · 5
  RSA · QUANTUM_VULNERABLE · 2 places
    ...
  TLSv1.0 · BROKEN · 1 place
    TLSv1.0 is deprecated by RFC 8996 and rejected by modern clients and PCI DSS.
    → Allow only TLS 1.2 and 1.3.
      deploy/nginx.conf:2   tls-protocol-version
  X25519 · QUANTUM_VULNERABLE · 1 place
    ...

LOW · 1
  pkg:pypi/pycryptodome · UNKNOWN · 1 place
    ...

Scanned 4 files · 12 findings · 2 critical · 5 high · 1 low · 2 quantum-safe (skipped: ...) · 0 warnings
```

In this sample, `ssl_ciphers HIGH:!aNULL:!3DES` is correctly **not** reported, because `!3DES`
disables 3DES. The `crypto/mlkem` import and the hybrid `X25519MLKEM768` TLS group count as
**quantum-safe**, which shows migration progress rather than problems.

## What it finds

| Detector | Looks at | Examples |
|---|---|---|
| **Go AST** | `.go` files, parsed | `crypto/rsa`, `crypto/des`, `rsa.GenerateKey(r, 1024)` (key size read from the call), `crypto/mlkem` |
| **Certificates and keys** | PEM in any text file, DER, PKCS#12, OpenSSH keys | each certificate's key, signer and signature hash; **committed private keys**, even encrypted ones; CSRs, DH parameters |
| **Configuration** | nginx, Apache, HAProxy, PostgreSQL, stunnel, `openssl.cnf`, `sshd_config`, Kubernetes Secrets | enabled TLS versions, cipher suites and groups (removals like `!3DES` are understood), SSH key exchange, ciphers, MACs and host keys, base64 keys in Secrets |
| **Dependencies** | 19 manifest and lockfile formats across npm, PyPI, Maven/Gradle, Go, Composer, Cargo, RubyGems and NuGet | `node-forge`, `pycryptodome`, Bouncy Castle, `phpseclib`; post-quantum libraries such as `liboqs-python` and `ml-kem` |
| **Patterns** | Python, Java/Kotlin, JavaScript/TypeScript, PHP, C#, Ruby, C/C++, Rust, plus any text file | `Cipher.getInstance("AES")` (Java defaults to ECB), `hashlib.md5`, `createCipheriv('aes-128-ecb')`, `openssl genrsa 1024`, `ssh-keygen -t rsa` |

`shorstop rules list` shows all 225 rules with their IDs and descriptions.

## How findings are rated

| Status | Meaning | Examples |
|---|---|---|
| `BROKEN` | Insecure today, quantum computer or not | MD5, SHA-1 signatures, DES, 3DES, RC4, RSA/DH under 2048 bits, SSLv3, TLS 1.0/1.1 |
| `INSECURE_MODE` | A sound cipher used in a mode that leaks | AES-ECB |
| `QUANTUM_VULNERABLE` | Secure today, broken by Shor's algorithm | RSA, ECDSA, ECDH, Ed25519, X25519, DH, DSA |
| `WEAKENED` | Grover's algorithm halves its strength | AES-128 |
| `ACCEPTABLE` | Fine now and after quantum computers | AES-256, SHA-256/384/512, SHA-3, ChaCha20, HMAC-SHA-1 |
| `QUANTUM_SAFE` | Post-quantum cryptography | ML-KEM, ML-DSA, SLH-DSA |
| `UNKNOWN` | Not enough information to rate it | a crypto toolkit dependency, AES of unknown key size |

**Severity** runs `critical` (broken crypto, committed private keys) → `high` (quantum-vulnerable
key exchange, insecure modes, TLS 1.0/1.1) → `medium` (quantum-vulnerable signatures,
AES-128) → `low` (dependency hints) → `info` (nothing to do).

## Output formats

```sh
shorstop scan .                                         # terminal table (the default)
shorstop scan . --format json   --output cbom.json      # CycloneDX 1.6 CBOM, every finding
shorstop scan . --format sarif  --output shorstop.sarif # SARIF 2.1.0 for code scanning
shorstop scan . --format markdown > report.md           # for a PR comment or an audit
```

The CBOM is validated against the official CycloneDX 1.6 JSON schema in ShorStop's tests, and
SARIF against the OASIS SARIF 2.1.0 schema. Colour is used only on a terminal, and never when
`NO_COLOR` is set.

## In CI

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage or scanner error.

```sh
shorstop scan . --fail-on high
```

### GitHub code scanning

Until the GitHub Action is published, this workflow installs ShorStop with Go and uploads
SARIF, so findings show up in the **Security** tab and inline on pull requests:

```yaml
name: shorstop
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v6
        with:
          go-version: stable
      - run: go install github.com/shorstophq/shorstop/cmd/shorstop@latest
      - run: shorstop scan . --format sarif --output shorstop.sarif
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: shorstop.sarif
```

Code scanning is free for public repositories. Private repositories need GitHub Code
Security.

### Adopting on an existing codebase: baselines

Record today's findings once, commit the file, and from then on only **new** findings are
reported or fail the build:

```sh
shorstop scan . --format sarif --output .shorstop/baseline.sarif
shorstop scan . --baseline .shorstop/baseline.sarif --fail-on high
```

A previous SARIF or CBOM output both work as a baseline. Findings are matched without their
line number, so moving code doesn't make old findings look new.

## Suppressing a finding

Put a comment on the line, or on its own line just above it, in whatever comment style the
file uses:

```python
key = RSA.generate(2048)  # shorstop:ignore py-pycryptodome-rsa-generate reason="partner API until 2027"
```

```nginx
# shorstop:ignore tls-protocol-version reason="legacy clients, removed in Q3"
ssl_protocols TLSv1 TLSv1.2 TLSv1.3;
```

Rule IDs are comma-separated, and a marker without IDs covers every finding on the line.
Suppressed findings leave the table, SARIF, Markdown and `--fail-on`, and are counted in the
summary. The CBOM still lists them, because the crypto is still there.

## Configuration: `.shorstop.yaml`

At the root of the scanned directory, or wherever `--config` points:

```yaml
version: 1
exclude: [third_party/, "*.min.js"]
fail-on: high
baseline: .shorstop/baseline.sarif
max-file-size: 4MB
rules: [.shorstop/rules.yaml]    # your own rules, in the rule-pack format
disable: [generic-rsa-bits]      # turn a rule off for the whole repository
```

Flags given on the command line override the file. Unknown keys and unknown rule IDs are
errors, so a typo can't silently do nothing. ShorStop never scans its own config, rule,
baseline or output files.

### Custom rules

Rules use the same format as the [built-in pack](internal/rules/rules.yaml). Each pattern
rule must list example lines it matches, and those examples are checked every time the rules
load:

```yaml
version: 1
rules:
  - id: acme-legacy-cipher
    description: ACME's in-house wrapper around a 64-bit block cipher.
    detector: regex
    languages: [python]
    algorithm: 3DES
    primitive: block-cipher
    match:
      keywords: [legacy_cipher]
      pattern: 'legacy_cipher\('
      examples: ["legacy_cipher('blowfish')"]
```

Check a rule file without scanning anything: `shorstop rules list --rules .shorstop/rules.yaml`.

## Known limitations

- **Regex rules match comments too.** Commented-out crypto is still worth seeing in an
  inventory. Use `shorstop:ignore` for the exceptions.
- **No type checking in Go.** A local variable that shadows a package name
  (`rsa := x; rsa.GenerateKey(...)`) is reported as a crypto call.
- **OpenSSL cipher sets that depend on the build** (`HIGH`, `MEDIUM`, `DEFAULT`) aren't
  expanded, so `MEDIUM` on an old OpenSSL that still includes 3DES isn't caught.
- **Hybrid key exchange:** in `X25519MLKEM768`, the X25519 half is reported as
  quantum-vulnerable even though the hybrid protects it.
- **Lockfiles over 2 MB** are skipped by default. Raise the limit with `--max-file-size`.
- **Maven `${property}` versions and Gradle version catalogs** aren't resolved.

## How it's built

ShorStop is a single Go binary with four runtime dependencies (`go.yaml.in/yaml/v3`,
`golang.org/x/crypto`, `spf13/cobra`, `spf13/pflag`). Every design decision, tradeoff and data
structure is recorded function by function in [`docs/decisions.md`](docs/decisions.md).

```sh
make test    # go vet + go test -race
make lint    # golangci-lint
make build   # bin/shorstop
```

## Security

To report a vulnerability in ShorStop itself, use GitHub's
[private vulnerability reporting](https://github.com/shorstophq/shorstop/security/advisories/new)
rather than a public issue.

## License

[Apache 2.0](LICENSE)
