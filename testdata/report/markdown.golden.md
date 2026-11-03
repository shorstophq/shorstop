## ShorStop post-quantum scan

**12 findings** · 2 critical · 5 high · 1 medium · 3 low · 1 quantum-safe

| Severity | Asset | Status | Places | What to do |
|---|---|---|---:|---|
| critical | RSA-2048 private key | QUANTUM_VULNERABLE | 1 | Treat the key as compromised: revoke and rotate it, remove it from the repository history, and keep keys in a secret manager. |
| critical | SHA-1 | BROKEN | 1 | Use SHA-256 or stronger (SHA-384, SHA-3). |
| high | RSA-2048 | QUANTUM_VULNERABLE | 2 | Migrate to ML-KEM (FIPS 203) for key exchange and encryption, and ML-DSA (FIPS 204) for signatures; for TLS, enable X25519MLKEM768. |
| high | AES-128-ECB | INSECURE_MODE | 1 | Use AES-GCM (or another authenticated mode). |
| high | TLSv1.0 | BROKEN | 1 | Allow only TLS 1.2 and 1.3. |
| high | certificate with RSA-2048 key | QUANTUM_VULNERABLE | 1 | Migrate to ML-KEM (FIPS 203) for key exchange and encryption, and ML-DSA (FIPS 204) for signatures; for TLS, enable X25519MLKEM768. |
| medium | RSA | QUANTUM_VULNERABLE | 1 | Plan a migration of signatures to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205). |
| low | pkg:npm/node-rsa (RSA) | QUANTUM_VULNERABLE | 2 | Migrate to ML-KEM (FIPS 203) for key exchange and encryption, and ML-DSA (FIPS 204) for signatures; for TLS, enable X25519MLKEM768. |
| low | pkg:npm/node-forge | UNKNOWN | 1 | Check which algorithms it is used with. |

### Findings by file

<details><summary><code>README.md</code> · 1</summary>

| Line | Asset | Status | Severity | Rule |
|---:|---|---|---|---|
| 3 | RSA-2048 | QUANTUM_VULNERABLE | high | `generic-rsa-bits` |

</details>

<details><summary><code>a.go</code> · 1</summary>

| Line | Asset | Status | Severity | Rule |
|---:|---|---|---|---|
| 10 | RSA-2048 | QUANTUM_VULNERABLE | high | `go-rsa-generate-key` |

</details>

<details><summary><code>b.js</code> · 1</summary>

| Line | Asset | Status | Severity | Rule |
|---:|---|---|---|---|
| 2 | AES-128-ECB | INSECURE_MODE | high | `generic-aes-cipher-string` |

</details>

<details><summary><code>ca.pem</code> · 3</summary>

| Line | Asset | Status | Severity | Rule |
|---:|---|---|---|---|
| 1 | SHA-1 | BROKEN | critical | `cert-signature-hash` |
| 1 | certificate with RSA-2048 key | QUANTUM_VULNERABLE | high | `cert-public-key` |
| 1 | RSA | QUANTUM_VULNERABLE | medium | `cert-signature` |

</details>

<details><summary><code>k.key</code> · 1</summary>

| Line | Asset | Status | Severity | Rule |
|---:|---|---|---|---|
| 1 | RSA-2048 private key | QUANTUM_VULNERABLE | critical | `private-key-committed` |

</details>

<details><summary><code>nginx.conf</code> · 1</summary>

| Line | Asset | Status | Severity | Rule |
|---:|---|---|---|---|
| 5 | TLSv1.0 | BROKEN | high | `tls-protocol-version` |

</details>

<details><summary><code>package-lock.json</code> · 1</summary>

| Line | Asset | Status | Severity | Rule |
|---:|---|---|---|---|
| 9 | pkg:npm/node-rsa@1.1.1 (RSA) | QUANTUM_VULNERABLE | low | `dep-npm-node-rsa` |

</details>

<details><summary><code>package.json</code> · 2</summary>

| Line | Asset | Status | Severity | Rule |
|---:|---|---|---|---|
| 4 | pkg:npm/node-rsa (RSA) | QUANTUM_VULNERABLE | low | `dep-npm-node-rsa` |
| 5 | pkg:npm/node-forge | UNKNOWN | low | `dep-npm-node-forge` |

</details>

