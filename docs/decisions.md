# ShorStop — Decisions per Method

Every function and method, with the decisions behind it, the tradeoffs, and the data structures it uses.
Organised by file. When a function changes, update its entry here in the same change.

Entry format: **What it does** · **Decisions & tradeoffs** · **Data structures**

**How a scan flows** (read this first; the entries below refer to it):

```
walk (1 goroutine) ──jobs chan string──► workers (N goroutines) ──results chan fileResult──► collector (Scan's own goroutine)
 applies ignore rules                     open, size check, binary sniff,                     owns the Result; sorts at the end
 sends root-relative paths                run detectors                                       
```

Each piece of state has exactly one owning goroutine, so the crawler uses **no mutexes and no atomics**. Goroutines only share data through channels.

---

## `internal/detect/detect.go`

### `type Detector interface { Name; Supports(path, binary); Detect(ctx, File) }`
- **What it does:** the contract every detector (regex, Go AST, certs, deps, config — Phase 2) implements.
- **Decisions & tradeoffs:**
  - **`Supports(path string, binary bool)` (plan had `Supports(path)`).** The crawler reads the first 8000 bytes, decides "binary or not", then asks each detector. This lets the cert detector accept binary `.der` files, while every other binary file (images, archives) gets skipped *without being read in full*. Cost: `Supports` can't look at content, only name and binary-ness. That's enough for every detector in the plan.
  - **`Detect(ctx, File) ([]Finding, error)` (plan had `Detect(ctx, path) []Finding`).**
    - Takes the file *content*, not a path. The crawler reads each file **once** and every detector shares that buffer. With the plan's signature, five detectors would open and read the same file five times.
    - Returns an `error`. A Go file that fails to parse should be reported as a warning, not silently produce zero findings. Findings returned alongside an error are kept, so partial results aren't lost.
  - **Must be safe for concurrent use.** One detector value is shared by all workers. The alternative, one detector instance per worker, would multiply compiled regexes and rule tables by N for no gain, since rules are read-only after startup.
  - **Must not modify `f.Content`.** The same slice goes to every detector for that file. Copying it per detector would be safer but would double memory and CPU for every file; a documented rule is the cheaper guard.

### `type File struct { Path; Content; Binary }`
- **Data structures:**
  - `Path string`: slash-separated, relative to the scan root. It's the same on Windows and Unix, so CBOM and SARIF output and baselines match across machines.
  - `Content []byte`: `[]byte`, not `string`. `go/parser`, `x509.ParseCertificate` and `regexp` all accept bytes directly. Converting to `string` would copy the whole file.
  - `Binary bool`: computed once by the crawler, so detectors don't each re-scan for NUL bytes.

### `type Finding struct`
- **What it does:** one piece of crypto found. Fields as in the plan.
- **Decisions & tradeoffs:** `File` and `Detector` are **filled in by the crawler**, not by detectors. The crawler already knows both, so a detector can't get them wrong or forget them. Detector authors write less code.
- **Data structures:** a flat struct of strings and ints. It's cheap to copy, sorts easily, and maps 1:1 to CBOM occurrences and SARIF results later.

---

## `internal/detect/snippet.go`

### `const MaxSnippet = 120` / `func Snippet(content, n) string`
- **What it does:** returns line *n* of the file, with whitespace trimmed and cut to 120 characters, for `Finding.Snippet`. It lives in `detect`, not in one detector, because every line-based detector (goast now, regex next) needs exactly this.
- **Counts runes, not bytes**, and cuts on a rune boundary. A byte cut would split a multi-byte character and put invalid UTF-8 into JSON/SARIF output. Invalid bytes already in the source are replaced with U+FFFD for the same reason.
- When cut, the snippet keeps 119 runes and adds `…`, so its total length stays exactly 120 and readers can see it was truncated.
- `TrimSpace` also removes the `\r` of CRLF files, so Windows line endings don't leak into reports.
- *Tradeoff:* it scans from the start of the file for every finding, which is O(file size) per call. That's fine for goast, which has only a handful of findings per file.

### `func SnippetOf(line) string` (added with the regex detector)
The trimming and truncation half of `Snippet`, for a caller that already has the line. The regex detector walks lines itself, so going through `Snippet` would rescan the file from the top for every finding, which is O(n·findings) on a crypto-dense file. `Snippet` now calls `SnippetOf`, so there's one implementation of the truncation rules.

---

## `internal/detect/goast/goast.go`

### `type pkgRules` / `type Detector` / `func New(rs) *Detector`
- **Data structure:** `map[importPath]*pkgRules`, where each entry holds `onImport []*Rule` and `calls map[funcName][]*Rule`. A file's imports and each call expression take one map lookup, never a scan over all rules.
- Slices of rules, not single rules: two rules may share an import and call, and both must fire.
- **Read-only after `New`**, so all workers share it with no locks, which is what `detect.Detector` requires.
- `New` skips rules for other detectors instead of returning an error. It's always given `pack.ForDetector("goast")`, and skipping is the safer failure: a regex rule with an empty `Import` would otherwise be indexed under `""`.

### `func (*Detector) Supports(path, binary) bool`
- `.go` files that aren't binary. **`_test.go` files are included:** crypto used in tests is still crypto in the codebase, and leaving them out would understate the inventory. *Open:* the reporters may want a "test file" flag later to lower their severity.
- Suffix only, no build-tag check: a file for another OS or architecture still ships crypto on that platform.

### `func (d *Detector) Detect(ctx, f) ([]Finding, error)`
- **Two passes, as the plan says.** Pass 1 parses with `parser.ImportsOnly`, so the parser stops after the import block. That alone serves every import rule. Pass 2, a full parse, runs only if a matched import has call rules (today only `crypto/rsa`, `crypto/des` and `crypto/ecdh`). On Go's standard library source (10,114 files) a scan takes about 1 s at 8 workers.
- **`parser.SkipObjectResolution`** in both passes: we never use `ast.Object` (it's deprecated), and skipping it makes parsing faster.
- **The filename passed to the parser is empty.** The crawler's `FileError` already adds the path, so parse errors read `13:14: expected ')'` rather than repeating the path.
- **Partial parses:** `go/parser` returns a partial AST along with the error. We keep the findings from it **and** return the error, which the scan reports as a warning. *Options:* (a) drop the file silently, which would miss real crypto; (b) findings only, which would hide that the file wasn't fully read; (c) both. **Chose (c):** a security scanner shouldn't silently say "nothing here" about a file it couldn't read. *Cost:* deliberately broken test files produce warnings (4 in Go's own source).
- **Import matching** is an exact lookup on the unquoted path. Import findings go on the import line, so every file that imports `crypto/rsa` is one CBOM occurrence.
- **Call matching:** `pkg.Func(...)` is resolved through a `map[localName]*pkgRules` built from the imports. Bare `Func(...)` is matched against a `[]*pkgRules` of dot imports. A blank import (`_`) adds no call matches, since a blank import can't be called.
- **Only call expressions count.** `f := rsa.GenerateKey` isn't reported as a call, though the file's import finding still covers the package. Key-size arguments only exist on calls.
- **Known limitation, no type checking:** a local variable that shadows the package name (`rsa := x; rsa.GenerateKey(...)`) would be reported as a call. Getting this right needs `go/types` and the imported packages, which are slow and often unavailable (no `go mod download` in CI scanners). Shadowing an imported crypto package name is rare, and `// shorstop:ignore` (Phase 5) handles the leftovers.
- `ctx` is checked between the passes, so a cancelled scan doesn't start a full parse. Pass 1 findings are still returned with the error, consistent with the interface contract.
- Every finding is high confidence (the rule default for goast): the code was parsed, not pattern-matched.

### `func localName(imp, importPath) string`
The alias if there is one, otherwise `path.Base(importPath)`. That's correct for every path the rules use (std and `golang.org/x/crypto/*`). It would be wrong for `…/v2`-style paths or packages whose name differs from their directory. Getting it right in general means reading the imported package, which needs the same type-checking setup ruled out above.

### `func intLiteral(e) int`
- Reads `2048`, `0x800` and `2_048` (`strconv.ParseInt` with base 0 follows Go's literal syntax). It returns 0 (unknown) for constants, variables, expressions, non-positive values, and anything over 32 bits.
- *Tradeoff:* `const bits = 3072; rsa.GenerateKey(r, bits)` gives an unknown size. Following file-local constants is possible, but this is the "literals" scope the plan sets; the unknown size is still reported, just without a size.
- Key-size argument index beyond `len(call.Args)` (code that doesn't compile) also gives 0 rather than a panic. `calls.go` has a fixture for it.

### `func finding(r, line, bits, content) Finding`
Copies the rule's fields into a `Finding`. A size read from the code wins over the rule's fixed `key_size` (the rule schema forbids setting both, so this is only the fallback order). `File` and `Detector` are left empty; the crawler fills them in.

### Tests: `testdata/fixtures/go/*.go` + `*.go.golden`
- **Golden files**, as the plan requires. Each fixture is checked against its `.golden` file, generated with `go test ./internal/detect/goast -update` and reviewed by hand. The format is **tab-separated text, one finding per line** (line, rule, algorithm, primitive, bits, confidence, snippet), plus the error. Chosen over JSON because a rule change then shows up as a one-line diff a reviewer can read.
- Fixtures run against the **built-in rule pack**, so a change to `rules.yaml` that changes results fails here until the golden files are updated on purpose.
- Fixtures: `imports.go` (every import rule, alias, blank import), `calls.go` (key sizes, hex, constant, too few args, function value, two aliases of one package), `dot.go`, `clean.go` (crypto names only in strings, comments and a local type: no findings), `pqc.go`, `broken.go` (partial parse plus error).
- They sit at the repo root, as the plan says (`testdata/fixtures/<lang>/`); `go build`/`vet` ignore `testdata`, and lint excludes it.

---

## `internal/detect/detect.go` — `Finding` fields for certificates and keys (added with the cert detector)
- **`AssetType`** (`algorithm` | `certificate` | `related-crypto-material`) and **`MaterialType`** (`private-key` | `public-key`) use **CycloneDX 1.6's own names**, so the Phase 4 CBOM reporter copies them through, the same reasoning as `rules.Primitives`. Empty `AssetType` means `algorithm`, so the existing detectors didn't need to change.
- *Options considered:* a separate `Secret bool`, or a new `Status`. **Chose CycloneDX's model:** "a private key is in the repo" is a related-crypto-material asset of type private-key, and the classifier (Phase 3) can rate that critical from the fields alone. A finding's risk status stays the classifier's decision, not the detector's.
- **`Cert *Certificate`** (subject, issuer, validity dates): a pointer, so the ~95 % of findings that aren't certificates carry 8 bytes instead of a ~100-byte struct. These are the fields CycloneDX `certificateProperties` needs.
- **`ParameterSet`** (`ML-DSA-65`): post-quantum schemes are sized by named parameter set, not key bits. Putting 65 into `KeySize` would be wrong, and the CBOM's `nistQuantumSecurityLevel` depends on the set (44 → 2, 65 → 3, 87 → 5). Maps to CycloneDX `parameterSetIdentifier`.
- **`Algorithm` may now be `""`**: an encrypted PKCS#8 key or a `.p12` store doesn't reveal its algorithm, and the finding still has to be reported.
- `Snippet` is documented as **never containing key material**. That's a contract every detector must keep, since reports are shared and uploaded.

### `rules.Algorithms` gains `MD2`
X.509 can name `MD2WithRSA`, and the closed set must cover every name any detector emits, not only rule-pack names. `TestAlgorithmNamesAreKnown` (cert package) enforces this for the cert detector's mappings.

### `rules.Algorithms` gains `sntrup761` (added with the config detector)
Streamlined NTRU Prime, the post-quantum half of OpenSSH's **default** key exchange since 9.0 (`sntrup761x25519-sha512`). It's not NIST-standardised, so it gets its own name rather than being folded into ML-KEM: the classifier can rate it "quantum-resistant, non-NIST" separately. Spelled the way OpenSSH spells it, because no other common name exists.

---

## `internal/detect/detect.go` — `Protocol` and the TLS version constants (added with the config detector)
- **`AssetProtocol = "protocol"`** (CycloneDX's assetType) and **`Finding.Protocol`**, which holds one of `SSLv2`, `SSLv3`, `TLSv1.0` … `TLSv1.3`. An enabled TLS version is a protocol asset, not an algorithm, and RFC 8996 deprecates TLS 1.0/1.1 regardless of cipher. The classifier rates these.
- **One string field** rather than CycloneDX's split type/version: every protocol finding so far is TLS. The CBOM reporter splits `TLSv1.2` into `tls` + `1.2`. Revisit when an IPsec or SSH protocol-version finding appears.
- The version spellings are fixed constants, so every detector and the classifier use the same strings (`TLSv1` and `TLSv1.0` both become `TLSv1.0`).

## `internal/detect/dedupe.go` (added with the config detector)

### `func Dedupe(fs []Finding) []Finding`
- **What it does:** merges findings that say the same thing about the same line. Used by the crawler (across detectors) and by the config detector (many suites on one line share ECDH and SHA-1).
- **Rule: subsumption, not equality.** *a* subsumes *b* when they share line, algorithm, asset type, material type and protocol, and every detail *b* states (key size, mode, parameter set, primitive) *a* states the same way. *b* may leave any of them unknown. Regex's `ML-KEM` and config's `ML-KEM` with parameter set `ML-KEM-768` on one `KexAlgorithms` line are one fact, and the richer one is kept. *Option rejected:* exact equality, which would keep both of those, because they differ only in what the regex couldn't see.
- **Conflicting details are never merged:** AES-256-GCM and AES-128-CTR on one `Ciphers` line are two configurations. Neither is a less detailed version of the other.
- **Confidence:** the kept finding takes the higher of the two confidences. Two independent detectors agreeing is more evidence, not less.
- **Certificates are never merged**, because a certificate finding carries its subject and dates, and two certificates can't be "the same line".
- **Order:** the surviving findings keep their input order. When two are identical, the earlier one wins, so the result doesn't depend on loop order (the goldens are deterministic).
- **Data structures:** an index slice stably sorted by line (findings are grouped by line without reordering `fs`), and a `[]bool` drop mask. Comparisons are O(k²) within a line group of size *k*. Lines rarely have more than a dozen findings (a long `ssl_ciphers`), so that's cheap. Filtering is in place, with no new allocation for the result.

### `func subsumes(a, b *Finding) bool` / `func covers[T](a, b T) bool`
`covers` is a generic helper ("b is unknown, or equals a") used for the four detail fields, so int and string fields use the same rule. Pointer arguments avoid copying the ~250-byte `Finding` on every comparison. **`PURL` is part of the subject** (added with the deps detector), so two libraries named on one line are never merged into one.

## `internal/detect/detect.go` — `PURL` (added with the deps detector)
A dependency finding names a **library**, not one algorithm, so it carries its **Package URL** (`pkg:npm/node-forge@1.3.1`). That's the identifier CycloneDX uses for components, so the CBOM reporter can list the library as a component and link the crypto asset to it, and the backend can join findings with SBOM data later. *Option rejected:* separate name, version and ecosystem fields. purl is the standard way to pack exactly those, and reporters would rebuild it anyway.

---

## `internal/detect/cert/cert.go`

No rules: a certificate or key states its own algorithm, so this detector maps parsed values directly. New dependency **`golang.org/x/crypto/ssh`** (project-owner decision, 2026-11-02). It's maintained by the Go team and parses OpenSSH key formats, which avoids a hand-written parser for exactly the kind of untrusted binary format where bugs hide. It brings in `golang.org/x/sys` indirectly.

### Constants `Name = "cert"` and built-in rule IDs
`cert-public-key`, `cert-signature`, `cert-signature-hash`, `private-key-committed`, `public-key`, `dh-parameters`. They're constants here, not in `rules.yaml`, because nothing about them is configurable. They follow the same ID format and never-rename rule, since suppressions and baselines reference them. *Open:* SARIF (Phase 4) needs a description for each; they'll need a registry the reporter can read.

### `var derExts`, `var keyStoreExts`, `var pemBegin`
Maps for O(1) extension checks. Extensions are compared **lower-cased** (`CA.CRT` counts). `.p12`/`.pfx` are reported without parsing: they're password-protected and normally hold private keys, so the honest finding is "a private-key store is committed" at medium confidence. `.jks` is left out because Java truststores (public CA certs only) are common, and flagging them as private keys would be a false critical.

### `func (*Detector) Supports(path, binary) bool`
- **Every text file**, because PEM blocks are embedded in source code (Go's own `crypto/x509/parser_test.go`, for example) and configuration as often as they sit in `.pem` files. `Supports` only sees the path, so content sniffing must happen in `Detect`.
- *Cost:* the crawler now reads every text file in full instead of just the first 8 KB. Measured on Go's source tree (10,519 files): ~0.3 s warm, about the same as before. The regex detector will need full reads anyway.
- Binary files only with a DER or PKCS#12 extension.

### `func (*Detector) Detect(ctx, f) ([]Finding, error)`
Routes by kind: key store → one finding; binary → `detectDER`; text → SSH public keys (only in `.pub`/`authorized_keys*`) plus PEM, but only after a `bytes.Contains(content, "-----BEGIN ")` pre-check. Most files fail that check, so they cost one linear scan and no allocation. Errors from each part are joined, so findings from one part survive an error in another.

### `func FindPEM(ctx, content) ([]Finding, error)` (was `detectPEM`; exported for the config detector's Kubernetes secrets)
- **Finds every `-----BEGIN ` marker and decodes from each one independently.** *Option rejected:* the usual `for block, rest := pem.Decode(rest)` loop, which stops at the first malformed block and silently hides every key after it. A bundle with one broken certificate must not hide a private key further down.
- **Line numbers are counted incrementally** (`bytes.Count` from the previous marker), so a file is scanned once overall rather than once per marker (O(n), not O(n·markers)).
- A decoded block must have the **same type as its marker**. Otherwise `pem.Decode` may have skipped ahead to a later block, and the finding would get the wrong line.
- **The snippet is the marker text, never the source line.** A key embedded on one line (`"-----BEGIN…\nMIIE…"`) would otherwise put the private key itself into the report. `TestNoKeyMaterialInSnippets` guards this.
- Parse failures of decoded blocks become warnings with the line number. Blocks that don't even decode (a `...` placeholder in a README) are skipped silently: there's nothing in them to inventory, and warning would be noise on every project with TLS setup docs.
- `ctx` is checked once per block, so a CA bundle with hundreds of certificates stops promptly.

### `func blockType(b) (string, bool)`
Accepts `A–Z`, `0–9` and space, up to 64 bytes, before the closing `-----`. That's tighter than the PEM grammar, on purpose: lower-case text like "-----BEGIN something-----" in prose isn't a PEM marker (the README fixture checks this), and the length cap stops a stray marker from scanning megabytes.

### `func parseBlock(typ, block) ([]Finding, error)`
- **Any type containing `PRIVATE KEY`** (PKCS#1/8, SEC 1, OpenSSH, `ENCRYPTED`, even `PGP PRIVATE KEY BLOCK`) is reported **even when the block won't decode**. A committed private key is the most severe finding the tool has, so it should over-report here rather than under-report.
- `CERTIFICATE` → `certFindings`. `CERTIFICATE REQUEST`, `PUBLIC KEY` and `RSA PUBLIC KEY` → a public-key finding. `DH PARAMETERS` → DH, so a server's committed `dhparam.pem` shows up as quantum-vulnerable key agreement. Other types are ignored.
- *Known limitation:* Go's x509 parser is strict, so certificates it rejects (negative serials, malformed policies; 13 such test certs in Go's own tree) give a warning instead of an inventory entry. A more lenient parser would mean writing our own ASN.1 handling, which isn't worth it for deliberately broken certificates.

### `func parsePrivateKey(typ, block) Finding`
- PKCS#8 → `x509.ParsePKCS8PrivateKey` (it knows ML-DSA in Go 1.27). PKCS#1, SEC 1 and OpenSSH → `ssh.ParseRawPrivateKey`, which handles all of them, including legacy OpenSSL encryption.
- **Encrypted OpenSSH keys still reveal their algorithm:** that format stores the public key unencrypted, and `ssh.PassphraseMissingError.PublicKey` exposes it. The `id_ed25519_enc` fixture is reported as EdDSA at high confidence.
- **It never fails.** If parsing doesn't work, the marker prefix gives the algorithm (`RSA ` → RSA, `DSA ` → DSA, `EC ` → ECC) at medium confidence; with no prefix, the algorithm is unknown.

### `func privateKeyFrom(pub) Finding`
Reports a parsed private key through its public half (algorithm, size, parameter set). **EC private keys are reported as `ECC` with no primitive**, whatever format they're in. Go parses all of them as `*ecdsa.PrivateKey`, but the key itself doesn't say whether it signs or does key agreement. Saying `ECDSA` would claim a use we can't know, and the classifier rates both the same anyway.

### `func privateKey(...)` / `func publicKey(pub)`
Small constructors, so every key finding fills `AssetType`/`MaterialType` the same way. The `publicKey(nil)` pattern in the SSH path relies on `keyInfo(nil)` returning a zero value.

### `func certFindings(c) []Finding`
- **Up to three findings per certificate:** the subject key (the certificate asset, carrying `Cert`), the issuer's signature algorithm, and the hash in that signature. *Option rejected:* one finding per certificate. The `chain.pem` fixture shows why not: an **ML-DSA certificate signed by an RSA CA** looks quantum-safe if you only read its key, but its trust still rests on RSA. Likewise RSA-2048 signed with SHA-1 has two separate problems.
- Ed25519 and ML-DSA signatures have no separate hash, so there's no third finding for them.
- Expiry isn't judged here. The dates go into `Cert`, and reporters decide what "expired" means.

### `func detectDER(content) ([]Finding, error)`
Tries the formats in order: certificates (`ParseCertificates` handles concatenated DER), PKCS#8, PKCS#1, SEC 1 private keys, then a PKIX public key. The first success wins. Anything else gives a "not a DER certificate or key" warning. Findings get **line 0** (binary files have no lines) and a descriptive snippet such as `DER certificate`.

### `func isSSHPublicKeyFile(path) bool` / `func detectSSHPublicKeys(content) []Finding`
- Only `*.pub` and `authorized_keys*` files. `ssh-rsa AAAA…` lines are common in documentation, and in `known_hosts` they're other people's host keys, not this project's crypto.
- Parsed **line by line** with `ssh.ParseAuthorizedKey`, which gives line numbers (its own multi-line mode doesn't). Lines that fail are skipped without a warning, because `.pub` files often hold PEM keys instead, which `FindPEM` reports.
- SSH certificates are unwrapped to the key they certify. The snippet is the key type (`ssh-ed25519`), never the base64 body.

### `func sshTypeInfo(t) keyDetails`
Fallback for SSH key types with no Go `crypto.PublicKey` form, such as FIDO `sk-ssh-ed25519@openssh.com`. It goes by substring in the type name. It only runs after the typed path has failed, so a false match can only fill an otherwise unknown algorithm.

### `type keyDetails` / `func keyInfo(pub) keyDetails`
- A type switch over Go's public-key types. Sizes: RSA/DSA modulus bits, ECDSA curve bits, Ed25519/X25519 = 255, the NIST curves for ECDH by curve identity. ML-DSA reports its **parameter set**, not bits.
- **RSA has no primitive**: the key alone doesn't say whether it signs or encrypts.
- Unknown key types give zero `keyDetails` (the algorithm is unknown) rather than an error, so the certificate is still inventoried.

### `func publicOf(key) crypto.PublicKey`
Uses the `Public()` method most private keys share, with `*dsa.PrivateKey` (which has none) as a special case. Returns nil for unknown types, which `keyInfo` handles.

### `type sigDetails` / `func sigInfo(a) sigDetails`
An explicit `switch` over every `x509.SignatureAlgorithm`, splitting each into signer, hash and parameter set. *Option rejected:* parsing `a.String()` ("SHA256-RSA"), which would break silently if Go changed its spelling. With a switch, a new Go constant shows up as unknown, and the test that loops over every constant would catch a name outside `rules.Algorithms`.

### Tests and fixtures: `testdata/fixtures/cert/`
- **Real certificates and keys**, generated by `gen.sh` (`go run gen.go` for the X.509/PKCS formats, plus `ssh-keygen` and `openssl` for OpenSSH, encrypted PKCS#8, DH parameters and SHA-1 signatures, which Go refuses to create). Both generators are committed so the fixtures can be rebuilt. Dates are fixed (2026-01-01 to 2036-01-01) so regenerating doesn't change the goldens for no reason.
- **All keys are throwaway test keys.** Secret scanners such as GitHub's will flag them, which is expected for this directory.
- Goldens go in `golden/<name>.golden`, a subfolder because the fixtures have no shared extension to glob. The format is the goast one plus `ParameterSet`, asset/material type and certificate fields.
- Coverage: RSA/ECDSA/Ed25519/ML-DSA certificates, a mixed ML-DSA-leaf-with-RSA-CA chain, SHA-1-signed, DER, PKCS#1/PKCS#8/ML-DSA/encrypted PKCS#8/OpenSSH (plain and encrypted) private keys, keys embedded in source (raw and escaped), CSR, PKIX public key, DH parameters, `authorized_keys` (RSA, ECDSA, FIDO, a garbage line), a `.p12` store, plus negatives: a README placeholder, a malformed cert, a junk `.der`.
- `TestNoKeyMaterialInSnippets` and `TestAlgorithmNamesAreKnown` guard the two contracts above.

---

## `internal/detect/regex/regex.go`

Matches the `regex` rules line by line in any text file. Measured with `BenchmarkDetect`: **~315 MB/s** on source without crypto (the common case), **~6 MB/s** on the crypto fixture repeated, where almost every line has a match. A full CLI scan of Go's source tree (10,519 files, all three detectors) takes ~0.56 s warm.

### `const ctxCheckLines = 4096`
Cancellation is checked every 4,096 lines, not on every line: `ctx.Err()` takes a lock, and 4,096 lines take well under a millisecond, so a cancelled scan still stops promptly.

### `var lowerASCII [256]byte`
A lookup table for ASCII lower case, built once. Folding a byte is one indexed load, with no branch, no allocation, and no change to line length (non-ASCII bytes map to themselves). That's why keywords must be ASCII.

### `const triBits = 16` / `func triHash(tri) uint32`
- **The keyword index.** Each keyword's first three bytes (a *trigram*, 24 bits) are hashed with a multiplicative (Fibonacci) hash to 16 bits, and that bit is set in a 65,536-bit (8 KB) filter. While scanning a line, every position's trigram is checked against the filter. Almost all positions miss, which costs one load and one AND.
- 8 KB fits in L1/L2 cache. With ~100 distinct keywords, about 0.15 % of the bits are set, so false hits (a trigram that hashes to a set bit but begins no keyword) are rare, and each one costs a map lookup.

### `type ruleSet` / `func newRuleSet(rs) *ruleSet`
- **Data structures:** `keywords [][]byte` (distinct, lower-cased), `byKeyword [][]int` (keyword → rule indexes), `byTri map[uint32][]int` (trigram → keyword indexes), and `filter [1024]uint64` (the bit filter above). Slices indexed by integer rather than maps keyed by string everywhere except `byTri`, which is only consulted after the filter says yes.
- Keywords shared between rules (`keypairgenerator` is used by 8 Java rules) are stored once, so each is checked once per position no matter how many rules use it.
- **The first version** searched the whole file once per keyword (`bytes.Contains` over a lower-cased copy). Profiling showed 78 % of the time in that loop, for a cost that grew with every rule added: 44 MB/s on clean files. The single-pass trigram scan made it about 7× faster (315 MB/s), and it also removed the 16 KB lower-cased copy per file.
- *Options rejected:* **Aho-Corasick** (optimal, but a dependency or ~200 lines of automaton code, for a gain the trigram filter mostly already captures), and **one big alternation regex of all keywords** (Go's RE2 has no literal-set acceleration, so it would be slower than the trigram scan).

### `func (s *ruleSet) lineRules(dst, line, seen, stamp) []int`
- One pass over the line with a **rolling trigram**: shift in one lower-cased byte per position, so each byte is read once. On a filter hit it looks up the keywords that start with that trigram, confirms each with `equalFoldASCII`, and adds their rules.
- **De-duplicating without clearing:** `seen[ri] == stamp` (the stamp is the line number) means rule *ri* is already in the result. A per-line map, or clearing a bool slice for each line, would cost time on every line, including the ~99 % with no keyword. The `seen` slice is allocated once per file.
- The result is sorted, so rules run in pack order and the findings order on a line is deterministic.
- **Line-level, not file-level:** a pattern runs only on lines that contain one of its keywords, not on every line of a file that contains one somewhere. The second version (file-level prefilter) still ran 0.95 MB/s on crypto-heavy files, because every candidate rule's regex ran on every line. Going line-level made that about 6× faster. It relies on the keyword rule ("every line the pattern can match contains a keyword"), which `examples` check at load time.

### `func equalFoldASCII(b, lower) bool`
Compares a slice of the source with a lower-case keyword byte by byte through `lowerASCII`, with no allocation. `bytes.EqualFold` would also handle Unicode, which costs more and isn't needed.

### `type Detector` / `func New(rs) *Detector`
- **Data structure:** `byExt map[string]*ruleSet`, holding one rule set per language and shared by all of that language's extensions (`.js`, `.mjs`, `.cjs` and `.jsx` point to the same set). There's also a `generic` set for files of no known language. Every set is built at construction, so `Detect` does one map lookup per file.
- Each language's set = generic rules + that language's rules, **in pack order**, so findings on one line come out in a stable order, and golden diffs show only real changes.
- Read-only after `New`, so workers share it with no locks.

### `func (d *Detector) setFor(path) *ruleSet` / `Supports(path, binary) bool`
The extension is lower-cased (`Main.JAVA` counts as Java). Files with no extension or an unknown one (`Makefile`, `sshd_config`, `.md`, `.conf`) get the generic rules. `Supports` accepts any text file that has at least one applicable rule, so a detector built with no rules never makes the crawler read files in full.

### `func (d *Detector) Detect(ctx, f) ([]Finding, error)`
- **Hand-rolled line loop** (`bytes.IndexByte`) instead of `bufio.Scanner`, which the plan suggested. The crawler has already read the whole file into memory, and `Scanner` has a maximum token size (minified JavaScript lines can exceed it, and the plan's 1 MB buffer was a workaround for that) and copies each line. Slicing the content directly has no length limit and no copying. A trailing `\r` is removed, so CRLF files give the same matches and snippets.
- **Comments are matched like code** (project-owner decision, 2026-11-02). Telling comments apart reliably needs a parser per language, and commented-out crypto is worth seeing in an inventory. False positives are handled by `// shorstop:ignore` (Phase 5), and documentation hits (Go's own tree has `3DES` in comments) are true mentions, not mistakes.
- **One finding per distinct match per rule per line** (from `MatchAll`), minus generic findings covered by a language rule (`coveredBy`). The snippet is computed once per matching line (`SnippetOf`) and shared by all its findings.
- `hits` and `active` are reused across lines (`[:0]`), so a file with no crypto allocates only the `seen` slice.
- It never returns an error other than cancellation: a regex can't fail on input.

### `type hit` / `func (h hit) coveredBy(line []hit) bool`
- When a **language rule** and a **generic rule** find the **same algorithm on the same line** (`cs-3des` and `generic-3des` on `TripleDES.Create()`), only the language rule's finding is kept: its ID names the API, which is the more useful fact, and the CBOM would otherwise count one use twice.
- Two generic rules, or two language rules, are never merged: `Signature.getInstance("SHA1withRSA")` really is RSA *and* SHA-1, and `aes256-gcm,aes128-ctr` really is two AES configurations.
- *Option rejected:* tightening generic patterns so they can't match inside API calls. That would need a negative lookbehind, which RE2 doesn't support, and it would make generic rules miss real cipher strings.
- O(hits²) per matching line. Lines with more than two or three hits are rare.

### Tests: `testdata/fixtures/{c,csharp,generic,java,javascript,php,python,ruby,rust,typescript}/`
- **One realistic fixture per language** using the real APIs, with goldens in `<lang>/golden/<file>.golden` (same tab-separated format as goast, plus mode). `generic/` covers a `nginx.conf`, an `sshd_config` with no extension, and a README.
- **Each fixture ends with a "Near-misses" section**: lines that look like crypto but aren't (`hashlib.sha256`, a Java call inside a Python string, `md5sum` as a variable name, "description"/"caesar"). `TestNearMisses` fails if anything below that marker produces a finding, so a loosened pattern can't be quietly accepted into a golden file.
- `TestLanguageSets` checks that generic rules apply everywhere, language rules only to their own extensions, and Kotlin gets the Java rules. `TestCRLFAndLastLine` checks CRLF handling and a last line with no newline. `TestCancelled` checks cancellation. `BenchmarkDetect` measures the two throughput numbers above.
- **Reviewing the goldens found three bugs** before they shipped: only the first match per line was reported, generic and language rules double-counted the same call, and `modes.ECB()` was guessed as AES on a 3DES line. All three are fixed above.
- **False-positive check on real code:** a throwaway dump (deleted afterwards) of the 556 regex findings in Go's source tree. I sampled every rule and found no false positives; all were real mentions of the algorithm, in code, test vectors or comments.

---

## `internal/detect/config/` — `config.go`, `tls.go`, `ssh.go`, `k8s.go`

Reads cryptographic settings from server configuration and reports **the configuration in effect**: TLS versions, cipher strings and key-exchange groups (nginx, Apache, HAProxy, PostgreSQL, stunnel, openssl.cnf), OpenSSH algorithm lists, openssl.cnf key defaults, and certificates and keys base64-encoded in Kubernetes Secrets. No rule pack: each directive's meaning is code, not data, because it needs real parsing (removals, `all`, multi-line statements).

**Why a parser and not more regex rules:** in a cipher string, `HIGH:!aNULL:!3DES` *disables* 3DES. A pattern can't tell that from enabling it, and the regex detector reported exactly this false positive on most real nginx configs. Apache's `all -SSLv3 -TLSv1` has the same problem for protocol versions.

**Comments are skipped here**, unlike in the regex detector (whose comment matching was a project-owner decision about source code). This detector parses each format's syntax, so it knows what's commented out, and a commented-out directive is by definition not in effect. Validated on this machine: macOS's fully commented `/etc/ssh/sshd_config` gives no findings, and Homebrew's two `openssl.cnf` files give exactly `default_bits = 2048`.

### `config.go`

#### Constants: rule IDs
`tls-protocol-version`, `tls-cipher`, `tls-group`, `ssh-kex`, `ssh-cipher`, `ssh-mac`, `ssh-key-algorithm`, `openssl-default-bits`, `openssl-default-md`. One ID per directive *kind*, not per algorithm: a suppression like "TLS 1.0 is accepted on this legacy host" targets a kind of setting. Kubernetes Secret findings keep the cert detector's IDs (`private-key-committed`, …), because they are the same finding wherever the key sits. Same never-rename rule as the rule pack.

#### `type kind` / `var tlsDirectives` / `var sshDirectives`
- **Data structure:** `map[lower-case directive name]kind`, a closed table of what each directive means. Lookups are one map access per statement.
- **One TLS table for every format.** The names are distinctive enough not to clash (`ssl_ciphers` is nginx *and* PostgreSQL, with the same meaning). *Option rejected:* detecting the format first (is this nginx or Apache?). Files don't say what they are, nginx site files have no extension, and a per-format split would duplicate the shared cipher-string reader five times.
- **SSH directives only in OpenSSH files** (`isSSHFile`): `Ciphers` is an SSH algorithm list there, but in stunnel it's an OpenSSL cipher string. Outside OpenSSH files `ciphers` is read as a cipher string (a stunnel fixture caught that this was first left unread).
- Covered: nginx `ssl_*` and its `proxy_`/`grpc_`/`uwsgi_` variants, Apache `SSLProtocol`/`SSLCipherSuite`/`SSLOpenSSLConfCmd`, HAProxy `ssl-default-*`/`ssl-min-ver`, PostgreSQL `ssl_min_protocol_version`, openssl.cnf `CipherString`/`Ciphersuites`/`MinProtocol`/`Groups`/`default_bits`/`default_md`, OpenSSH `KexAlgorithms`/`Ciphers`/`MACs`/`HostKeyAlgorithms` and the `Pubkey…`/`Hostbased…`/`CASignature…` lists.

#### `func (*Detector) Supports` / `isConfigFile` / `isSSHFile` / `isYAML`
`.conf`, `.cnf`, `.cfg`; files whose name starts with `sshd_config`/`ssh_config`, or that sit in `sshd_config.d`/`ssh_config.d`; anything in nginx's `sites-available`/`sites-enabled` (those files usually have no extension); and `.yaml`/`.yml` for Kubernetes Secrets. By path only, so the crawler doesn't read every text file in full on this detector's behalf.

#### `func (*Detector) Detect`
YAML goes to `k8sSecrets`. Everything else goes through `statements` → directive lookup → `interpret`. Each finding gets the statement's first line and a snippet of that line. Confidence is always **high**: the value was parsed, not pattern-matched. The result goes through `detect.Dedupe`, because one cipher list repeats ECDH and SHA-1 across many suites, and the golden files should show what the user will see.

#### `func interpret(k, v) []Finding`
A switch on `kind`. Notable cases:
- **Apache `SSLCipherSuite TLSv1.3 …`**: a leading protocol word is dropped before the cipher string is read.
- **`default_bits`** means RSA, because `openssl req` generates RSA unless told otherwise. It's digits only, capped at 65,536, and anything else is ignored.
- **`default_md`** maps through `mdNames`. `default` names no algorithm, so it's ignored.
- **`SSLOpenSSLConfCmd`** takes a sub-command name and dispatches to the same readers (`Groups`, `CipherString`, `MinProtocol`).

#### `type stmt` / `func statements(content) []stmt`
- Splits a file into directives: `key value`, `key = value`, nginx's `key value;` (possibly continued over several lines until the `;`), and `\` line continuation (Apache, openssl.cnf).
- **nginx multi-line**: only for keys containing `ssl_` written without `=` (PostgreSQL's `ssl_ciphers = …` has one), and **only joined if a `;` actually appears** within 20 lines. Otherwise the line stands alone. The first version joined any key containing `ssl`, which would have swallowed the lines after every Apache `SSLCipherSuite` (Apache doesn't end directives with `;`).
- `[section]` headers, nginx `{`/`}` and XML-ish `<VirtualHost>` lines don't start with a key character, so they're skipped without special cases.
- Snippets use the statement's **first physical line**, so they point at the directive's name.

#### `func splitDirective(line)` / `func isKeyByte(c)` / `func stripComment(s)`
- Keys are `[A-Za-z0-9_.-]`, up to 64 bytes, lower-cased for lookup. `=` is optional; whether it was present matters to the nginx rule above.
- **Comments:** a `#` at the start of a line or after whitespace, **outside quotes**, starts a comment. `'v#1'` and `abc#def` keep their `#`. That's the shared subset of the five formats' comment rules.

### `tls.go`

#### `type algo`
The value-level result (algorithm, primitive, mode, parameter set, bits) before a rule ID, line and snippet are attached. Small and comparable, so tables of them are plain map literals.

#### `var tlsVersions` / `var apacheAll` / `func parseVersion` / `func protocolList` / `func minProtocol`
- `protocolList` handles nginx's plain list and Apache's `+`/`-`/`all`, plus `!` as a removal. The result is a set, emitted oldest-first, so `+TLSv1.3 +TLSv1.1` reports 1.1 then 1.3 consistently.
- **`all` = TLS 1.0–1.3, without SSLv3.** OpenSSL 1.1.0+ is built without SSLv3, and Apache only adds it when the library has it. *Tradeoff:* a server linked against an ancient OpenSSL would also enable SSLv3. We'd under-report it, and say so here.
- `minProtocol` (openssl.cnf `MinProtocol`, HAProxy `ssl-min-ver`, PostgreSQL) reports the minimum **and every newer version**, so `TLSv1.1` flags 1.1 and still inventories 1.2/1.3. `None` and unknown values give nothing.

#### `var cipherKeywords` / `func cipherString(v)`
- Tokens split on `:`, `,` and whitespace. **`!` and `-` remove, `+` reorders, `@` is an option, so none of them enables anything.** `HIGH`, `MEDIUM`, `DEFAULT`, `ALL`, `aNULL` and similar name sets defined by the OpenSSL build. Expanding them would need the library's table, which changes between versions, so they report nothing. *Tradeoff:* `MEDIUM` could include 3DES on an old OpenSSL. We under-report rather than guess.
- `EECDH+AESGCM` (both required) reports each part.
- `cipherKeywords` holds single-algorithm terms (`RC4`, `kRSA`, `aECDSA`, `AESGCM`, …), so `EECDH+AESGCM` gives ECDH and AES-GCM.

#### `func parseSuite(s)`
- Reads both **OpenSSL** (`ECDHE-RSA-AES128-GCM-SHA256`, `DES-CBC3-SHA`) and **IANA** (`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, TLS 1.3's `TLS_AES_256_GCM_SHA384`) names, using one token walker over `-`-separated tokens (IANA's `_` is normalised to `-`).
- **Roles from position:** RSA after a key exchange signs; RSA with no key exchange before it (`TLS_RSA_WITH_…`) transports the key (`pke`).
- **Implied RSA:** OpenSSL names with no key exchange (`AES128-SHA`, `DES-CBC3-SHA`, `RC4-MD5`) use RSA key transport, so it's added. TLS 1.3 names have no key exchange in them, and PSK/SRP suites aren't public-key, so neither gets it.
- **AES without an AEAD mode is CBC**, since TLS has no other non-AEAD AES suites.
- **The trailing hash gets a role-specific primitive:** `mac` (HMAC record MAC) in CBC/stream suites, `kdf` (PRF/HKDF) in AEAD suites. HMAC-SHA1 and HMAC-MD5 are not broken the way SHA-1 signatures are. The plan's correction #2 says the report mustn't overstate risk, and the primitive lets the classifier tell those cases apart.
- Ciphers outside the closed algorithm set (Camellia, ARIA, SEED, IDEA, NULL) count as "a cipher was seen" but add no finding. A name with no cipher token at all (`TLSv1.2`, `FOO-BAR`) isn't a suite, and gives nothing.

#### `func groupList(v)` / `var groupAlgos`
Key-exchange groups (nginx `ssl_ecdh_curve`, OpenSSL `Groups`/`Curves`). **Hybrid post-quantum groups report both halves**, e.g. `X25519MLKEM768` → X25519 *and* ML-KEM with parameter set ML-KEM-768. The CBOM then shows the classical half still present, and the quantum-safe half as progress. OpenSSL 3.5's `?` (optional) and `*` (key share) prefixes are stripped; `-`/`!` entries are removals.

#### `func splitAny(s, seps)`
`strings.FieldsFunc` over the given separators plus tab, then strips quotes and drops empty fields. Every list format here is "tokens separated by some of `: , space`", possibly quoted.

### `ssh.go`

#### `func sshList(v, name)`
OpenSSH lists are comma-separated. `+` (append) and `^` (prepend) enable their items; `-` removes them. **Wildcard patterns are skipped** (`ssh-*`), because they select from OpenSSH's built-in default list, which we don't have.

#### `func sshKex` / `var dhGroupBits`
`curve25519` → X25519. `sntrup761x25519` → sntrup761 + X25519. `mlkem768x25519`/`mlkem768nistp256`/`mlkem1024nistp384` → ML-KEM + the classical half. `ecdh-sha2-nistpN` → ECDH-N. `diffie-hellman-groupN` → DH at the RFC size (group1 = 1024 … group18 = 8192); `group-exchange` → DH of unknown size, because the server picks it. A `-sha1` suffix adds SHA-1 (hash). `ext-info-c`, `kex-strict-*` and GSS methods are protocol extensions, not algorithms.

#### `func sshCipher` / `func sshMAC` / `func sshKeyAlg`
- Ciphers: `aesN-ctr|cbc|gcm`, `3des-cbc`, `chacha20-poly1305` (`ae`), `arcfour*` → RC4. Blowfish and CAST-128 are outside the closed set and give nothing.
- MACs: `hmac-sha1`/`-96`, `hmac-md5`/`-96`, `hmac-sha2-256/512`, with `-etm` variants folded in. UMAC is not a hash.
- Key algorithms: **`ssh-rsa` reports RSA *and* SHA-1**, because that signature algorithm hashes with SHA-1 (the reason OpenSSH disabled it). `rsa-sha2-256/512` give RSA + SHA-2. Certificate (`-cert-v01`), FIDO (`sk-`) and `webauthn-` variants are reduced to the key they use.

### `k8s.go`

#### `func k8sSecrets(ctx, content)`
- **Why:** a Secret's `data:` values are base64, so a committed TLS key in a manifest is invisible to the cert detector, and committed manifests are a common way keys leak. Each value is decoded (whitespace removed first, since long base64 is wrapped over lines). If it contains a PEM marker, it goes to **`cert.FindPEM`**, the cert detector's own parser, exported for this. The same parsing and the same "never print key material" rule apply.
- `stringData:` (plain text) is left alone: the cert detector already reads the raw file, and handling it here would report each key twice.
- Findings are placed on the line of the **data key** (`tls.key:`). The snippet is `tls.key in Secret web-tls (base64): -----BEGIN RSA PRIVATE KEY-----`, naming the key and Secret and never the value.
- **Prefilter:** files without both `kind` and `Secret` aren't parsed as YAML. Most YAML in a repo is CI config or app settings.
- **Templates are skipped silently** (`{{` anywhere): a Helm template is not valid YAML until rendered, and its values are placeholders. A YAML syntax error in a non-template file *is* reported as a warning, because a Secret we couldn't read might hold a key.
- Multi-document files (`---`) are walked document by document. Non-Secret documents (ConfigMaps) are skipped.

#### `func mapValue(m, key)`
A linear lookup in a YAML mapping node's key/value pairs. Mappings in manifests have a handful of keys, so building a map would cost more than it saves.

### Tests: `testdata/fixtures/config/`
- Fixtures modelled on real configs: nginx (a removals-only cipher string that must report nothing, a multi-line list, a hybrid PQC group), an nginx site file with no extension, Apache (`all -…`, `\` continuation, TLS 1.3 prefix, `SSLOpenSSLConfCmd Groups`), sshd_config (+/−/^ lists, PQC key exchanges, a commented line), an included `sshd_config.d/*.conf`, openssl.cnf, HAProxy, PostgreSQL (`=` and quotes; `+3DES` only reorders), stunnel, a Kubernetes multi-document file (ConfigMap + TLS Secret built from the cert fixtures), and a Helm template.
- Goldens in `config/golden/<path>.golden`, mirroring the fixture tree.
- **Table tests per parser** (`TestCipherString`, `TestProtocols`, `TestSSHLists`, `TestStatements`) pin the semantics independently of fixtures. All of them passed on the first run, and the fixture review then found the stunnel `ciphers` gap and the duplicate-per-line output, both fixed.
- `TestAlgorithmNamesAreKnown` checks every table entry against `rules.Algorithms`, `Primitives` and `Modes`.

---

## `internal/detect/deps/` — `deps.go`, `lines.go`, `npm.go`, `python.go`, `jvm.go`, `other.go`

Finds known crypto libraries among a project's declared dependencies, driven by the `deps` rules. **Why it's worth having at low confidence:** it reaches crypto the other detectors can't read: minified bundles, compiled dependencies, and languages without regex rules yet. It also reports the library's identity (purl), which the CBOM needs either way.

**No new dependencies:** JSON and XML come from the standard library, YAML (pnpm) from the existing `go.yaml.in/yaml/v3`. The TOML files (poetry.lock, Cargo.lock/toml, pyproject.toml) are read line by line. *Option rejected:* a TOML library. It would be a new dependency for reading `name =` and `version =` keys from files that tools write in a fixed shape. *Cost:* hand-written edge cases. Exotic TOML (multi-line inline tables) can be missed, which is acceptable for low-confidence hints. A fixture exists for each shape we do read.

### `deps.go`

#### `type dep` / `type parser` / `func parserFor(path)`
- One `parser{eco, parse}` per file type, chosen **by file name**: go.mod; package.json, package-lock.json/npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml; requirements*.txt (and `requirements/*.txt`, pip-tools `.in`), poetry.lock, pyproject.toml, Pipfile.lock; pom.xml, build.gradle(.kts); composer.json/lock; Cargo.toml/lock; Gemfile.lock; *.csproj/fsproj/vbproj, packages.config, Directory.Packages.props.
- That's the plan's list plus the manifests of every language the regex detector covers. *Not covered yet:* go.sum (hashes only; go.mod already names the modules), Pipfile (TOML), setup.py/setup.cfg, Gemfile (Ruby code), Gradle version catalogs (`libs.versions.toml`).
- **Manifests and lockfiles are both read**, so a library can be reported from package.json (direct dependency, version range) *and* the lockfile (exact version, plus transitive copies like `selfsigned/node_modules/node-forge`). Those are different files, hence different occurrences. A transitive copy is real code shipped with the project.

#### `func normalize(eco, name)`
Registry-equivalent spellings compare equal: PyPI uses PEP 503 (lower-case, runs of `-_.` → `-`, so `liboqs_python` = `liboqs-python`), Cargo treats `-` and `_` the same, npm/Composer/RubyGems/NuGet compare case-insensitively. **Go module paths and Maven coordinates stay case-sensitive**, because that's how those ecosystems resolve them (`github.com/ProtonMail/go-crypto` ≠ `…/protonmail/…`).

#### `func purl(eco, name, version)`
Builds Package URLs per the purl spec: `pkg:maven/group/artifact`, npm scopes as `%40scope/name`, PyPI names normalised, `+` in versions encoded as `%2B`. The version is included **only when exact**. A manifest range (`^1.3.1`) isn't a version, and a purl with one would mislead. The lockfile occurrence supplies the exact one.

#### `type index` / `type prefixRule` / `func (ix *index) match(norm)`
- **Data structures:** per ecosystem, `exact map[normalized name][]*Rule` (one lookup per dependency) and a `[]prefixRule` slice for the trailing-`*` rules, checked by `HasPrefix`. A lockfile with 2,000 packages costs 2,000 map lookups plus 2,000 × (a handful of prefix rules).
- `append(slices.Clip(out), …)` keeps the prefix results from writing into the map's shared slice.

#### `func New` / `Supports` / `Detect`
- `Supports` accepts a file only if its ecosystem has rules, so a detector built with none never makes the crawler read lockfiles.
- **A file that doesn't parse gives an error (a warning) and no findings.** A half-read lockfile could miss libraries silently, and saying nothing about a broken file is the failure the project avoids everywhere else.
- Findings are sorted by line (stable), and the snippet is the manifest line, e.g. `"node-forge": "^1.3.1",`.
- *Known limitation:* lockfiles over `--max-file-size` (default 2 MB) are skipped as "too large" by the crawler. Big monorepo `package-lock.json` files exceed that. The CLI already counts and prints skipped files; raising the limit per file type is left for Phase 5's config file.

### `lines.go`

#### `func jsonKeyLine(content, key)` / `func jsonValueLine(content, field, value)`
`encoding/json` reports no positions, so lines are found by searching the text: the first `"key"` **followed by `:`** (so the same string appearing as a value elsewhere doesn't count), or the first `"field": "value"` pair. *Option rejected:* a position-aware JSON tokenizer, which is a lot of code for line numbers on low-confidence hints. *Cost:* in npm lockfile v1, a name that appears as a nested key earlier gets that earlier line. v2/v3 lockfiles use unique `node_modules/...` keys, so they're exact.

#### `func exact(v)` / `var exactSemver`
A version string is kept only if it looks like an exact version (`1.3.1`, `v0.58.0`, `2.0.0-rc.1`, `1.2.3.4`), not a range (`^`, `~`, `>=`, `*`). Each caller adds its ecosystem's rule on top (Cargo needs a leading `=`; PEP 508 needs `==`).

#### `func splitLines` / `func lineAt`
Shared helpers: lines without `\r`, and byte offset → 1-based line.

### `npm.go`
- **`packageJSON`:** the four dependency maps; versions are ranges, so only exact pins are kept. Map order is random, so results are sorted (`sortDeps`).
- **`npmLock`:** lockfile v2/v3 `packages` keyed by install path (name = after the last `node_modules/`, so nested copies are found); the root `""` entry and workspace paths are skipped. v1 is a nested `dependencies` tree, walked recursively.
- **`yarnLock`:** classic and Berry. An entry header at column 0 lists specs; the name is taken before `@npm:` (Berry) or before the last `@` (`@scope/name@^1` keeps its scope). Then the indented `version` line is read, quoted (classic) or `version:` (Berry).
- **`pnpmLock`:** YAML keys under `packages`, with the node's line number. Three key formats are supported: v9 `name@1.2.3`, v6 `/name@1.2.3(peer)`, and v5 `/name/1.2.3_peer@ver`. **v5 is checked first**, because its peer suffix contains an `@` of its own. The first version split `/openpgp/5.11.0_react@18.2.0` at that `@`, and the fixture caught it.
- **`sortDeps`** sorts by line then name and drops exact duplicates.

### `python.go`
- **`requirement`** (PEP 508): the distribution name, plus a version only for an exact `==` pin (not `===`, not `==3.*`).
- **`requirementsTxt`:** skips options (`-r`, `-e`, `--hash`, `--index-url`) and bare URLs, keeps `name @ url` direct references, and handles `\` continuations, since each physical line is read alone and the `--hash` lines start with `-`.
- **`tomlPackages`** (poetry.lock **and** Cargo.lock, which share the `[[package]] name/version` shape): reads `name` and `version` inside each `[[package]]` table.
- **`pyproject`:** PEP 621 `[project] dependencies`, `[project.optional-dependencies]`, PEP 735 `[dependency-groups]` (arrays of requirement strings, followed across lines until `]`), and Poetry's `[tool.poetry.*dependencies]` tables (`name = constraint`, skipping `python`).
- **`pipfileLock`:** JSON `default` and `develop` maps; versions are `==x`.
- **`tomlKeyString` / `tomlHeader` / `tomlQuoted`:** the small TOML subset the readers above need.

### `jvm.go`
- **`pom`:** `encoding/xml` token stream, collecting `groupId`/`artifactId`/`version` for every `<dependency>` (dependencies, dependencyManagement, plugin dependencies), with the line from `Decoder.InputPos`. **Property versions (`${bc.version}`) are left unknown**, because resolving them needs the parent-POM chain, maybe from a remote repository. Non-strict decoding tolerates real-world POMs, but it also accepts plain text, so a file with no `<project>` element is an error rather than a silent empty result (`TestMalformed` caught this).
- **`gradle`:** Gradle files are programs, so only the two literal notations are read: `"group:artifact:version"` strings and `group: …, name: …, version: …` maps, skipping comment lines. Versions from variables or version catalogs aren't resolved.
- **`ptrIf`:** a small helper so `groupId`/`artifactId` text is captured only inside a `<dependency>`.

### `other.go`
- **`goMod`:** `require` lines and `require ( … )` blocks; `// indirect` comments are stripped. `replace` and `exclude` don't add dependencies.
- **`composerJSON` / `composerLock`:** `require` and `require-dev`, skipping platform requirements (`php`, `ext-*`, which have no `/`). In the lock, the `v` prefix is dropped from versions, matching the purl convention.
- **`cargoToml`:** `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, their `[target.<cfg>.…]` forms, `[workspace.dependencies]`, and `[dependencies.<name>]` headers. **A renamed dependency (`alias = { package = "real" }`) is reported by its real name**, which is what the rule matches. **A bare Cargo version (`"0.9"`) is a caret range, so only `=x.y.z` is taken as exact**, including inside inline tables. The first version treated `"0.9"` as exact; the golden review caught it.
- **`gemLock`:** gems under `GEM` → `specs:` at four-space indent; six-space lines are their dependencies, not resolved gems.
- **`nugetXML`:** `<PackageReference>` (attribute or child `<Version>`), `<PackageVersion>` (central package management), and `packages.config`'s `<package id version>`.

### Tests: `testdata/fixtures/deps/<ecosystem>/`
- One realistic file per format (19), each mixing crypto libraries, ordinary packages and **near-name packages that must not match** (`md5-hex`, `rsa-tools`, a `"md5"` npm script, `universalify`-style substrings). Goldens are in `deps/golden/`.
- `TestNormalizeAndPURL`, `TestMatch` (wildcard boundaries, case rules per ecosystem), `TestSupports`, and `TestMalformed`, where five formats must report a broken file.
- **Checked on real files on this machine:** Go's own `go.mod` reports `golang.org/x/crypto` with its pseudo-version in the purl. 42 package files from npm's `npx` cache gave no findings, and a text search of those lockfiles confirmed none of the listed libraries appear (the only substring hit was `universalify`).

---

## `internal/classify/classify.go` (Phase 3)

Rates a finding: a **status** (`QUANTUM_VULNERABLE`, `WEAKENED`, `BROKEN`, `INSECURE_MODE`, `ACCEPTABLE`, `QUANTUM_SAFE`, `UNKNOWN`), a **severity**, a one-sentence **reason**, a **recommendation**, and the **NIST quantum security level** for the CBOM.

### `func Classify(f detect.Finding) Result`
- **A pure function of one finding**, as the plan requires ("Done when: classify is a pure function with table-driven tests for every row"). It reads no files and no other findings, so it's deterministic and every reporter (terminal, CBOM, SARIF, markdown) gets the same answer by calling it. *Option rejected:* storing the rating in `Finding` at scan time. That would freeze ratings into baselines and caches, so a corrected rating would never reach old scans. Computing it on demand is cheap: a switch statement per finding.
- **Precedence is the order of the checks:**
  1. A committed private key is **critical whatever its algorithm**, even ML-DSA or unknown: the problem is the exposed secret, not the maths. Its status still comes from the algorithm, so the CBOM can say "quantum-vulnerable RSA key, exposed".
  2. Protocol findings are rated by version.
  3. Everything else is rated by algorithm.
  4. **Dependency findings are capped at low** (`PURL` set): the plan's "low (dependency-only hints)". The cap only lowers; a quantum-safe library stays `info`. The reason gets a `Dependency:` prefix, so a reader knows it's a hint.
- **Gaps the plan's matrix left open, filled here and listed for review:**
  - **Short keys are BROKEN, not only quantum-vulnerable:** RSA, DSA and DH below 2048 bits, and elliptic curves below 224 bits (NIST SP 800-131A). RSA-1024 and DH-1024 (Logjam) can be attacked classically today; calling them only "quantum-vulnerable" would understate the risk.
  - **HMAC-SHA-1 / HMAC-MD5** (primitive `mac` or `kdf`) are **ACCEPTABLE at low severity**, not BROKEN. HMAC and key derivation rely on preimage resistance, which those hashes still have; it's collisions that are broken. This is the plan's correction #2 (don't overstate). The detectors record the primitive precisely for this, for example a cipher suite's SHA-1 as `mac`, and `ssh-rsa`'s SHA-1 as `hash`, because it's a signature hash.
  - **TLS/SSL versions:** SSLv2/SSLv3 are BROKEN and **critical** (DROWN, POODLE; prohibited by RFC 6176/7568). TLS 1.0/1.1 are BROKEN but **high**, a deliberate step down from the plan's "BROKEN → critical": RFC 8996 deprecates them, but the known attacks are mitigated in current stacks, so they're not an emergency the way SSLv3 is. TLS 1.2/1.3 are ACCEPTABLE; their key exchange is rated by the cipher and group findings.
  - **Quantum-vulnerable of unknown use** (an import of `crypto/rsa`, a certificate's RSA key) is rated **high**, like key exchange, not medium like signatures. Harvest-now-decrypt-later applies to anything that might encrypt or transport keys, and TLS 1.2 RSA certificates do exactly that. Only a finding known to be a signature gets medium.
  - **AES of unknown key size** is UNKNOWN/low with a "make sure it's 256-bit" recommendation. Rating it WEAKENED would accuse every `crypto/aes` import, and rating it ACCEPTABLE would hide AES-128. **AES-192** is ACCEPTABLE (≈96-bit strength under Grover). **ChaCha20** is ACCEPTABLE (256-bit keys).
  - **sntrup761** is QUANTUM_SAFE, with a reason that says it's not NIST-standardised. **MD2/MD4** are BROKEN like MD5. **SHA-224** is ACCEPTABLE.
  - **Unknown algorithm** (crypto toolkits, undecodable material) is UNKNOWN/low with "check which algorithms it is used with".
- **Severity: `info`** is added below the plan's four levels for ACCEPTABLE and QUANTUM_SAFE, so every finding has a severity, and `--fail-on low` (Phase 5) won't fail on AES-256.
- **Known limitation, hybrids:** `X25519MLKEM768` reports X25519 and ML-KEM separately, and the X25519 half is rated high. In a hybrid the X25519 half isn't a risk, but on most real lines (`X25519MLKEM768:X25519`, `sntrup761x25519-sha512,curve25519-sha256`) plain X25519 is also offered as a fallback, and the crawler's merge folds the two into one finding. Telling them apart needs a "hybrid" flag set by the detector. *Open:* add it when the CBOM reporter needs hybrid components (CycloneDX models them as a combiner).

### `type Status` / `type Severity` / `func (Severity) Rank() int`
Typed strings, so JSON/SARIF output can use them as they are, and a typo is a compile error. `Rank` gives the order (critical 5 … info 1, 0 for anything unknown) for sorting and for the Phase 5 `--fail-on` threshold.

### `type Result`
`NISTLevel` is CycloneDX's `nistQuantumSecurityLevel`. It's filled **only where NIST defines a category by reference**: key search on AES-128/192/256 (categories 1/3/5), collisions on SHA-256/384 (2/4), and the ML-KEM (512/768/1024 → 1/3/5) and ML-DSA (44/65/87 → 2/3/5) parameter sets. Everything else is 0, rather than an invented number (SHA-512, SHA-3, ChaCha20, SLH-DSA without a parameter set).

### Constants `recKEM`, `recSignature`, `recPublicKey`, `recHash`, `recCipher`, `recTLS`, `recKey`
Recommendation texts shared by several rules, so the same advice is worded the same way everywhere. They name the FIPS standards (203/204/205) and the hybrid TLS group, as the plan's matrix does.

### `func algorithm(f)` / `func quantumVulnerable(f)` / `func shortKey(f, minBits)` / `func protocol(v)` / `func pqcLevel(param)` / `var brokenCipher`
One switch over `rules.Algorithms`, where each case states its own reason. `quantumVulnerable` splits by primitive: key exchange, signature, or unknown (the conservative default). `shortKey` reuses `quantumVulnerable`'s recommendation, since the fix for RSA-1024 is the same migration. `brokenCipher` holds one specific reason per broken cipher (DES brute force, Sweet32, RC4 biases), not a generic "broken".

### Tests: `classify_test.go`
- **`TestClassify`:** one case per row of the plan's matrix, then one per gap above. **`TestPrivateKeys`** (critical whatever the algorithm; public keys aren't critical), **`TestProtocols`**, **`TestDependenciesAreLow`**.
- **`TestEveryAlgorithmIsRated`** loops over `rules.Algorithms`, so adding an algorithm without a rating fails the build. That is the check the closed algorithm set was designed for (see `rules.Algorithms`).
- **`TestResultsAreComplete`** sweeps algorithms × primitives × sizes × ECB: every rating has a reason, every rating of medium or above has a recommendation, and every severity has a rank.
- **Checked on Go's source tree:** 125 critical findings, all of them really broken today (SHA-1/MD5/DES/RC4 imports, 3DES, SHA-1- and MD5-signed test certificates, RSA keys under 2048 bits generated in tests, 1024-bit DSA certificates, committed test keys). High findings are mostly the RSA keys of 413 test certificates, plus X25519 and ECDH use.

---

## `pkg/cbom/types.go` (Phase 4)

The CycloneDX 1.6 types for a CBOM. **Public** (`pkg/`, not `internal/`), as the plan says, so the backend can decode exactly what the CLI writes.

- **Written from the official schema, not the plan's sketch.** I read `bom-1.6.schema.json` field by field (the plan's correction #1 was that its first draft wasn't valid CycloneDX). Differences from the plan's draft that the schema forced:
  - `mode` is a lower-case enum without XTS/OCB/EAX/SIV (see `cdxMode`).
  - `primitive` has `unknown`.
  - `nistQuantumSecurityLevel` is 0–6.
  - `tools` uses the 1.5+ object form `{components: [...]}`.
- Added beyond the plan:
  - `CertificateProperties` (subject, issuer, validity, `subjectPublicKeyRef`, `signatureAlgorithmRef`)
  - `RelatedCryptoMaterialProperties` (`type`, `state`, `algorithmRef`, `size`)
  - `ProtocolProperties` (`type`, `version`)
  - `Component.PURL`
  - `Dependency.Provides` (CycloneDX 1.6's way for a library to "provide" a crypto asset)
- **Only what ShorStop writes is modelled.** The full schema has hundreds of fields; types that list them all would be bigger and suggest support that doesn't exist. The schema forbids unknown fields (`additionalProperties: false`), which is one more reason not to invent any.
- `NISTQuantumSecurityLevel` has no `omitempty`: 0 is meaningful ("not quantum-safe"), as in the plan's type.

## `internal/report/cbom.go` (Phase 4)

### `type CBOMOptions` / `func CBOM(fs, opts) *cbom.BOM`
- **Grouping** (the plan: "group findings by algorithm+parameters into one component with many occurrences"):
  - **one component per distinct algorithm** (name, size, mode, primitive)
  - **per certificate** (subject, issuer, validity, key)
  - **per public-key kind**
  - **per enabled protocol version**
  - **per library** (purl without version)
  - Each place it was seen is an `evidence.occurrences` entry. Go's source tree (2,349 findings) becomes a 1.3 MB CBOM.
- **Committed private keys are not grouped:** each is its own component, with `state: "compromised"`, CycloneDX's own word for a key anyone with the repository now holds. Two keys of the same type are two secrets to rotate.
- **Readable, stable bom-refs** (`crypto:algorithm:RSA-2048:unknown`, `crypto:protocol:tls:TLSv1.0`, `pkg:npm/node-rsa`), derived from the asset, never from scan order, so the backend can diff two scans by ref (the plan's requirement). *Option rejected:* hashing everything, as the plan suggested. Readable refs are just as stable and can be debugged by eye. Hashes are used only where the identity is long or private: certificates (subject, issuer, dates) and private keys (file and line).
- **Deterministic output** for given options: components sorted by ref, occurrences by location, rule lists sorted. `TestCBOMIsDeterministic` reverses the findings and requires byte-identical output.
- `metadata.component` is the scanned project (`bom-ref: project`), and `dependencies` says the project depends on each library, and what each library provides.

### `func WriteCBOM(w, bom)` / `func NewSerialNumber()`
Indented JSON, with HTML escaping off (snippets keep `<`, `>` and `&` readable). The serial number is a version-4 UUID from `crypto/rand`, built by hand (10 lines) rather than with a UUID dependency.

### `type builder` / `type entry` / `func (b *builder) get` / `func (e *entry) seen` / `func (e *entry) component`
- **Data structures:** `map[bom-ref]*entry` accumulates components, and `map[library ref][]algorithm ref` holds the provides links. Each entry keeps its occurrences, rule IDs, highest confidence and rating, and becomes a `cbom.Component` at the end.
- **Rating properties**, in the plan's `shorstop:*` namespace: `status`, `severity`, `reason`, `recommendation`, `confidence` (the highest among occurrences), `rules` (every rule ID that found it, for traceability back to `rules.yaml`), and `expired` on certificates.
- An occurrence's `additionalContext` is `rule-id: snippet`, so a reader of the CBOM sees *why* each place counts, without opening the source. Snippets never contain key material (the detectors guarantee that).
- When one ref gets findings with different ratings, the worst one wins (`get`).

### `func (b *builder) algorithm(f, evidence)`
- Builds the algorithm component: `primitive` (empty → `unknown`), `parameterSetIdentifier` (the named parameter set, otherwise the key size), `mode` (`cdxMode`), `classicalSecurityLevel` and `nistQuantumSecurityLevel` (from `classify`).
- **The algorithm is rated on its own**, with its finding's context stripped (no PURL, no private-key flag), so an algorithm's rating doesn't change depending on which finding created it. The context is rated on the library and key components.
- `evidence` is false when the algorithm is only *referenced*: by a library that provides it, by a key's `algorithmRef`, or by a certificate's signature. A library in package.json isn't evidence that the code calls RSA.

### `type locKey` / `type certSig` / `func certSignatures(fs)` / `func (b *builder) certificate(f, sig)`
- A certificate's three findings share a file and line (the crawler sorts by file, line, rule ID), so they're joined into one component. `subjectPublicKeyRef` points at the key's algorithm, `signatureAlgorithmRef` at the signer's algorithm, and **the certificate is rated by its weakest part** (key, signer, or signature hash). The first version ignored the hash, and a SHA-1-signed certificate came out "high". `TestCBOMSemantics` caught it before it shipped.
- **When a location has several certificates** (a DER file of concatenated certificates is all line 0), signatures aren't linked, because which belongs to which can't be told. The certificates are still listed.
- The same certificate in several files is one component (identity = subject, issuer, validity, key). `shorstop:expired` is set when `notValidAfter` is before the scan time, which is why the scan time is an option rather than `time.Now()` inside the function: it keeps tests deterministic.

### `func (b *builder) material(f)` / `func (b *builder) protocol(f)` / `func (b *builder) library(f)`
- **Keys:** `relatedCryptoMaterialProperties.type` = private-key/public-key, `algorithmRef`, `size`.
- **Protocols:** `protocolProperties.type` is `tls` for SSL too (CycloneDX has no separate SSL type), and the version is spelled `1.2` / `3.0`, while the component name keeps the readable `TLSv1.2` / `SSLv3`.
- **Libraries:** a `library` component keyed by the purl *without* version, so the manifest's range and the lockfile's exact version are one library with two occurrences, and the exact version fills `version`/`purl`. A rule that names an algorithm adds it to the library's `provides`.

### `func purlParts` / `func algName` / `func cdxMode` / `func classicalLevel` / `func shortHash`
- `algName`: `RSA-2048`, `AES-128-GCM`, `ML-KEM-768`, `Ed25519` (EdDSA-255), `X25519`/`DES`/`3DES` without their only size.
- `cdxMode`: maps to the schema's enum; XTS/OCB/EAX/SIV become `other` rather than being dropped.
- `classicalLevel`: only where it's well defined: AES/ChaCha20/3DES by key size, RSA/DSA/DH by NIST SP 800-57 Part 1 Table 2 (1024 → 80 … 15360 → 256), elliptic curves at half their size, SHA-2 by collision resistance. Broken or unknown algorithms are omitted rather than given an invented number.
- `shortHash`: the first 8 bytes of SHA-256, in hex. That's enough to keep refs unique among the certificates and keys of one project.

### Tests: `cbom_test.go`
- **Schema validation is the plan's acceptance test.** The official CycloneDX 1.6 schema (plus the SPDX and JSF schemas it references) is committed in `testdata/cyclonedx/`, downloaded once from the CycloneDX repository's `1.6` tag. It's compiled **offline** by registering each file under its `$id`, with format assertions on (`date-time`, …). Validator: **`github.com/santhosh-tekuri/jsonschema/v6`** (project-owner decision, 2026-11-02). It's a **test-only** dependency: `go version -m bin/shorstop` lists only `go.yaml.in/yaml/v3` and `golang.org/x/crypto`.
- **`TestCBOMOfAllFixturesIsValid`** scans every fixture in the repository with all five detectors, renders the CBOM, validates it, and checks that every asset type is present. Any finding any detector can produce is therefore checked against the schema. The 1.3 MB CBOM of Go's source tree was also validated once by hand.
- **`TestCBOMGolden`** (`testdata/report/cbom.golden.json`): exact output for one finding of each kind, so changes to the CBOM's shape show up as diffs. **`TestCBOMIsDeterministic`**, **`TestCBOMSemantics`** (grouping, compromised keys, certificate refs and rating, library version and provides, protocol version, mode mapping, NIST level), and **`TestHelpers`**.

## `internal/detect/detect.go` — `Suppression` (Phase 5)
`Finding.Suppression *Suppression{Reason, Line}`, set by the crawler when a `shorstop:ignore` comment covers the finding. It's a pointer, so the common case (not suppressed) costs 8 bytes, and the reason and the comment's line travel with the finding for reports that want to show *why* something was accepted. The finding isn't deleted, because the CBOM keeps it.

## `internal/suppress/suppress.go` (Phase 5)

### Syntax: `shorstop:ignore [rule-id[,rule-id…]] [reason="…"]`
- The plan's form (`// shorstop:ignore go-rsa-import reason="legacy partner API"`), **in any comment style**. The marker is found as text, so `//`, `#`, `--`, `;`, `/* */` and `<!-- -->` all work without a per-language comment parser. *Tradeoff:* the marker inside a string literal also counts. That's harmless in practice, because writing it means someone asked to suppress.
- **Scope:** the marker's own line, and **the next line when the marker's line is only a comment** (`commentOnly`: the line starts with a comment token). A trailing marker on a line of code therefore doesn't silently also hide the next line's findings; the test has that case.
- **Rule IDs are comma-separated; none means every rule on the line**, like `//nolint` and `# noqa`. A reason is optional (`reason="…"`, `'…'` or a bare word) but recorded.
- `shorstop:ignored` or `shorstop:ignore-foo` aren't markers: the marker must be followed by whitespace or end the line.

### `type marker` / `func parse(line, n)` / `func commentOnly(line)` / `func Apply(content, fs)`
- `Apply` costs **one `bytes.Contains` for files without the marker** (nearly all), and only then splits lines. **Data structure:** `map[covered line][]marker`, built once per file, so each finding is one map lookup.
- **Binary files (line 0) are never suppressed**: there's no line to put a comment on.
- The first matching marker wins, and its reason and line are recorded.

## `internal/rules/rules.go` — `Pack.Source`, `Merge`, `Without` (added with `.shorstop.yaml`)
- **`Pack.Source`** is the file a pack came from (set by `Parse`), so a duplicate-ID error names both files: `rule "x" is defined in both rules.yaml and .shorstop/rules.yaml`.
- **`func Merge(packs...)`** concatenates packs in order and **rejects duplicate IDs** rather than letting a later pack override an earlier one (see `loadRules`). Rules are copied by value. Their compiled regexes are pointers, so nothing is recompiled, and `ForDetector` hands out pointers into the merged pack.
- **`func (p *Pack) Without(ids)`** returns a filtered copy; the built-in pack is shared process-wide (`Builtin`) and must not be modified.

## `internal/settings/settings.go` (Phase 5)

### `type Settings` / `const FileName = ".shorstop.yaml"`
- The plan's config file: **`exclude`, `fail-on`, `baseline`, `max-file-size`, `rules`** (custom rule files), and **`disable`**, which isn't in the plan: rule IDs to turn off for the whole repository. That's the repository-wide counterpart to `shorstop:ignore` comments, for a rule that doesn't fit a codebase at all. Keys are kebab-case like the flags, so `fail-on` reads the same in both places.
- **Output options (`format`, `output`) are deliberately not configurable**: they describe one run (a CI step writes SARIF, a developer reads the table), not the repository.
- Package name `settings`, not `config`, because `config` is already the configuration-file *detector*.

### `func Find(dir)` / `func Load(path)` / `func Parse(data)` / `func resolve(base, p)`
- `Find` looks only at the scan root. Walking up parent directories like git does would make a scan of `src/` pick up a surprise config from far above it.
- **Strict decoding** (`KnownFields`), as for rule files: `fail_on: high` is an error rather than a silently ignored key. An empty file is a valid, empty config. `version` may be left out (it defaults to 1); any other version is rejected.
- **Paths are relative to the config file**, not the working directory (`resolve`), so `shorstop scan repo/` and `cd repo && shorstop` read the same baseline and rule files. Absolute paths are kept.

## `internal/baseline/baseline.go` (Phase 5)

### `type Baseline` / `func Load(path)` / `func Parse(data)`
- The plan's `--baseline`: adopt ShorStop without fixing everything first. **Format:** a previous **SARIF** (`--format sarif`) *or* **CBOM** (`--format json`) output from ShorStop, detected from the content. The plan named `cbom.json`; SARIF is accepted too, because that's the file CI pipelines already keep for GitHub.
- **Matching is by fingerprint** (`report.Fingerprint`, without the line number), so moving code doesn't make known findings new. SARIF stores it in `partialFingerprints["shorstop/v1"]`. The CBOM now stores it as each occurrence's `bom-ref`, `shorstop:fp:<fingerprint>#<n>` (see `cbom.go`).
- **Data structure:** `map[fingerprint]count`, a multiset rather than a set: if the baseline had one `crypto/md5` import in a file and the code now has two identical ones, one of them is new.
- **Format detection:** the CBOM has `bomFormat: "CycloneDX"`, SARIF has `version: "2.1.0"`. `version` is a string in SARIF and a number in CycloneDX, so it's probed as raw JSON. The first version probed it as a string and failed on every CBOM; `TestRoundTrip` caught it. Anything else is an error, not an empty baseline, because a mistyped file would otherwise silently baseline nothing.

### `func (b *Baseline) Split(fs)` / `func (b *Baseline) Len()`
Walks the findings in order, using up each baseline entry once (on a copy of the counts, so a `Baseline` can be reused). It returns new and known findings in their original order. That's deterministic, because the crawler sorts findings.

## `internal/report` — fingerprints shared by SARIF, the CBOM and baselines (Phase 5)
- **`Fingerprint` and `FingerprintKey` are exported**, so `internal/baseline` computes exactly the identity the reports wrote.
- **CBOM occurrences now carry `bom-ref: shorstop:fp:<fingerprint>#<n>`** (`cbom.Occurrence.BOMRef`). *Options:* (a) reconstruct the fingerprint from component fields when reading a CBOM baseline, which is fragile because the component name isn't the raw algorithm; (b) store the fingerprint on the occurrence. **Chose (b):** CycloneDX allows a `bom-ref` on occurrences, and it costs one field.
  - `bom-ref`s must be unique, but identical findings share a fingerprint, so occurrences are **numbered `#1`, `#2`, … after sorting**, which keeps the numbering independent of scan order (`TestCBOMIsDeterministic` still holds).
  - **Each finding's fingerprint appears on exactly one occurrence**, so a CBOM baseline counts every finding once. The one finding that lands on two components, a certificate's key (the certificate and its key algorithm), records the fingerprint only on the certificate (`entry.see(f, false)` for the algorithm). On the golden findings, 12 findings give 12 fingerprint refs, all unique.

## `internal/report/group.go` (added with the terminal and Markdown reporters)

### `type rated` / `type assetGroup` / `var severities` / `func groupFindings(fs, includeInfo)`
- Both human-readable reports are grouped **by severity, then by asset and rating**: the 22 places MD5 is used are one entry with 22 locations, not 22 rows that each repeat the reason and the advice. Groups are ordered most severe first, then most frequent (the biggest problem of a severity first), then by name.
- **Data structures:** a `map[key]index` into a `[]assetGroup` slice, which keeps first-seen order for the stable sort. The key is severity + label + status + reason, so two RSA-2048 findings with different ratings (an import vs. a committed key) stay apart.
- `info` (acceptable, quantum-safe) is left out by default, for the same reason as in SARIF. Those findings still show in the summary count.

### `func groupLabel(f)`
`assetLabel` without a library's version, so `pkg:npm/node-rsa` (package.json range) and `pkg:npm/node-rsa@1.1.1` (lockfile) are one library, as in the CBOM. The first version grouped them apart, and the golden review caught it. Per-file rows and SARIF messages keep the exact version.

### `type Counts` / `func Count(fs)` / `func (Counts) String()`
Findings by severity plus the quantum-safe count, and the plan's summary text (`· 12 critical · 48 high · 3 quantum-safe`). This was `ratings()` in `main`; it moved here so the terminal summary and the Markdown header count the same way.

### `func loc(f)`
`path:line`, or just `path` for binary files.

## `internal/report/table.go` (Phase 4, the default output)

### `type TableOptions` / `func WriteTable(w, fs, opts)`
- The plan's "coloured table grouped by severity". Each severity heading carries its count, and under it each asset shows its status, number of places, **reason, recommendation (→)**, then its locations with the rule that found each.
- **At most 5 locations per asset** (`MaxLocations`), then "… and N more (all are in --format json or sarif)". A terminal screen is for deciding what to fix first; the full lists are in the machine formats. On Go's source tree an unlimited list would be thousands of lines.
- Locations are aligned with `text/tabwriter`. Colour codes are kept out of the tabwriter columns, because escape sequences would count toward column width.
- **The summary line is the caller's job**, since it needs the crawler's skip statistics, which the reporter doesn't have.
- The output is built in a `strings.Builder` and written once, so a slow terminal gets one write rather than thousands.

### ANSI constants / `var severityColor`
Bold red for critical, red for high, yellow for medium, cyan for low, green for the recommendation arrow and for info. These are the plain 16-colour codes every terminal supports.

### `func clean(s)`
**Control characters in file paths and names are replaced with `?`.** A repository can contain a file named `\x1b[2J…`, and printing it raw would let a scanned repository clear or rewrite the user's terminal (terminal escape injection). C1 controls (0x80–0x9F) are included. `TestUntrustedText` checks it.

## `internal/report/markdown.go` (Phase 4)

### `type MarkdownOptions` / `func WriteMarkdown(w, fs, opts)`
- The plan's "summary table plus per-file sections; usable as a PR comment or audit attachment". The header line has the counts; the **summary table** has one row per asset and rating (severity, asset, status, places, what to do); then **one collapsible `<details>` section per file** (line, asset, status, severity, rule), so a long report stays short in a PR until someone opens a file.
- **Size budget, not a row cap.** GitHub rejects comments over 65,536 characters. The first version capped rows at 500, and Go's source tree still produced 71 KB, because rows vary in length, so measuring showed the cap was wrong. Now `MaxBytes` (default 60,000, leaving room for text around the report) is checked **per whole file section**, and the report ends with "N more files not shown …". The budget counts bytes, which are never fewer than characters, so it's safe for the character limit. A section is never cut in the middle, since half a table renders as garbage. The summary table is never cut. Go's source tree now gives 59,650 bytes.
- An all-clear scan says "Nothing needs attention." under its counts, which is useful as a PR comment too.

### `func mdCell(s)` / `func htmlEscape(s)`
Paths, package names and labels come from the scanned repository, so they're **untrusted**. Inside table cells, `|` (ends the cell), `` ` ``, `*`, `_`, `[`, `]` (formatting and links) are escaped, and `<`, `>`, `&` become HTML entities. A file named `a|b<script>.go` can't break the table or inject markup into a PR comment. Snippets are deliberately not included in Markdown: they're the least trusted text and add little that the line number doesn't.

### Tests: `text_test.go`
`TestTableGolden` (`testdata/report/table.golden.txt`) and `TestMarkdownGolden` (`markdown.golden.md`) pin the exact output for the shared golden findings. **`TestTableColorAndLimit`** (coloured header, 3 places then "… and 5 more"), **`TestUntrustedText`** (no escape sequence reaches the terminal, no markup reaches the Markdown), **`TestMarkdownLimits`** (whole sections within the budget, the note, the uncut summary, the all-clear text), and **`TestCountString`**. In `cmd/shorstop`: **`TestRunTableAndMarkdown`** (the default table to a buffer has no colour) and **`TestUseColor`** (pipes and buffers get no colour; a real terminal gets colour unless `NO_COLOR` is set).

**This completes Phase 4.** All four formats render from the same `[]Finding` through `classify.Classify`, and the CBOM passes schema validation (and SARIF passes its schema too).

## `internal/report/sarif.go` (Phase 4)

SARIF 2.1.0, the plan's "highest-value format for adoption": GitHub code scanning reads it through `github/codeql-action/upload-sarif` and shows findings inline on pull requests.

### `type Catalog` / `func NewCatalog(pack, builtins...)` and `cert.RuleDescriptions` / `config.RuleDescriptions`
- SARIF lists every rule it reports, with a description. Rule-pack rules already carry `description`. The cert and config detectors' built-in IDs now have a `RuleDescriptions` map next to their constants, so adding an ID and its description happens in one place. This closes the "registry of rule IDs" item left open since the cert detector.
- `Catalog` is a plain `map[id]description`: lookups are all SARIF needs. A missing ID falls back to "ShorStop rule x." rather than failing the report, and **`TestSARIFOfAllFixturesIsValid` fails if any ID emitted on the fixtures lacks a description**, so the fallback is never reached in practice.

### `type SARIFOptions` / `IncludeInfo`
**`info` findings (acceptable, quantum-safe) are left out by default.** SARIF results become code-scanning *alerts*, and an alert for AES-256 or ML-KEM is noise that teaches people to ignore the tool. The CBOM is the complete inventory, and SARIF is the to-do list. `IncludeInfo` exists for tests and future use; Go's source tree gives 1,282 alerts out of 2,349 findings.

### SARIF types (`sarifLog` … `sarifResultProps`)
Unexported and local to the reporter: only ShorStop writes them, and nothing decodes them (unlike the CBOM, whose types are public for the backend). Only the fields used are modelled.

### `var securityScore` / `func sarifLevel(sev)`
- **`security-severity`** is the rule property GitHub reads to label security alerts Critical (≥ 9.0), High (7.0–8.9), Medium (4.0–6.9) and Low (0.1–3.9). Our severities map to 9.5 / 8.0 / 5.5 / 3.0, the middle of each band, so GitHub's label matches ours.
- **`level`:** critical and high → `error`, medium → `warning`, low → `note`.

### `func WriteSARIF(w, fs, opts)`
- **One rule can produce results of different severities** (`go-rsa-generate-key` finds RSA-1024, critical, and RSA-4096, high), but SARIF and GitHub take `security-severity` from the *rule*. *Options:* (a) split rules per severity (`go-rsa-generate-key/critical`); (b) give the rule its **worst** severity among this run's results, and give each result its own `level` and `shorstop:severity`.
  - **v0.1.0 shipped (b). v0.1.1 switches to (a)** (`sarifRuleID`). The v0.1.0 demo repo (`shorstophq/shorstop-demo`) showed 6 of 20 alerts at the wrong severity in the Security tab. One nginx `ssl_ciphers` line enables 3DES (critical), so its HMAC-SHA-1 (low), AES-128 (medium) and RSA/ECDH key exchange (high) alerts were all labelled Critical, and so was an RSA-2048 key next to an RSA-1024 one. Real cipher strings almost always mix strong and weak algorithms, and a "Critical" label next to HMAC-SHA-1 teaches people to stop trusting the labels.
  - Reasons given against (a) earlier, rechecked: suppressions (`shorstop:ignore <rule>`) are written in the source with the detector's rule ID and never see the SARIF ID; the link to `rules.yaml` is kept as the ID's prefix and as the rule's `shorstop:rule` property; the catalog description and help are looked up by that plain ID.
  - **The suffix is always added**, even for a rule that only finds one severity, so a rule's ID never depends on what else the scan found.
  - **Baselines are unaffected:** they match on `partialFingerprints`, which use the detector rule ID, not the SARIF one. A v0.1.0 SARIF used as `--baseline` still hides every known finding (checked on the demo repo).
  - **Cost:** GitHub keys alerts by rule ID and fingerprint, so after the upgrade existing alerts close once and reopen under the new IDs, and earlier dismissals are lost. Acceptable while the only user is our own demo repo.
  - A severity-split rule's results all share a severity, so its `defaultConfiguration.level`, `security-severity` and recommendation in `help` come from its first result.
- **Only rules with results are listed**, sorted by ID; `ruleIndex` points into that list.
- Results are in file, line, rule order, so the output is stable for diffs. An empty scan still writes `"results": []` and `"rules": []`, because GitHub rejects a log without them.
- Each result's properties carry `shorstop:status`, `severity`, `confidence`, `asset` and `purl`, for anyone post-processing the log.

### `func message(f, r)` / `func assetLabel(f)`
The alert text is what a reviewer reads on a pull request, so it says everything in one line: **what** (`RSA-2048`, `TLSv1.0`, `RSA-2048 private key`, `pkg:npm/node-forge`), **the rating** (`BROKEN, critical`), **why**, and **what to do**. For example: `MD5 (BROKEN, critical). MD5 has practical collision attacks: … Use SHA-256 or stronger (SHA-384, SHA-3).`

### `func location(f)`
- The path is relative to `%SRCROOT%`, which code scanning resolves against the repository checkout. Each path segment is URI-escaped (`my ca.der` → `my%20ca.der`), as the schema's `uri` format requires.
- **Binary files (line 0) get no region**: SARIF allows a file-level location, and a fake line 1 would point at bytes.

### `func fingerprint(f)`
- `partialFingerprints["shorstop/v1"]` = SHA-256 of rule, file, what was found and the trimmed source line, **without the line number**. GitHub uses fingerprints to track an alert across commits, so an alert keeps its identity, and its dismissed state, when code above it moves. *Option rejected:* letting the upload action compute GitHub's own line-hash fingerprints. Those work only on GitHub, and ours also serve the Phase 5 baselines.
- The key is versioned (`/v1`), so the recipe can change later without colliding with old fingerprints.
- *Tradeoff:* two identical findings in one file (the same import twice) share a fingerprint. GitHub then treats them as one alert, which is acceptable for identical lines.

### Tests: `sarif_test.go`
- **Validation against the OASIS-published SARIF 2.1.0 schema** (errata 01, `testdata/sarif/`, draft-04, compiled offline with the same validator as the CBOM). Like the CBOM test, **`TestSARIFOfAllFixturesIsValid`** renders every finding from every fixture, and it also checks every emitted rule ID has a description.
- **`TestSARIFGolden`** (`testdata/report/sarif.golden.json`), **`TestSARIFSemantics`** (info left out, one SARIF rule per severity with its own `security-severity`, `shorstop:rule` and catalog description, `ruleIndex` correct, URI escaping, no region for binary files), **`TestFingerprintIgnoresLine`**, and **`TestSARIFEmpty`**.

---

## `cmd/shorstop/main.go` — `func detectors() ([]detect.Detector, error)`
Builds every detector from `rules.Builtin()`, in one place, so `run` stays about flags and output. A broken embedded pack exits with code 2 and `loading rules: …`. `TestBuiltinLoads` makes that unreachable for shipped builds, but the path exists for `--rules` later. Order: goast, cert, config, deps, regex. **Order matters for duplicates:** when `detect.Dedupe` finds two identical findings, the earlier detector's is kept. The parsing detectors come before regex, so the more precise rule ID survives.

---

## `internal/rules/rules.go` + `rules.yaml`

The rule pack: data that tells rule-driven detectors (`goast`, `regex`) what to look for. The schema was pulled forward from Phase 3 so detectors are built against it from the start rather than refactored later.

### YAML library: `go.yaml.in/yaml/v3` (project-owner decision, 2026-11-02)
- *Options:* `go.yaml.in/yaml/v3`, `goccy/go-yaml`, JSON with the stdlib only.
- **Chose `go.yaml.in/yaml/v3`:** it's the maintained continuation of `gopkg.in/yaml.v3`, the most widely used Go YAML library, and it supports strict decoding (`KnownFields`). It's the project's first non-test dependency.
- *Tradeoff:* the parser runs on user-supplied `--rules` files later, so it is attack surface. The files are small and local, and the risk is accepted. JSON would avoid the dependency, but rule authors could no longer write comments.

### File shape: `version: 1` + `rules: [...]`
- The plan's example was a bare list. **Wrapping it adds a format version**, so a future build can reject or migrate old files instead of misreading them. That's what the plan's "keep the format stable and versioned" asks for.
- Only `FormatVersion = 1` is accepted. v1 isn't frozen until the first release: the `config` and `deps` detectors will add `match` fields.

### Constants `DetectorGoAST`, `DetectorRegex` and `var defaultConfidence`
- Detector names live **in `rules`, not in each detector package**. Detectors import `rules`, never the other way round, so there's no import cycle, and validation can list the valid names.
- Only detectors that actually consume rules are listed. `cert` parses X.509 itself and needs no rules; `config` and `deps` get added together with their `match` fields. A name with no `match` schema would be a rule that can never do anything.
- Default confidence comes from the detector (`goast` → high, `regex` → medium), so most rules don't need to say it; a rule can override it.

### `var Algorithms` / `var Primitives` (closed sets)
- *Options:* free-form strings, or a closed list. **Chose the closed list:** the Phase 3 classifier must map every algorithm to a status, and a closed set means a test can check that it covers every name. A typo like `SHA1` instead of `SHA-1` fails at load time; otherwise it would quietly produce an unclassified finding.
- *Tradeoff:* adding an algorithm means a code change. Custom-rule authors can't invent new ones. That's intended: the classifier couldn't rate an algorithm it doesn't know anyway.
- **Primitive names are CycloneDX 1.6's** (`block-cipher`, `key-agree`, `kem`, …), so the CBOM reporter can copy them through without a mapping table. "Unknown" is an empty string rather than the literal `unknown`, because a rule like `go-rsa-import` really doesn't know whether RSA is used for encryption or signatures.
- Slices rather than maps: they keep a stable order for error messages ("known: …"), and with ~25 entries a linear `slices.Contains` costs nothing at load time.
- `ECC` was added for `crypto/elliptic`, which is curve math under both ECDSA and ECDH, so neither name would be accurate.

### `DetectorDeps`, `var Ecosystems`, `Match.Ecosystem` / `Match.Package` (added with the deps detector)
- **The library list is data** (`detector: deps` rules), like the other rule-driven detectors, so the community can add a library in one YAML line without touching Go. Default confidence is **low**: a dependency says a library is installed, not that, or how, the code uses it. That matches the plan's severity row, "low: dependency-only hints".
- **`algorithm` is optional for deps rules only.** `node-forge` provides RSA, AES, 3DES, MD5 and SHA-1. Naming one would be invented, and naming all would claim usage we can't see. It's set only for single-purpose libraries (`node-rsa` → RSA, `ml-kem` → ML-KEM), so the classifier can still call those quantum-safe or broken. Multi-algorithm toolkits stay unknown, and their description says what they contain.
- **`Ecosystems`** is a closed set of purl types (`cargo`, `composer`, `gem`, `golang`, `maven`, `npm`, `nuget`, `pypi`), so the rule's ecosystem *is* the purl type, with no mapping table.
- **`match.package` may end in `*`, and only there, and only after a separator** (`org.bouncycastle:bcprov-*`). Bouncy Castle ships one artifact per JDK range (`-jdk15on`, `-jdk18on`, …), so exact names would rot. Requiring a separator before the `*` stops `forge*` from matching unrelated names like `forgefoo`. A lone `*` is rejected. *Option rejected:* full globs or regexes, which are more than any ecosystem's naming needs, and easy to write too broadly.
- Each detector's `match` fields are rejected on the others' rules, as before; deps rules also reject `languages` (the ecosystem already says where they apply).

### `var Modes` / `var Languages` (added with the regex detector)
- **`Modes`** is a closed set (ECB, CBC, CTR, GCM, CCM, CFB, OFB, XTS, OCB, EAX, SIV) for the same reason as `Algorithms`: the classifier keys `INSECURE_MODE` off it. A rule's fixed `mode` must be in the set, or loading fails. A captured `(?P<mode>)` value outside it (`MODE_OPENPGP`) becomes an empty mode at scan time, because a source line can say anything and the scan must not fail on it.
- **`Languages`** is a map from language name to extensions, used by the `languages:` rule field. A map because the regex detector inverts it into extension → rule set once at construction. Each extension belongs to one language. **Kotlin and Java are separate languages** that share rules by listing both (`languages: [java, kotlin]`), so a Kotlin-only rule is possible later. `.h` counts as C. C++ headers named `.h` get the C rules only, so C++-specific rules should also list `c` if they target headers.

### `func validKeyword(k) bool` / `const MinKeywordLen = 3`
Keywords must be **printable ASCII and at least 3 bytes**. ASCII means lower-casing never changes a line's length, so the detector can compare in place without allocating a lower-cased copy. Three bytes, because the detector indexes keywords by their first trigram. Printable means a keyword can't contain a newline, so it can never span two lines. *Cost:* no non-ASCII keywords. No crypto API name needs one.

### `var idPattern` (`^[a-z0-9]+(-[a-z0-9]+)*$`)
IDs appear in `// shorstop:ignore <rule-id>`, SARIF rule IDs and baselines, so they're restricted to characters that need no quoting anywhere. The header of `rules.yaml` says IDs are never renamed or reused, because that would silently break users' suppressions.

### `type Pack` / `type Rule` / `type Match`
- **`Match` is one struct holding every detector's fields**, not a per-detector type or an interface. A tagged union in YAML would need a custom `UnmarshalYAML`, and that loses strict decoding (see `Parse`). Instead, `validate` rejects fields that don't belong to the rule's detector, which gives the same safety with plain struct decoding.
- `KeySizeArg` is `*int` because argument 0 is a valid index. A pointer tells "unset" apart from "0".
- `Rule.re` is unexported and filled by `validate`, so **each regex compiles once at load**, as the plan requires. Detectors read it through `Regexp()` and can't replace it.
- `Rule.Confidence` is filled with the detector default during validation, so consumers never handle the empty case.
- **`Rule.Languages`** (regex only) is a top-level rule field, as in the plan's example, not inside `match`, because it says *where* a rule applies, not *what* it matches. Empty means every text file. goast rules reject it, since they're Go-only by definition.
- **`Match.Keywords`** (regex, required): literal words, at least one of which must appear on any line the pattern can match. The detector runs a pattern only on lines containing one, which makes the scan fast with ~100 rules. *Option rejected:* deriving keywords from the pattern automatically (RE2's `syntax` package exposes literal prefixes). That only works for patterns that start with a literal, and it would hide from rule authors why a rule never fires. Explicit keywords are visible, and `examples` check them.
- **`Match.Examples`** (regex, required): lines the pattern must match, checked **every time the pack loads**. Each must also contain a keyword (otherwise the prefilter would skip it in a real scan), and any `bits`/`mode` capture must parse. This makes every rule carry its own test, which matters most for community-contributed rules (the plan's growth engine). *Cost:* about 100 regex matches at startup, well under a millisecond.
- **Mode uses a `(?P<mode>…)` group** like `bits`, rather than the separate `match.mode_group` field I first proposed: one convention for every capture, and nothing new for rule authors to learn.
- `bitsIdx`/`modeIdx` are cached at load (from `SubexpIndex`), so the hot path doesn't look group names up per match.

### `func (p *Pack) ForDetector(name) []*Rule`
Returns pointers into `p.Rules`, not copies: `Rule` is about 150 bytes and every worker shares one pack. File order is kept so results are deterministic. It's a linear scan, but each detector calls it once at construction, not once per file.

### `var Builtin = sync.OnceValues(...)`
- The embedded file is parsed **once per process**, and the error is cached with the result. Every caller gets the same `*Pack`, and none of them needs to know when it was loaded.
- *Options:* `init()` parsing (a panic at import time would be untestable and would also hit `--version`); a package-level `MustLoad` (same problem); or `OnceValues`. **Chose `OnceValues`:** it's lazy, safe for concurrent use, and returns an error instead of panicking.
- `TestBuiltinLoads` guarantees the shipped file is valid, so at run time the error path only matters for future `--rules` files.

### `type file`
Mirrors the top level of the YAML only. Kept separate from `Pack` so the on-disk shape can change between format versions without changing the API detectors use.

### `func Parse(data, source) (*Pack, error)`
- **Pass 1, strict decode:** `KnownFields(true)` makes an unknown key an error. Without it, `key_sise: 2048` would load fine and quietly do nothing, the worst failure for a security scanner. A second `Decode` must return `io.EOF`, so a stray `---` can't hide a second document that never gets read.
- **Pass 2, node tree, only for line numbers** (`ruleLines`). yaml.v3's `Node.Decode` doesn't carry `KnownFields`, so we can't decode per rule from nodes and stay strict. Parsing twice was the simplest way to get both strict decoding and line numbers, and rule files are a few KB.
- **Collects all errors** (`errors.Join`) instead of stopping at the first, so a custom-rule author fixes everything in one go. Each message starts with `file:line: rule "id":` so editors can jump to the line.
- Duplicate-ID detection uses `map[string]int` (id → first line), so the message points at both places. Empty IDs are skipped there because "missing id" already reports them.
- Rejects version ≠ 1 and empty rule lists before validating rules: with no rules, a scan would report "no findings", which is a false all-clear.

### `func ruleLines(data) []int`
Walks the document's top mapping to the `rules` key, then reads `Line` from each sequence element. It returns nil on any surprise, and `Parse` then reports line 0 rather than failing: line numbers are a convenience, and pass 1 already decided validity.

### `func (r *Rule) validate() []error`
- Checks the shared fields, then the detector-specific `match` fields: goast needs `import`, and `key_size_arg` needs `call`; regex needs `pattern`, which must compile as RE2. Fields belonging to the other detector are rejected, so a rule can't look like it does something it doesn't.
- `key_size` together with `key_size_arg` or a `(?P<bits>)` group is rejected, and so is `mode` together with a `(?P<mode>)` group: two sources for one value would be ambiguous.
- Regex rules also need valid `keywords` and `examples`, known `languages`, and a pattern that **doesn't match the empty string** (`a*` would match every line of every file).
- **Mutates the rule** (default confidence, lower-cased keywords, compiled regex, group indexes). It's called once, on a value `Parse` owns, before the pack is returned, so nothing else can see a half-filled rule.
- **Regex engine is Go's RE2**: linear time, so a user-supplied pattern can't cause catastrophic backtracking during a scan. The cost is no lookarounds or backreferences in rule patterns.

### `func (r *Rule) hasKeyword(lower) bool`
Validation only: checks that an example contains a keyword. A linear `strings.Contains` per keyword is fine at load time; the detector has its own indexed version.

### `const maxKeyBits` / `type LineMatch` / `func (r *Rule) MatchAll(line) []LineMatch`
- **`MatchAll` is the only code that reads a pattern's captures**, and both example validation and the detector call it. "Examples pass" therefore means "the detector reads these lines the same way". *Option rejected:* letting the detector read capture groups itself, which would be a second implementation that could drift from what validation checked.
- **Every match on the line, de-duplicated** (`FindAllSubmatchIndex`, then `slices.Contains` on the small `[]LineMatch`). The first version took only the first match, and a review of the golden files caught it dropping `aes128-ctr` after `aes256-gcm` on one `Ciphers` line: a real CBOM entry, lost. Identical results on one line are reported once.
- `LineMatch` is a small comparable struct (`KeySize`, `Mode`), so de-duplication is a plain `==`.
- **Bits must be 1 to 65,536** (`maxKeyBits`); anything else is "not a key size" and leaves the rule's own `key_size` in place. Mode is upper-cased and must be in `Modes`.
- `matchAll`/`captures` also return a description of each unusable capture, which only validation uses: an example whose `bits` group captures `0` is a broken rule, while a real line that does the same is just an unknown size.

### `func group(line, loc, i) (string, bool)`
Returns subexpression *i*'s text from a `FindAllSubmatchIndex` location, if it took part in the match. Optional groups (`(?:…(?P<bits>\d+))?`) are common in the pack, because a key size on the next line is still a finding, just without a size.

### `rules.yaml` content
- **22 `goast` rules:** every crypto import the plan lists, plus calls where the call adds information. `rsa.GenerateKey` takes its key size from argument 1. `des.NewTripleDESCipher` means 3DES, not DES. `ecdh.X25519` names the curve.
- `crypto/mlkem` and `crypto/mldsa` (both in Go 1.27's standard library; checked with `go list std`) are included so reports show quantum-safe progress.
- SHA-256/512/SHA-3 are included even though they're acceptable: a CBOM is an inventory, not just a list of problems.
- **59 `deps` rules** (added with the deps detector), one per library: npm 15, PyPI 11, Maven 6, Go 5, Composer 4, Cargo 11, RubyGems 3, NuGet 4. They cover the plan's list (`node-forge`, `jsrsasign`, `pycryptodome`, Bouncy Castle, `phpseclib`) and the common libraries for each language the regex detector covers, including **post-quantum libraries** (`@noble/post-quantum`, `liboqs-python`, `kyber-py`, CIRCL, `ml-kem`), so dependency findings show progress too. Written as one-line flow mappings, since each rule is just an ID, a description and a package.
- **129 `regex` rules** (21 generic, 108 language-specific; 116 added with the regex detector, 13 shell-command rules with the config detector):
  - 8 **generic** rules with no `languages`, run on every text file: cipher names such as `aes-256-cbc` (bits and mode captured), `RSA-2048`/`rsa:4096`, 3DES and RC4 names, the PQC names `ML-KEM-768`/`ML-DSA-65`, and the hybrid `X25519MLKEM768` TLS group and `mlkem768x25519-sha256` SSH key exchange.
  - **Language rules:** Python (PyCryptodome, pyca/cryptography, hashlib, python-rsa, liboqs), Java/Kotlin (JCA names, Bouncy Castle), JavaScript/TypeScript (Node crypto, Web Crypto, node-forge, jsrsasign), PHP (openssl, md5/sha1, mcrypt, phpseclib), C# (.NET), Ruby (OpenSSL, Digest), C/C++ (OpenSSL), Rust (rsa, dalek, p256, ml-kem crates).
  - **`java-cipher-aes-default`:** `Cipher.getInstance("AES")` is reported as **ECB**, because that is what Java silently uses. It's one of the most common real-world crypto bugs.
  - **AES-ECB rules that can't see the cipher.** `py-cryptography-aes-ecb` requires `algorithms.AES(` and `modes.ECB(` on one line. Its first version guessed "AES" from `modes.ECB(` alone and mislabelled a 3DES-ECB line in the fixtures. `cs-ecb` (`CipherMode.ECB` is normally set on its own line) keeps the guess, at **low** confidence.
  - The Java ML-KEM/ML-DSA rules match only the bare names (`"ML-KEM"`); names with a parameter set are left to the generic rules, so one call isn't reported twice.
  - Generic rules that overlap language rules (`generic-3des` vs `cs-3des` on `TripleDES.Create()`) are de-duplicated by the detector, not by weakening the patterns. See `hit.coveredBy`.
  - Bare TLS suite names in configs (`RC4-SHA`) aren't matched; the config detector parses `ssl_ciphers` lists properly. `DES-CBC3-SHA` is matched, because that name is unambiguous.
  - **`!` guard (added with the config detector):** `generic-3des` and `generic-aes-cipher-string` start with `(?:^|[^!\w])` instead of `\b`, so `ssl_ciphers HIGH:!3DES` (3DES *disabled*) isn't reported as 3DES. That line appears in most real nginx configs. RE2 has no lookbehind, so the pattern consumes the preceding character instead, which is harmless for line-level matching. `-` is still allowed before the name, because `openssl enc -des-ede3-cbc` is a command-line flag. In a cipher string `-3DES` also means removal, but it's rare, and the config detector reports such files correctly anyway.
  - **13 shell-command rules (added with the config detector):** `openssl genrsa/genpkey/ecparam/dhparam`, `openssl … -md5/-sha1`, and `ssh-keygen -t rsa|dsa|ecdsa|ed25519`, with key sizes captured when they're on the line. The plan listed Dockerfiles under the config detector. But what a Dockerfile holds is shell commands, and the same commands appear in CI scripts, Makefiles and READMEs, so generic regex rules cover all of them at once. `[^|;&]*` keeps a match inside one command of a `&&` chain, so `openssl version && ssh-keygen -l` matches nothing.
- **Rule IDs aren't frozen yet.** `generic-aes128-cbc` became `generic-aes-cipher-string`, and `py-cryptography-ecb` became `py-cryptography-aes-ecb`. Nothing has been released, so no suppressions exist yet. From the first release on, the header's never-rename rule applies.
- Flow mappings (`match: { import: crypto/rsa }`) keep goast rules compact. Regex rules use block mappings with flow lists, and single-quoted patterns so `\b` reaches RE2 unescaped (a literal `'` is written `''`).

---

## `internal/crawler/scan.go`

### Constants `jobBuffer = 256`, `resultBuffer = 256`
- **Decisions & tradeoffs:** buffered so the three stages rarely wait on each other. An unbuffered channel would force the walker and workers to proceed in lockstep. Buffer size changes throughput, never correctness. 256 is the plan's number and costs almost nothing: each `jobs` slot is a 16-byte string header. Tune it later with `BenchmarkScan`, not by guessing.

### Constant `sniffLen = 8000`
- **Decisions & tradeoffs:** a file is "binary" if a NUL byte appears in its first 8000 bytes. The plan said 512, but git uses 8000. A larger window means fewer binary files misclassified as text, and it costs nothing extra because we read that head anyway.
  - **Known limitation:** UTF-16 text (some Windows PowerShell or C# files) contains NUL bytes and is treated as binary. Accepted for now; revisit if real repos hit it.

### `type Options struct { Root; Workers; MaxFileSize; Excludes }`
- **Decisions & tradeoffs:**
  - Plain struct, no defaults applied inside the crawler. The CLI owns defaults (`GOMAXPROCS`, 2MB). Hidden defaults in two places would drift apart. Invalid values are rejected by `Scan` instead.
  - `MaxFileSize int64`: matches `os.FileInfo.Size()`, so there's no conversion and no overflow on files over 2GB.

### `type Result`, `type Stats`, `type FileError`
- **Decisions & tradeoffs:**
  - **All slices sorted.** Workers finish in random order, so raw output would differ run to run. Sorting makes the same repo always produce the same result: golden-file tests work, CBOM diffs are clean, baselines (Phase 5) are stable. Cost: an O(n log n) sort at the end, which takes milliseconds even for 100k files.
  - **`Files []string` is always collected**, even when `--list-files` isn't used. That's about 6MB for 100k paths, which is small next to file contents. The markdown reporter's per-file sections (Phase 4) will need it, and an option flag would add a code path to test.
  - **`Stats` has one counter per skip reason** instead of a single "skipped" count. It answers "why wasn't my file scanned?" without a debug mode.
  - **`FileError` implements `error` and `Unwrap`.** It prints as `path: cause`, and callers can still use `errors.Is(err, fs.ErrPermission)` on the underlying cause.
  - **File-level problems are warnings in `Errors`, not a failed scan.** One unreadable file in a 100k-file repo shouldn't throw away 99,999 results. Only an unusable root, or cancellation, fails the scan.
- **Data structures:** slices (ordered output, cheap append); `Stats` is a struct of ints, not a `map[reason]int`. A struct keeps names fixed at compile time (a typo won't compile) and avoids map allocation.

### `type fileResult` and `type outcome`
- **What it does:** a worker's report about one file, sent on `results`.
- **Decisions & tradeoffs:**
  - **One message per file, not one per finding (plan sent each finding separately).** Every outcome (scanned, too large, binary, failed) has to reach the collector for `Stats` anyway. Batching findings per file also means fewer channel operations for files with many findings.
  - **Workers never touch `Result` directly.** Only the collector does, so no mutex is needed. ("Share memory by communicating.")
- **Data structures:** `outcome` is an `int` enum with `iota`: a compact, comparable type for `switch`.

### `func Scan(ctx, opts, dets) (*Result, error)`
- **What it does:** validates options, starts walker → workers → collector, waits, sorts, returns.
- **Decisions & tradeoffs:**
  - **Validates up front** (workers ≥ 1, size ≥ 1, root exists and is a directory, excludes parse), so a typo fails instantly with a clear message, not halfway through a large scan.
  - **Derived `context.WithCancel`.** If the walk fails, `cancel()` stops the workers too, rather than letting them scan files whose result will be thrown away.
  - **Fixes the gaps in the plan's sketch:**
    1. Returns an error on cancellation. The sketch always returned `nil`, so a Ctrl+C would have looked like a clean scan.
    2. Workers check `ctx.Err()` before every file and stop. In the sketch, cancelling didn't stop work already queued.
    3. The walker's own error is returned, not discarded.
  - **Final `return res, ctx.Err()`.** Subtle case: the walk can finish *before* cancellation, while workers are still busy. They then exit early and the result is incomplete, but `walkErr` is nil. Checking `ctx.Err()` at the end catches this.
  - **Returns partial `Result` along with an error.** The caller decides whether to use it. The CLI currently discards it and exits 2.
  - **`wg.Go(...)` (Go 1.25+)** instead of `wg.Add(1)` plus `go func(){ defer wg.Done() }`. It's impossible to forget `Done` or place `Add` wrongly.
  - **Leak-freedom argument** (verified by `goleak`):
    - The walker never blocks forever, because every send is a `select` with `ctx.Done()`.
    - Workers exit when `jobs` closes or `ctx` is cancelled.
    - The `results` closer exits when all workers do.
    - The collector drains `results` until it's closed, so a worker can never block on a send.
  - **The walker passes its stats through a variable, not the channel.** It's written before `walkDone <- err` and read after `<-walkDone`. The channel operation creates the Go memory-model happens-before edge, so there's no race (confirmed by `-race`).
- **Data structures:** `chan string` (jobs), `chan fileResult` (results), `chan error` with buffer 1 (`walkDone`, so the walker can send and exit without waiting for anyone to receive), `sync.WaitGroup`.

### `func scanFile(ctx, opts, dets, rel) fileResult`
- **What it does:** opens one file, checks it, reads it, runs the detectors that want it.
- **Decisions & tradeoffs (in execution order):**
  1. **`f.Stat()` on the open file**, not the walker's earlier info. The file may have changed between walk and open (time-of-check/time-of-use). Stat on the open handle describes exactly what we'll read.
  2. **Size check before reading anything.** A 2GB file is skipped without reading a byte, so memory per worker is capped at `MaxFileSize` (plan, Phase 6).
  3. **Read only the head (≤ 8000 bytes) first.** Decide binary, then ask detectors. A binary file nobody wants (PNG, JAR) costs at most 8KB of I/O instead of up to 2MB.
  4. **A text file no detector wants is still counted as scanned**, without reading the rest. "Scanned" means "eligible": not ignored, not too large, and text (or binary wanted by a detector). This is what `--list-files` shows.
  5. **One exact-size allocation for the full content** (`make([]byte, size)`), and the head is copied in. The alternative, allocating the full size up front, wastes memory on every skipped file. Cost: copying ≤ 8000 bytes, which is negligible.
  6. **Read up to the size seen at `Stat`, even if the file grows.** The limit holds no matter what. If a file shrinks, `ErrUnexpectedEOF` is accepted and we use what was read.
  7. **Detector errors are combined with `errors.Join`** into one per-file error. All detectors still run; one failing doesn't stop the others.
  8. **No buffer pooling (`sync.Pool`) yet.** It would cut allocations, but detectors might keep references to the content, which a pool would then overwrite: a nasty bug. Revisit only if Phase 6 benchmarks show GC pressure.
  9. **Cross-detector duplicates are merged here** with `detect.Dedupe` (added with the config detector), after every detector has run on the file. The crawler is the only place that sees all detectors' findings for one file. Doing it in the reporters would make each of them repeat it, and a later CBOM grouping step would still count one line twice as two occurrences.
  10. **`shorstop:ignore` comments are applied here** (`suppress.Apply`, Phase 5), after merging and for text files only, because this is the last place that still has the file's content. Doing it in each detector would repeat it five times; doing it after the scan would mean keeping every file's content in memory.
- **Data structures:** `[]byte` buffers; `[]detect.Detector` filtered per file (`wanted`); `[]error` for joining.

### `func runDetector(ctx, d, f) ([]Finding, error)`
- **What it does:** calls `d.Detect`, wraps its error with the detector name, and turns a panic into an error.
- **Decisions & tradeoffs:** detectors parse **untrusted files** (any repo can contain a malformed certificate or a corrupted config). A parser bug panicking on one file must not kill a scan of 100k files. Tradeoff: `recover` can hide bugs. Mitigated because the panic is reported as a warning naming the file and detector, and tests check that panics produce errors.
- **Data structures:** named return values, needed so the deferred `recover` can overwrite them.

### `func (res *Result) add(r fileResult)`
- **What it does:** folds one worker report into the result. Runs only on the collector goroutine.
- **Decisions & tradeoffs:** a `switch` over `outcome` keeps "which counter" logic in one place.

### `func (res *Result) sort()`
- **Decisions & tradeoffs:**
  - Findings are sorted by file, then line, then rule ID, then detector. The last key breaks ties when two detectors flag the same line with the same rule, so the order is fully deterministic.
  - `slices.SortFunc` with `cmp.Or` (Go 1.22+) instead of `sort.Slice`. It's type-safe (no `interface{}`), faster, and multi-key comparison reads as one expression.
  - Errors use a **stable** sort because one path can have two errors (a directory error and a file error). Stable keeps their walk order.

---

## `internal/crawler/walk.go`

### `var defaultSkipDirs = map[string]struct{}{...}`
- **What it does:** `.git`, `node_modules`, `vendor`, `dist`, `build`, `.venv` are never entered, at any depth.
- **Decisions & tradeoffs:**
  - The list is from the plan.
  - **Known tradeoff:** `vendor/` holds dependency code that *ships in your product*, so a complete CBOM arguably should include it. It's skipped because the dependency detector (Phase 2d) covers the same libraries via manifests far more cheaply, and vendored code would flood the report with third-party findings users can't fix.
  - `build/` is source code in some projects, though rare. A `--no-default-excludes` flag can undo this later if users ask.
- **Data structures:** `map[string]struct{}`, Go's idiomatic set: O(1) lookup, and the empty struct takes zero bytes per value.

### `type walkStats`
- Owned by the walker goroutine only. See `Scan` for how it's handed over safely.

### `func walk(ctx, root, excludes, jobs) (walkStats, error)`
- **What it does:** walks the tree depth-first, applies ignore rules, sends eligible file paths.
- **Decisions & tradeoffs:**
  - **`filepath.WalkDir`, not `filepath.Walk`.** `WalkDir` uses directory-entry types from `readdir` and avoids an `lstat` syscall per file. That's a large difference at 100k files.
  - **Single walker goroutine.** Walking is metadata I/O and fast compared with reading and parsing files. A parallel walker adds complexity for little gain at this stage. Revisit if benchmarks show workers idling.
  - **Checks `ctx.Err()` at every entry**, not only when sending. Otherwise cancelling during a walk of a huge *ignored* tree, where no sends happen, wouldn't be noticed.
  - **Root errors are fatal; everything else is recorded and skipped.** A wrong `--dir` is a user error. A single unreadable subdirectory shouldn't sink the scan.
  - **Duplicate-error suppression.** For an unreadable directory, `WalkDir` visits it once successfully (we then fail to read its `.gitignore`) and again with the read error. The `.gitignore` error is dropped so the directory is reported once. `.gitignore` errors in *readable* directories are still reported, because they mean ignore rules weren't applied.
  - **Symlinks are never followed.** Following them could escape the scan root (reading `/etc` from a repo symlink) or loop forever. Tradeoff: files reached only through a symlink aren't scanned. They're counted under `NotRegular`.
  - **Sockets, devices and FIFOs are skipped here, by directory-entry type.** Opening a FIFO blocks until a writer appears, which would hang a worker forever. Workers re-check with `Stat` in case the entry changed.
  - **`.gitignore` is respected even outside a git repo.** Simple and predictable.
  - **Global gitignore (`~/.config/git/ignore`) and `.git/info/exclude` are deliberately *not* read.** Both are per-machine and not committed. Using them would make the same repo scan differently on a laptop and in CI.
  - **A `.gitignore` is read when its directory is *entered*.** `WalkDir` visits a directory before its children, so its rules are always in place before any file under it is checked.
- **Data structures:** `ignoreStack` (see below); paths as slash-separated strings relative to root.

### `func isIgnored(e, rel, excludes, stack) bool`
- **What it does:** decides whether one entry is skipped.
- **Decisions & tradeoffs (precedence, highest first):**
  1. Default skip dirs: cheapest check, done first.
  2. `--exclude` patterns: **always win**. The user typed them explicitly for this run, so a repo's `.gitignore` negation shouldn't override them.
  3. `.gitignore` rules, deepest file first.
- **Data structures:** the path is split into `[]string` segments **once** per entry. Every rule in every frame then matches against a sub-slice of those segments, with no re-splitting.

### `func joinRel(dir, name) string`
- Joins with `/` and handles the root (`""`) without producing a leading slash. `path.Join` would also clean `..` segments, which can't occur here, so a plain concatenation is clearer.

---

## `internal/crawler/ignore.go`

**Why our own gitignore matcher instead of a library?** The plan suggested `sabhiram/go-gitignore` or go-git's matcher.
- `go-gitignore` hasn't been maintained since 2021 and handles a single file, not nested `.gitignore`s.
- go-git's matcher pulls the go-git module graph into `go.mod`, which is heavy for one feature in a security tool whose dependency list will be audited.
- Our own version is ~200 lines, has zero dependencies, and is covered by table tests.
- **Tradeoff:** we own the correctness of edge cases. The main gitignore rules are implemented and tested (anchoring, `**`, negation, directory-only, escapes, `[!...]`).

### Constant `maxIgnoreFileSize = 1 << 20` (1 MiB)
- The scanned repo is untrusted. Without a cap, a malicious multi-GB `.gitignore` could exhaust memory. Real `.gitignore` files are a few KB, so 1 MiB is generous. Larger files are reported as a warning and not applied.

### `type rule struct { segments; negate; dirOnly; anchored }`
- **Data structures:** the pattern is pre-split into `[]string` segments at **parse time**, once per rule, so matching thousands of paths never re-parses. `"**"` stays a whole segment so the matcher can recognise it with a single comparison. The three bools are the gitignore modifiers, decided once at parse time.

### `func parseRule(line) (rule, bool)`
- **What it does:** turns one gitignore line into a `rule`. Returns `false` for blanks, comments and malformed patterns.
- **Decisions & tradeoffs:**
  - Follows git's documented order: strip `\r` (Windows line endings), trim unescaped trailing spaces, skip `#` comments, handle `!` negation and the `\!` / `\#` escapes, trailing `/` = directory only, leading or middle `/` = anchored.
  - **`[!...]` is rewritten to `[^...]`**, because `path.Match` uses `^` for negation where gitignore uses `!`.
  - **Malformed globs (e.g. `[unclosed`) are dropped, not fatal.** Git also skips them. A bad line in someone's `.gitignore` shouldn't break the scan. (`--exclude` reports them, in `parseExcludes`.)
  - **Glob matching is done with stdlib `path.Match`** per segment. It's well tested, and its `*` never crosses `/`, which is exactly the gitignore semantic.

### `func trimTrailingSpaces(s) string`
- Gitignore drops trailing spaces unless escaped (`\ `). Trailing spaces are invisible in editors, so this avoids rules that silently never match.

### `func (r rule) match(parts, isDir) bool`
- **Decisions & tradeoffs:**
  - Directory-only rules don't match files.
  - **Non-anchored patterns (no `/`) match only the last segment (the name).** Because the walker checks every directory on the way down and prunes ignored ones, checking just the name of each entry is equivalent to git's "matches at any level".
  - **Files under an ignored directory are never checked at all.** That's both faster and matches git's rule that "you can't re-include a file whose parent directory is excluded".

### `func matchSegments(pat, parts) bool`
- **What it does:** segment-by-segment match with `**` = zero or more segments.
- **Decisions & tradeoffs:**
  - *Correction (Phase 6):* this was first recursive backtracking at each `**`, accepted as "exponential only with many `**`, which real patterns don't have". That missed who writes the patterns: `.gitignore` files come from the scanned repository, so a pull request controls them, and ShorStop runs in CI on pull requests. Measured: `**/**/**/**/**/**/**/**/z` on a tree 30 directories deep took 6 s, and ten `**` never finished. A one-line `.gitignore` could hang the scan.
  - **Now memoized:** each (pattern position, path position) pair is decided once, so the work is bounded by len(pattern) × len(path)² `path.Match` calls; 25 `**` take 0.07 s for the whole scan. *Option rejected:* collapsing consecutive `**` at parse time only. It fixes `**/**/**` but not `**/a/**/a/**/a/…` on a path of `a`s, which backtracks just as badly.
  - **Patterns without `**` skip the memo** (one segment against one segment, no allocation). Those are most anchored patterns, and this function runs for every path against every anchored rule.
  - Trailing `/**` requires at least one more segment, so `abc/**` matches everything *inside* `abc` but not `abc` itself (git's documented behaviour).
- **Data structures:** the memo is one `[]int8` of (len(pattern)+1) × (len(path)+1) entries (unknown, no, yes), allocated per call. Paths are a few dozen segments deep at most, so it is a few hundred bytes.
- **Tests:** `TestMatchSegmentsManyGlobstars` (25 `**` against a 60-deep path); `FuzzIgnore` compares it with the original backtracking matcher (kept in the test file as `naiveMatchSegments`) for patterns with up to three `**`, where backtracking is still fast.

### `func lastMatch(rules, parts, isDir) (ignored, matched bool)`
- Iterates rules **from last to first** and returns on the first hit. Gitignore says the last matching rule wins, so scanning backwards lets us stop early instead of always scanning every rule.
- Two return values distinguish "matched and re-included (`!`)" from "no rule matched". The caller needs that difference to decide whether to keep looking in shallower `.gitignore` files.

### `type frame` and `type ignoreStack []frame`
- **What it does:** holds the rules of the current directory's `.gitignore` and those of its ancestors.
- **Decisions & tradeoffs:**
  - **A stack, not a global list of all rules.** Because the walk is depth-first, the `.gitignore` files that apply to the current path are always exactly the ones on the path from root to here. Push on entering a directory, pop on leaving. Memory is O(depth × rules per file), not O(every rule in the repo).
  - Precedence falls out naturally: check from the top of the stack (deepest) down; the first file with a match decides.
  - `depth` is precomputed per frame, so converting a path to "relative to that `.gitignore`" is just `parts[depth:]`, with no string work.
  - **Empty rule lists aren't pushed**, since most directories have no `.gitignore`. The stack stays as short as possible.
- **Data structures:** slice used as a stack (`append` to push, reslice to pop), the idiomatic Go stack.

### `func (s *ignoreStack) push(dir, rules)` / `popTo(p)` / `ignored(parts, isDir)`
- `popTo(p)` pops every frame whose directory isn't an ancestor of `p`. Because `WalkDir` visits entries in lexical depth-first order, this is always correct, and each frame is pushed and popped exactly once: amortised O(1) per entry.
- The ancestor test is `strings.HasPrefix(p, dir+"/")`. The trailing `/` matters: without it, `src2/x` would wrongly count as being inside `src`.

### `func readIgnoreFile(name) ([]rule, error)`
- A missing file is `nil, nil`, not an error. Most directories have none, so that's the normal case.
- Reads through `io.LimitReader(max+1)`. Reading one byte past the cap is how we detect "too large" without trusting a size from `Stat`, which could change.
- `strings.Lines` (Go 1.24+) iterates lines without building a `[]string` of the whole file.

### `func parseExcludes(patterns) ([]rule, error)`
- Same syntax as `.gitignore`, relative to `--dir`, so users learn one pattern language.
- **Negation (`!`) is rejected**, as are malformed patterns, with an error. Unlike in a `.gitignore`, the user is present to fix a typo, and failing loudly beats silently scanning the wrong files. `--exclude` means "always skip", so a negated exclude has no clear meaning.

---

## `cmd/shorstop/main.go`

### Package-level `var version = ""`
- Must be a `var`, not a `const`, because `-ldflags -X` can only set string variables. Empty means "not set by the build", which tells `resolveVersion` to fall back. A hard-coded version would drift from git tags.

### Constants `exitOK = 0`, `exitFindings = 1`, `exitError = 2`, `defaultMaxFileSize = 2 << 20`
- The plan's contract: `0` clean, `1` findings over `--fail-on`, `2` usage or scanner error, so CI can tell "your code has RSA" from "the scanner crashed". `1` was reserved, unused, until `--fail-on` existed (Phase 5).
- Usage errors, runtime errors and **cancellation** all use `2`. The shell convention for Ctrl+C is 130, but the plan's contract defines only 0, 1 and 2. A cancelled scan is an incomplete scan, so it's treated as an error.
- `2 << 20` = 2 MiB, the plan's default limit.

### `func main()`
- **What it does:** sets up signal handling, calls `run`, exits with its code.
- **Decisions & tradeoffs:**
  - **`signal.NotifyContext` for SIGINT and SIGTERM.** Ctrl+C and CI job cancellation (which sends SIGTERM) both cancel the scan context, so the scan stops cleanly and reports "scan cancelled" instead of dying mid-write.
  - **`context.AfterFunc(ctx, stop)`.** After the first signal, normal signal behaviour is restored, so a **second Ctrl+C kills immediately**. Without this, a hung detector would make the process ignore Ctrl+C entirely.
  - `os.Exit` is called only after `run` returns, so every `defer` inside `run` has already run (output flushed and closed).

### `func run(ctx, args, stdout, stderr) int` / `type exitCode` (rewritten for cobra, Phase 5)
- **What it does:** builds the command tree, runs it with `args`, and turns the result into an exit code. It's still the testable entry point, so tests call it with fake args and buffers.
- **Takes a `context.Context`** (tests pass a cancelled one to check that path) and **`io.Writer`s** instead of `os.Stdout`/`os.Stderr`.
- **Errors are printed in one place, in one format** (`shorstop: …`). Cobra's own `Error:` lines and usage dumps are silenced (`SilenceErrors`, `SilenceUsage`): a scan failure isn't a usage mistake, and a usage block after "permission denied" buries the message.
- **`exitCode`** lets a command that has already explained itself (`--fail-on`: "3 findings at or above high") exit 1 without a second message. Every other error → 2. `context.Canceled` → "scan cancelled", 2.
- **Help (`-h`) exits 0, on stdout**: asking for help isn't a failure, and `shorstop --help | less` works. With the stdlib flag package, usage went to stderr.

### `func newRootCmd(stdout, stderr)` (Phase 5)
- **CLI library: cobra** (project-owner decision, 2026-11-02), as in the plan: subcommands, generated help, and a free `completion` command for bash/zsh/fish/PowerShell. Runtime dependencies: `spf13/cobra` and `spf13/pflag`, plus `inconshreveable/mousetrap`, which is linked only on Windows.
- **Commands:** `scan [dir]`, `rules list`, `version`. **Plain `shorstop` scans too** (the root command has the same flags and runs the same scan), so `shorstop --format sarif` and every example written so far keep working. The root takes **no positional arguments**: `shorstop src` would be ambiguous with a subcommand name, so a directory argument belongs to `scan`.
- **GNU-style flags** (pflag): `--format`, short `-f`/`-o`/`-v`/`-h`. *Breaking change:* single-dash long flags (`-version`) no longer work; pflag reads them as `-v -e -r …`. Nothing has been released, so no one depends on the old form.
- `--version` / `-v` and `version` print the same `shorstop v1.2.3` line (`SetVersionTemplate`).
- A flag error ends with `(see 'shorstop --help')` (`SetFlagErrorFunc`) instead of a full usage dump.

### `cmd/shorstop/scan.go` (Phase 5)

#### `type scanOptions` / `func newScanOptions` / `func addScanFlags(cmd, o)` / `var failOnLevels`
- One options struct per command instance, filled by `addScanFlags`, which both the root and `scan` call, so both define the same flags once.
- **`--workers` default is `runtime.GOMAXPROCS(0)`, not `runtime.NumCPU()` (plan said NumCPU).** Since Go 1.25, `GOMAXPROCS` respects container CPU limits (cgroups): in a CI container limited to 2 CPUs on a 64-core host, `NumCPU` returns 64 and would oversubscribe the CPU.
- **`--fail-on`** takes `none` (the default), `critical`, `high`, `medium` or `low`. **Off by default:** a tool that fails a build the first time someone tries it gets uninstalled. CI setups opt in.
- **`--baseline`** takes a previous SARIF or CBOM output (see `internal/baseline`).

#### `func newScanCmd(stdout, stderr)`
`scan [dir]` takes an optional directory argument (`shorstop scan src/`). Giving it **and** a different `--dir` is an error rather than a silent choice.

#### `func runScan(ctx, o, stdout, stderr)`
- **Every option is checked before scanning:** format, `--fail-on`, and **the baseline file is read and parsed first**. A typo, or a bad baseline path in CI, fails in milliseconds, not after a long scan.
- **After the scan:** suppressed findings (`Finding.Suppression`, set by the crawler) and then baselined findings (`baseline.Split`) are **set aside from what's reported**: the table, SARIF, Markdown and `--fail-on` see only the rest, and the summary counts both (`· 3 suppressed · 40 in baseline`). **The CBOM still gets every finding** (`renderEnv.all`): a CBOM is an inventory, and suppressing a finding doesn't remove the crypto from the code.
- Suppression is applied before the baseline, so a finding is either suppressed or baselined, never counted twice.
- Warnings go to stderr, results to stdout; `--list-files` and machine-readable formats send the summary to stderr, so stdout pipes cleanly.
- **`--fail-on`** is applied last, after the output is written, so CI gets the report *and* the failing exit code.

#### `func countAtOrAbove(fs, threshold)`
Counts reported findings rated at or above the threshold by `classify.Severity.Rank`; `none` counts nothing.

#### `--config`, `--no-config`, `--rules` flags and `scanOptions.flags` (added with `.shorstop.yaml`)
- `--config <file>` names the config explicitly. Otherwise `.shorstop.yaml` at the root of the scanned directory is used **if present**: a missing default is normal, but a missing explicit `--config` is an error. `--no-config` ignores the default file (an explicit `--config` still wins, since it's the more specific request).
- `--rules <file>` (repeatable) adds rule files in the rule-pack format.
- `scanOptions.flags` keeps the command's flag set, so `applySettings` can ask `Changed(name)`: **a flag given on the command line beats the config, and the config beats the flag's default.** Comparing values against defaults instead would get "`--fail-on none` given on purpose" wrong.

#### `func applySettings(o)`
Fills each option the command line didn't set from the config: `fail-on`, `baseline`, `max-file-size` (parsed by the same `byteSize.Set`, so `4MB` means the same in both places). **`exclude` and `rules` combine** (config first, then flags) rather than override: a one-off `--exclude` shouldn't silently drop the repository's standing excludes. The config's `fail-on` is then checked by the same validation as the flag.

#### `func selfExcludes(dir, paths...)`
**ShorStop never scans its own files** when they sit inside the scanned tree: the config, rule files, the baseline and the `--output` file. Each is excluded with an anchored pattern (`/ci/base.sarif`). They name crypto by design. The test that caught this had a custom rule file reported as 3DES usage, and **a baseline committed to the repository would have grown new findings on every run**, because its SARIF snippets contain "MD5" and friends. Paths outside the tree, or the root itself, are skipped. `TestBaselineInsideTheRepo` covers the committed-baseline case end to end.

#### `func loadRules(files, disable)` / `func builtinIDs()`
- Builds the rule pack for the scan: the built-in pack plus each rule file, parsed with the same strict `rules.Parse` (so custom rules carry `examples` too, validated at load), merged by `rules.Merge`.
- **A custom rule may not reuse a built-in ID**, whether a rule-pack ID (checked by `Merge`) or a cert/config built-in (checked here via `builtinIDs`): suppressions, baselines and SARIF alert history key on IDs, so a silently replaced rule would change their meaning.
- **`disable`:** rule-pack rules are removed from the pack (`Pack.Without`), so they never run. The cert and config detectors' built-in IDs have no pack entry, so they're returned for the scan to filter their findings. **An unknown ID is an error**, so a typo can't leave a rule on while looking disabled.
- `detectors(pack)` (in `main.go`) now takes the pack instead of loading the built-in one, and `renderEnv.pack` gives SARIF the descriptions of custom rules too.

### `cmd/shorstop/rules_cmd.go` (Phase 5)

#### `func newRulesCmd(stdout)` / `type ruleRow` / `func listRules(w, pack, detector)`
`shorstop rules list [--detector X] [--rules file]`: **every rule ShorStop can report**, both rule-pack rules and the cert/config detectors' built-in IDs, sorted by ID, with detector, algorithm and description, as a `tabwriter` table with a count (225 built in). It's the reference users need to write `shorstop:ignore <rule-id>` comments and `disable:` lists. With `--rules`, it also loads and **checks** a custom rule file, a quick way for rule authors to test a file without scanning anything. An unknown `--detector` is an error rather than an empty list.

### `.shorstop.yaml` in this repository
ShorStop dogfoods its own config. A crypto scanner's source is full of algorithm names (lookup tables like `tls.go`'s cipher table, test inputs), so the repository config excludes `testdata/`, `*_test.go`, the rule pack, `docs/` and the plan, and **disables the eight generic name rules**, which here only match the detectors' own tables. What's left is the crypto ShorStop really uses: the cert detector's `crypto/rsa`, `ecdsa`, `ed25519`, `dsa` and `ecdh` imports (for parsing keys), and `golang.org/x/crypto`. That's 10 findings, down from 132.

### `func writeOutput(path, stdout, write) error`
- **What it does:** writes output to a file (`--output`) or to stdout, through a buffer.
- **Decisions & tradeoffs:**
  - **`bufio.Writer`.** Listing 100k files with unbuffered writes would cost 100k `write` syscalls. Buffered, it's a few dozen.
  - **The `Close` error is checked** for files. On some filesystems (network, full disk), `Close` is the first place a failed write shows up. Ignoring it could report success for a truncated file.
  - **Takes a `func(io.Writer) error` callback**, so the open/buffer/flush/close logic lives in one place, and each output mode (list, summary, later each reporter) only writes content.
  - Tradeoff: the file isn't written atomically (temp file plus rename). A crash mid-write leaves a partial file. Acceptable for a report; revisit for `--baseline` files in Phase 5, where a corrupt baseline would matter.

### `func summary(res) string`
- One line with every `Stats` counter, plus the ratings from `report.Count` (`· 12 critical · 48 high · 3 quantum-safe`). It's the last line of the terminal table and goes to stderr for every other format. It shows **every skip reason**, so a user can see at a glance why the count is lower than expected.
- The rating counts were first a `ratings()` function here (added with the classifier). They moved to `report.Count` with the terminal and Markdown reporters, so every format counts the same way.

### `--format` flag and `formats.go` (added with the CBOM reporter)
- **`var formats map[string]renderFunc`** maps each `--format` value to a renderer with one signature, so adding SARIF and Markdown is one map entry each. `formatNames` keeps help and error text in a fixed order (map order is random).
- **Checked before the scan**, so `--format xlm` fails in milliseconds instead of after scanning a large repository. Exit code 2, as for every other usage error.
- **`json` is the CBOM**, as in the plan's flag table, and **`cbom` is accepted as an alias**, because "json" doesn't say *which* JSON and users will reach for the name of the thing.
- **Machine-readable formats print the summary to stderr**, so `shorstop --format json > cbom.json` gives a clean file, and the user still sees the counts.
- **`renderCBOM`** fills in what findings don't carry: a random serial number (a CycloneDX serial identifies one BOM *document*, so every run gets a new one), the current time, the tool version, and `projectName(dir)`, the scanned directory's own name (`.` resolves to the working directory's name).
- **`renderTable`** (the default) writes `report.WriteTable` and then the summary line. **`renderMarkdown`** writes `report.WriteMarkdown`.
- **`type renderEnv`** (added with the terminal reporter) passes what a renderer needs besides the result: the directory, and whether colour is allowed. It's a struct, so a new need doesn't change every renderer's signature again. That paid off in Phase 5, which added **`all`** (every finding, for the CBOM) and the **`suppressed`/`baselined`** counts (for the summary) without touching the signatures.
- **`func useColor(w)`:** colour only when stdout is a **character device** (a terminal) and **`NO_COLOR`** (no-color.org) is unset or empty, and never with `--output`, because a file isn't a terminal. That's the plan's 4a rule. *Option rejected:* `golang.org/x/term`'s `IsTerminal`, a new dependency for a check that `os.File.Stat`'s `ModeCharDevice` already does on every OS we target. CI logs (GitHub Actions) aren't terminals, so they get plain text. A `--color=always` override can come with the Phase 5 flags if anyone asks.
- **`renderSARIF`** (added with the SARIF reporter) builds the rule catalog from the rule pack plus `cert.RuleDescriptions` and `config.RuleDescriptions`. The catalog is assembled here, in the one place that knows every detector, so `report` doesn't need to know which detectors exist.

### `func resolveVersion() string`
- Checks, in order:
  1. ldflags `version` (`make build`, GoReleaser).
  2. `debug.ReadBuildInfo().Main.Version`: `go install …@v1.2.3` doesn't pass ldflags, but Go records the module version in the binary.
  3. `"dev"` for local builds, where Go reports the meaningless string `"(devel)"`.
- Not cached: it runs once per process.

---

## `cmd/shorstop/flags.go`

### `type byteSize int64` with `Set` / `String` / `Type`
- **What it does:** parses `--max-file-size` values like `512KB`, `2MB`, `2 MiB`.
- **Decisions & tradeoffs:**
  - **Implements `pflag.Value`** (`Type` added with cobra; it names the value in help: `--max-file-size size`), so parsing errors appear as normal flag errors, and the default shows in `-h` as `2MB`, not `2097152`.
  - **Binary units (1KB = 1024).** This is the common convention for file sizes, and what the plan's "2MB" meant. Both `KB` and `KiB` are accepted, so users don't have to know the distinction. Tradeoff: `KB` technically means 1000 in SI. Documented in the flag help.
  - **Case-insensitive, spaces allowed** (`2 mb`). Typos in CI YAML are common, and leniency costs nothing.
  - **Whole numbers only** (`1.5MB` rejected). Fractional bytes would need rounding rules for no real benefit.
  - **Overflow check** before multiplying, so `9999999999GB` errors instead of silently wrapping to a negative or tiny limit.
  - Units are checked **longest suffix first** (`KIB` before `B`), so `2MB` isn't read as "2M" plus a stray "B".
- **Data structures:** a slice of `{suffix, mult}` structs, not a map, because order matters for longest-suffix matching and Go map iteration order is random.

### `type stringList []string`
- A repeatable flag: `--exclude a --exclude b`. Repeating is the standard flag-package idiom. `Type` returns `pattern` for help. Kept instead of pflag's `StringArray`, so the flag's behaviour didn't change in the move to cobra.
- Comma-separated values aren't split, because a glob may legitimately contain a comma (`{a,b}` style patterns or file names).

---

## Tests

### `internal/crawler/scan_test.go`
- **`TestMain` → `goleak.VerifyTestMain`:** fails the package if *any* goroutine outlives the tests. That's how a leak in the cancel path would show up.
  - `goleak` is a **test-only** dependency. It appears in `go.mod` but isn't compiled into the binary.
  - Comparing `runtime.NumGoroutine()` before and after was rejected: it's flaky, because runtime goroutines come and go.
- **`fakeDetector`, `cancellingDetector`:** in-test fakes implementing `detect.Detector`, so crawler tests don't depend on real Phase 2 detectors. `atomic.Int64` call counters, because the fake is called from many workers concurrently.
- **`writeTree(t, map[path]content)`:** builds a fixture tree in `t.TempDir()`, which is removed automatically. A map literal keeps each test's tree readable in one place.
- **`TestScanFindingsDeterministic`:** the same tree with 1, 3 and 16 workers must give identical results. This guards the sorting decision.
- **`TestScanCancelMidway`:** a detector cancels the scan on its first call. The test asserts `context.Canceled` and that at most `Workers` files were processed (each worker may finish its current file, but no more).
- **`TestScanUnreadableEntries`:** uses `chmod 000`. It's skipped when running as root, because root ignores permissions.
- **`TestScanLargeTree`:** the plan's Phase 1 acceptance test (100k files). It only runs with `SHORSTOP_LARGE_TEST=1`, because creating 100k files takes about a minute under `-race`, which is too slow for every CI run.
- **`BenchmarkScan`:** baseline for Phase 6 tuning. Uses `b.Loop()` (Go 1.24+), which handles timer resets and keeps the compiler from optimising the work away.

### Fuzz tests (Phase 6)
**Why:** ShorStop's main job is scanning code it doesn't trust, often a stranger's pull request in CI. Every parser reads attacker-controlled bytes. A panic in a detector is caught per file (`runDetector`), but that file's findings are then lost, which is a way to hide crypto from the scan. A panic anywhere else, or a hang, stops the scan entirely.

**Targets**, one per parser that reads repository content. Go fuzzes one target per `go test` run.

| Target | Input | Checks |
|---|---|---|
| `detect/cert` `FuzzDetect` | PEM, DER, SSH public keys | detector contract (below) |
| `detect/config` `FuzzDetect` | nginx/Apache/HAProxy/OpenSSL/stunnel/PostgreSQL configs, `sshd_config`, Kubernetes YAML | detector contract |
| `detect/deps` `FuzzDetect` | 18 manifest and lockfile names (JSON, YAML, TOML, XML, line formats) | detector contract |
| `detect/goast` `FuzzDetect` | Go source, including files that don't parse | detector contract |
| `detect/regex` `FuzzDetect` | source in each language the rule pack covers | detector contract |
| `baseline` `FuzzParse` | `--baseline` SARIF or CBOM | no panic |
| `settings` `FuzzParse` | `.shorstop.yaml` | no panic |
| `rules` `FuzzParse` | a rule file, plus a line to match | a pack that parses can also match without panicking |
| `suppress` `FuzzApply` | file content with `shorstop:ignore` comments | every finding is kept; a suppression only ever comes from the finding's own line or the line above |
| `crawler` `FuzzIgnore` | `.gitignore` content and a path | deterministic; the memoized `**` matcher agrees with backtracking |

- **Detector targets take `(name uint8, content []byte)`.** The file name decides which parser runs (`pom.xml` vs `yarn.lock`, `.der` vs `.pem`), so it is picked from a fixed list by index. A free-form name string would spend most of the fuzzer's time on names no parser accepts.
- **`detecttest.Check`** (`internal/detect/detecttest`) holds the contract every detector promises, so all five targets test the same thing:
  - `Content` isn't modified (detectors share one buffer);
  - the same input gives the same findings (catches map-order dependence);
  - every finding has a rule ID, an algorithm from `rules.Algorithms` or none, a line inside the file (0 for binary files), and a snippet of valid UTF-8, one line, at most `detect.MaxSnippet` runes.
  - Errors are allowed: most fuzzed input is malformed, and saying so is correct.
  - `detecttest.File` sets `Binary` the way the crawler does (a NUL in the first 8000 bytes), so the DER path is reached only as it would be in a scan.
- **Seeds are the existing fixtures** (`testdata/fixtures/...`), so fuzzing starts from real files of each kind. Seeds and any saved failures (`testdata/fuzz/<Target>/`) run as ordinary test cases in every `go test`.
- **`-fuzzminimizetime 5s`:** Go shrinks every new interesting input before using it, for up to 60 s by default. With large seeds (the SARIF and CBOM goldens, the 66 KB rule pack) `baseline` and `rules` spent 27 of 30 s shrinking, with zero new executions; at 2–5 s they run at 20,000–50,000 inputs/s. Measured before choosing it, because a stall can also mean a parser hanging on one input.
- **CI:** a `fuzz` job runs each target for 30 s, as a matrix with `fail-fast: false` so one failure doesn't hide the others. A failing input is printed in the log rather than uploaded as an artifact, which avoids another third-party action. `make fuzz` runs them all locally in turn (`FUZZTIME`, default 30 s).

### `internal/crawler/ignore_test.go`
- One table of `{pattern, path, isDir, want}` covering each gitignore rule. A failure names the exact pattern and path.
- The stack test pushes and pops **in real walk order**, because `popTo` relies on depth-first order. (An earlier draft pushed out of order and failed for that reason, not because of a bug.)

### `cmd/shorstop/main_test.go`, `flags_test.go`
- End-to-end through `run` against a temp tree: flags, `--list-files`, `--exclude`, `--output`, bad sizes, a missing directory, cancellation.
- Phase 5: help on stdout (root and `scan`), `-v`, a rejected single-dash long flag, an unknown command, `scan <dir>` and a conflicting `--dir`, bad `--fail-on`, a missing baseline, and **`TestFailOnSuppressAndBaseline`**, the whole CI flow end to end:
  1. `--fail-on high` exits 1, with the suppressed line counted rather than reported.
  2. The scan's own SARIF, used as a baseline, leaves nothing new and exits 0.
  3. A newly added SHA-1 is reported and fails the build despite the baseline.
  4. The CBOM still lists every asset.

  Then **`TestRulesList`** (all detectors present, `--detector` filter, unknown detector).
- They change the global `version`, so they can't use `t.Parallel()`. Acceptable at this size.

---

## Build and tooling (no methods; one entry per file)

### `go.mod` — `go 1.27` + `toolchain go1.27.3`
- **Minimum is 1.27, the latest release**, by project-owner decision (2026-10-24). On that date go.dev listed 1.27.3 and 1.26.10 as supported.
- **Tradeoff:** users on 1.26 can't `go install` without Go downloading 1.27 for them. Prebuilt binaries aren't affected. In return, any 1.27 feature can be used.
- **`go 1.27`** is the minimum language/API version required of users. **`toolchain go1.27.3`** only says which Go this repo's builds use: an older local Go downloads it automatically. Bump it with each Go patch release.
- Dependencies: **`go.uber.org/goleak`** and **`santhosh-tekuri/jsonschema/v6`** (tests only), **`go.yaml.in/yaml/v3`** (rule pack and config; see `internal/rules`, `internal/settings`), **`golang.org/x/crypto`** (OpenSSH key parsing; see `internal/detect/cert`), **`spf13/cobra`** + **`spf13/pflag`** (CLI).

### Module path `github.com/shorstophq/shorstop` (project-owner decision, 2026-11-03)
- The plan's original module path, under the GitHub owner `shorstop`, couldn't be used: that name belongs to an unrelated user account. It was created in December 2022, with no repositories and no activity since, so there's no confusion risk; but GitHub doesn't release names held by inactive accounts. The owner created the **`shorstophq`** organisation, owned by their personal account; it can move to business terms if a company is formed. The product and binary are still called ShorStop / `shorstop`, the way `cli/cli` publishes `gh`.
- The path is set before the first release on purpose: once people `go install` a module, renaming it breaks them. It also determines the Docker image (`ghcr.io/shorstophq/shorstop`) and the Action reference (`uses: shorstophq/shorstop@v1`).
- **`cmd/shorstop/paths_test.go` (`TestNoOldOwnerPath`)** walks the repository and fails if a GitHub or GHCR path under the old owner `shorstop` ever reappears. (This entry describes those paths in words for that reason: when it first spelled them out, the guard failed on it, which is what it's for.) A stray old reference in an install command or import would point users at an account someone else controls: today it gives an error, but it would serve their code if they ever created a matching repository. The old strings are built at run time so the test doesn't match itself, and a check with a planted file confirmed it reports the file and line.

### `Makefile`
- `CGO_ENABLED=0`: static binary for `FROM scratch` images, easy cross-compiling.
- `-trimpath`: strips local paths from the binary, for privacy and reproducibility.
- No `-s -w` stripping in `make build`: local binaries keep their symbol table and DWARF, so debuggers (`dlv`) and `go tool nm` work. *Correction:* this entry first said stripping would make panic stack traces unreadable. That's wrong: Go's runtime keeps its own line tables (pclntab), so stripped binaries still print file:line traces. Release builds strip (see `.goreleaser.yaml`).
- `fuzz` runs every fuzz target in turn for `FUZZTIME` (default 30 s); see "Fuzz tests".
- `lint` and `release-snapshot` print an install hint when the tool is missing. `release-snapshot` runs GoReleaser with `--skip=sign,sbom`, because cosign and syft are installed only in the release workflow.

### `.golangci.yml`
The `standard` set plus `errorlint`, `misspell`, `unconvert`, `gocritic`. `gosec` is left out for now (it flags every `crypto/md5` and `crypto/sha1` reference, which the detectors must contain on purpose). `testdata/` is excluded.
- **`std-error-handling` exclusion preset** (added 2026-11-02, the first time the linter ran with v2.15.0). Before it was added, errcheck reported 7 issues: `defer f.Close()` on files opened read-only (`readIgnoreFile`, `scanFile`), and `fmt.Fprint*` to stdout/stderr in `run`. Neither error can be acted on: a read-only Close can't lose data, and if the terminal write fails there's nowhere to report the failure.
  - *Options:* (a) `_ = f.Close()` / `_, _ = fmt.Fprintf(...)` at each call site; (b) errcheck's `exclude-functions` list; (c) the preset. **Chose (c):** the preset covers exactly these standard-library cases, and call sites stay idiomatic.
  - *Tradeoff:* errcheck will also ignore an unchecked `Close` on a **writable** file, where the error does matter. Rule: writable files (e.g. `writeOutput`'s `--output` file) must check `Close` explicitly, and code review has to enforce that because the linter no longer will.

### `README.md` (added after the first push, 2026-11-03)
- **It claims only what exists.** There are no binary releases, Docker image or GitHub Action yet, so the README says "pre-release", installs with `go install` (which works now that the module is public, with Go 1.27+), and shows a CI workflow that installs with Go and uploads SARIF itself. The Action's shorter form replaces that workflow once it's published. A README that promised `brew install` before the tap existed would fail its first reader.
- **Install section (for `v0.1.0`):** Homebrew, Docker, signed binaries, then `go install`, in that order. Most readers want a one-liner; those who verify get the full steps. The binary steps were run as written against `v0.1.0-rc.1`: download, `cosign verify-blob` with the exact workflow identity, `shasum --ignore-missing -c`, extract. `shasum` works on macOS and Linux; `sha256sum` is given as the GNU alternative. The Docker example mounts read-only (`:ro`) and writes reports through stdout, which matches the image's non-root user. This section is committed together with the `v0.1.0` tag, so it never describes a release that doesn't exist yet.
- **The Action is referenced as `@v0.1.0`, not `@v1`:** a `v1` tag on a `0.x` product reads as a stability promise it doesn't make. Exact tags are also what GitHub's security hardening guide prefers after a commit SHA. A moving `v0` major tag can be added later if people ask for one.
- **The CI section uses the Action** instead of the earlier `go install` + `upload-sarif` workflow. Its inputs are listed in a table. Two caveats are stated: private repositories need GitHub Code Security, and fork pull requests get a read-only token, so they can't upload SARIF.
- **Every example was run before it was written down.** The sample output comes from a real scan of a demo project (trimmed with `...`). The workflow YAML parses. The `.shorstop.yaml` and custom-rule examples load, with the rule's `examples` passing. The two `shorstop:ignore` examples suppress what they claim (4 findings). The `upload-sarif` version was checked against the action's releases (v4 is current, v3 is still maintained).
- **The title opens with "post-quantum cryptography scanner"**, following the plan's naming note: search engines read "shorstop" as "shortstop", so the title and first line say what it is. The repository's GitHub description starts the same way.
- **The known limitations are listed openly** (comments matched, no Go type checking, build-defined OpenSSL sets, hybrid key exchange, 2 MB lockfiles, unresolved Maven/Gradle versions). They're the same gaps this log records, and a security tool that hides its blind spots is trusted less, not more.
- The repository's own `.shorstop.yaml` excludes `README.md` alongside `docs/`: its examples name algorithms and key-generation commands on purpose.

### `.github/workflows/ci.yml`
- A matrix of Go 1.27 (floor) and stable. Both are 1.27 today; they'll diverge when 1.28 ships, without editing the file. `permissions: contents: read`.
- **Every action is pinned to a full commit SHA**, with the release as a comment (`# v7.0.1`), since the repository went public (2026-11-03). A tag like `@v7` can be moved to point at other code, for example by a compromised maintainer account, as happened to `tj-actions/changed-files` in 2025. A commit can't change. *Cost:* updates are manual; Dependabot can raise them as PRs later.
- Moved to the current majors while pinning (checkout v7, setup-go v7, golangci-lint-action v9). I read the release notes first: the changes are a new Node.js runtime, plus checkout v7 refusing fork PRs under `pull_request_target`. That's a security fix, and CI uses `pull_request`.
- **golangci-lint itself is pinned to `v2.15.0`**, the version run locally, instead of `latest`, so a new linter release can't fail CI with no change to the code.
- **`release-check` job:** builds every release platform with GoReleaser (`--snapshot`, no publishing) on every push, so a broken release config, or code that doesn't compile for Windows, fails here rather than on release day. It sets up buildx, the same builder the release uses, so the container images are built and checked too.
- **`fuzz` job (Phase 6):** each fuzz target for 30 s per push; see "Fuzz tests".
- All workflows pass **actionlint** v1.7.12.

### `.goreleaser.yaml` (Phase 5)
- **Targets:** linux/darwin × amd64/arm64, plus windows/amd64. That's the plan's list; Windows on ARM can be added when someone asks. Archives are `tar.gz` (Windows: `zip`), named `shorstop_<version>_<os>_<arch>`, and contain the binary, `LICENSE` and `README.md`.
- **Build flags:** `CGO_ENABLED=0` (static, verified with `file`: "statically linked", so it runs on any Linux and in `FROM scratch`), `-trimpath`, and `-s -w`, which makes it a third smaller than the local build (8.5 MB vs 12.7 MB). `-X main.version=v{{ .Version }}` adds the `v`, so a release binary reports the same `v0.1.0` that `go install …@v0.1.0` does.
- **Reproducible builds:** `mod_timestamp: {{ .CommitTimestamp }}` plus `-trimpath` makes the output depend only on the commit. Verified: two snapshot builds gave byte-identical binaries on all five platforms, so anyone can rebuild a release and compare.
- **`checksums.txt`** (SHA-256) covers every archive. **SBOMs** (Software Bills of Materials) are made per archive with syft.
- **Signing: keyless cosign** on `checksums.txt`. In GitHub Actions, cosign gets a short-lived certificate from Sigstore tied to this repository's release workflow (via OIDC), so there is **no signing key to store, rotate or leak**. Signing the checksum file covers every archive, because each archive's hash is in it. The signature is written as a Sigstore bundle (`--bundle`, required since cosign v3). Users verify with `cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity-regexp 'https://github.com/shorstophq/shorstop/.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt`.
- `release.prerelease: auto`: a tag with a suffix (`v0.1.0-rc.1`) becomes a GitHub pre-release. `changelog.use: github` builds the notes from commit messages.
- Snapshot versions (`0.0.2-snapshot-<commit>`) can't be mistaken for releases. *Correction:* the template first used `+<commit>` (semver build metadata), but the version is also a Docker tag, and Docker tags can't contain `+` (the first image build failed with "invalid reference format"). Real tags (`v0.1.0`, `v0.1.0-rc.1`) were never affected.
- **Container image (`dockers_v2`):** `ghcr.io/shorstophq/shorstop`, linux/amd64 + linux/arm64 as one multi-platform image, built with buildx from the same binaries as the archives (no second compile, so the image and archive binaries are identical). Tags are `v<version>`, plus `latest` on full releases only: a pre-release never moves `latest`, so a plain `docker pull` always gets a stable build. GitHub's registry was chosen over Docker Hub because it uses the workflow's own token (no stored secret) and sits next to the source. An SBOM attestation is attached, and OCI labels (`org.opencontainers.image.source` links the package to the repo).
- **Image signing (`docker_signs`):** keyless cosign, like `checksums.txt`, signing each pushed image by digest. Verify with `cosign verify --certificate-identity-regexp 'https://github.com/shorstophq/shorstop/.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/shorstophq/shorstop:v<version>`. The `artifacts:` key is left at its default. GoReleaser v2.19's source (`internal/pipe/sign/sign_docker.go`) shows the default selects exactly the `dockers_v2` images. `manifests` and `images` would also include them, but they exist for the legacy `dockers`/`docker_manifests` pipes.

- **Homebrew (`homebrew_casks`):** `brew install --cask shorstophq/tap/shorstop`, on macOS and Linux. GoReleaser writes `Casks/shorstop.rb` to `github.com/shorstophq/homebrew-tap` on each full release.
  - **A cask, not a formula:** GoReleaser v2.19 deprecates `brews` for prebuilt binaries in favor of casks, and Homebrew casks now cover Linux too.
  - **Tap trust (Homebrew 6+):** Homebrew ignores casks from non-official taps unless they're trusted. Installing by the fully qualified name trusts only that cask, so the documented one-liner needs no separate `brew trust` step. That's the narrowest trust Homebrew's docs recommend; don't tell users to trust the whole tap.
  - **Token:** the release workflow's `GITHUB_TOKEN` can't push to another repository, so GoReleaser uses `HOMEBREW_TAP_TOKEN`, a fine-grained token with Contents read/write on `homebrew-tap` only. `skip_upload` is `true` when the secret is missing, so a release without it skips the tap instead of failing. `auto` otherwise: pre-releases never reach the tap, so brew users only get full releases.
  - **Quarantine:** the binary isn't signed or notarized by Apple. Homebrew marks downloads with `com.apple.quarantine`, and macOS then kills the binary (SIGKILL, exit 137, seen in testing). A `postflight_steps` `run "/usr/bin/xattr" -dr com.apple.quarantine` clears it. That's the declarative steps DSL; Ruby `postflight do` blocks are deprecated in GoReleaser. *Tradeoff:* this bypasses Gatekeeper for this one binary. Homebrew has already verified the archive's SHA-256 from the cask, and `checksums.txt` is cosign-signed. Apple notarization ($99/year developer account) would remove the need.
  - **Completions are shipped, not generated:** `scripts/completions.sh` (a GoReleaser `before` hook) writes `completions/shorstop.{bash,zsh,fish}` from cobra into every archive, and the cask links them. The first attempt used `generate_completions_from_executable`, but Homebrew 7 runs it *before* postflight, while the binary is still quarantined, so all completions failed. Shipping the files also gives users of the plain archives completions. *Side note:* `:cobra` already adds the `completion` subcommand, so `args: [completion]` ran `completion completion bash`.
  - **Verified (2026-11-12, Homebrew 7.0.11, macOS Intel):** from a temporary local tap pointing at the snapshot archives (`file://`), with a cleared download cache: the install links the binary and three completions, the quarantine flag is removed, and `shorstop version` runs. The test tap, trust entry and install were removed afterwards. `brew style` reports four layout nits (stanza order and spacing) in GoReleaser's cask template; they're cosmetic and only enforced in Homebrew's official taps.

### `Dockerfile` (Phase 5)
- **`FROM scratch`:** the image is the static binary plus `LICENSE`, and nothing else. ShorStop makes no network calls, so it needs no CA certificates, and it needs no shell, libc or `/etc/passwd`. That leaves nothing for an image scanner to flag and nothing to patch. *Tradeoff:* there's no shell for `docker run … sh` debugging; use the release binary for that. A distroless base was considered; it would add CA certificates and a passwd file that nothing uses.
- **`USER 65532:65532`**, numeric because scratch has no user database (65532 is distroless's "nonroot" convention). Reading a mounted repository only needs the usual read permission. Writing a report into the mount: redirect stdout (`> shorstop.sarif`), or pass `--user "$(id -u):$(id -g)"` when the mount isn't writable by 65532. On Linux it usually isn't; Docker Desktop's file sharing on macOS ignores ownership, so it works there either way.
- **`WORKDIR /src`, `ENTRYPOINT ["/shorstop"]`, `CMD ["scan", "."]`:** `docker run -v "$PWD:/src" ghcr.io/shorstophq/shorstop` scans the mounted directory with no arguments, and any arguments replace `scan .` (`… scan --format sarif`, `… version`).
- **The binary comes from GoReleaser's build context** (`${TARGETPLATFORM}/shorstop`), so the Dockerfile only packages it; it can't be built with a plain `docker build .`. That's deliberate: there's one build of the code per release, not two that could differ.
- **Verified with a snapshot build (2026-11-12):** the images are 8.5 MB (amd64) and 7.9 MB (arm64), contain only `/shorstop` and `/LICENSE`, and run as 65532:65532. `version` reports the snapshot version. A mounted repository scans (read-only mount) with the same findings as the local binary. `--format sarif > file` produces valid SARIF on the host. `--fail-on high` exits 1. The arm64 image ran under emulation on an amd64 host.

### `.github/workflows/release.yml` (Phase 5)
- Runs on a version tag push, `v[0-9]+.[0-9]+.[0-9]+*` (`v0.1.0`, `v0.1.0-rc.1`). It was `v*` at first; that would also have matched a moving major tag such as `v1` for the Action and started a release that GoReleaser can't parse. **Least privilege:** the workflow grants nothing by default (`permissions: {}`), and the one job asks for `contents: write` (create the release) and `id-token: write` (keyless signing) only.
- **The tests run again before releasing** (`go vet`, `go test -race`): a tag on a broken commit fails instead of publishing broken binaries.
- Installs cosign and syft, then runs GoReleaser, all pinned to commit SHAs like CI. The job can publish, so it must run exactly the reviewed code.
- **For the image:** `packages: write` (push to ghcr.io), buildx (multi-platform builds and push), and a ghcr login with the workflow's own `GITHUB_TOKEN`. **No QEMU:** the Dockerfile has no `RUN` step, so no arm64 code executes during the build, and QEMU would be one more third-party action in a job that can publish.

### `action.yml` (Phase 5): the GitHub Action
- **Composite, not Docker.** A Docker container action runs only on Linux runners. It also can't use the image's non-root user, because it must write to `GITHUB_WORKSPACE`, which root owns. It also pulls an image on every run. The composite action works on Linux, macOS and Windows runners (x64 and ARM64; no Windows on ARM build yet), and installs the same release binary users download. *Tradeoff:* it depends on bash being available. Every GitHub-hosted runner has it, Windows through Git Bash.
- **Name "ShorStop PQC Scan"**, not "ShorStop": a Marketplace listing's name must be unique and can't match a GitHub user or organization the publisher doesn't own. `shorstop` is an unrelated dormant account. The name appears only in the Marketplace and the Actions UI; `uses:` follows the repository path.
- **Marketplace:** publish from the `v0.1.0` release (edit the release, tick the box), not by drafting a release by hand. Releases are created by GoReleaser from the tag, with the signed files attached.
- **Minimal use:** `uses: shorstophq/shorstop@v1` after checkout, with `security-events: write`. It scans the repository, writes SARIF and uploads it to code scanning.
- **Inputs:** `path`, `fail-on` (default `none`, so adopting it never breaks a build on day one; findings still show in the Security tab), `baseline`, `config`, `args` (extra flags, split on whitespace with no quoting, which is enough for flags and globs and avoids an `eval`), `sarif-file`, `upload-sarif`, `category` (keeps several runs apart, e.g. one per directory), `version`, `verify`, `install`. **Outputs:** `version`, `sarif-file`, `exit-code`.
- **No script injection:** inputs reach the scripts only through `env:`, never interpolated into script text with `${{ }}`. The version must match `vX.Y.Z[-pre]` before it's used in a URL or path.
- **Scripts in `action/install.sh` and `action/scan.sh`**, not inline YAML, so they can be run and tested locally (with `SHORSTOP_DOWNLOAD_BASE` pointing at a local copy) and linted as shell.

#### `install.sh`
- Maps `RUNNER_OS`/`RUNNER_ARCH` to GoReleaser's archive names (`shorstop_<version>_<os>_<arch>.tar.gz`, `.zip` on Windows).
- **`version: latest`** follows the redirect from `/releases/latest` to `/releases/tag/<tag>` with `curl`. That's not an API call, so there's no rate limit and no token. GitHub never counts a pre-release as latest, so before the first full release users must set `version`; the error message says so. *Why not tie the binary to the action's ref (`@v1.2.3` installs v1.2.3)?* `github.action_ref` is unreliable inside composite actions, and `@v1` or a SHA doesn't name a binary anyway. Pinning means setting `version`.
- **Verification, in order:**
  1. `cosign verify-blob` on `checksums.txt` with its Sigstore bundle, requiring the **exact** certificate identity `https://github.com/shorstophq/shorstop/.github/workflows/release.yml@refs/tags/<tag>`. That proves the file came from this repository's release workflow, for that tag. The README's manual command uses a regexp; the action can be strict because it knows the tag.
  2. The archive's SHA-256 against its line in `checksums.txt`. A download that's missing, swapped or tampered with is rejected before it's extracted.
  `verify: false` skips step 1 only, with a warning. Cosign comes from `sigstore/cosign-installer` (SHA-pinned) only when verification is on.
- `sha256sum` where present, `shasum -a 256` on macOS. Windows zips are extracted with PowerShell's `Expand-Archive`, because Git Bash's `tar` can't read zip.
- It installs into `$RUNNER_TEMP/shorstop-<tag>` and adds that directory to `GITHUB_PATH`, so later steps can call `shorstop` too.

#### `scan.sh`
- Runs `shorstop scan <path> --format sarif --output <file> --fail-on <level>`. The default report location is `$RUNNER_TEMP/shorstop.sarif`, outside the workspace, so it doesn't show up in the repository or in later scans.
- **Exit codes:** 0 and 1 continue (1 is recorded in `exit-code`), so the report is uploaded even when the threshold is crossed. A last step in `action.yml` then fails the job with an `::error` annotation. Exit code 2 (a usage or scanner error) fails immediately: there's no report to upload.
- **Subdirectory paths:** SARIF URIs are relative to the scanned directory, but code scanning resolves them against the repository root. For `path: services/api`, `jq` prefixes every `%SRCROOT%` URI with `services/api/`. Leading `./`, a trailing `/`, backslashes and an absolute path inside the workspace are normalised first. A path outside the repository gets a warning and no rewrite. *Note:* a baseline taken from the action's own SARIF for a subdirectory carries the prefix. Make baselines with the CLI in that directory, or scan from the root. A `--path-prefix` CLI flag would remove this step; it's left for later.
- Bash 3.2 compatible (Apple's `/bin/bash`): under `set -u`, an empty array is checked with `${#extra[@]}` before it's expanded.

#### Tests
- Run locally (2026-11-12) against the snapshot release, served with `file://`. Tests covered: installing on macOS/amd64 and Linux/arm64 archives; a tampered archive rejected; cosign missing with verify on; Windows ARM rejected; an injection-shaped `version` rejected; `latest` before any release. On the scan side: root, `./subdir/`, absolute workspace path, `fail-on high` (exit-code 1, script exits 0), extra args, a bad flag (exit 2), and a path outside the repo. Both scripts were run under bash 3.2 and 5.
- **CI `action` job** on ubuntu, macos and windows: it builds a release from the commit in the same layout, installs it through the action with `file://`, and checks the outputs, `shorstop` on PATH, the threshold failure and the URI prefixes. Not covered until the first real release: cosign verification against a real signature, and `latest` resolution.

---

### `LICENSE`
Apache 2.0, as the plan specifies. Downloaded verbatim from apache.org (sha256 `cfc7749b…3d30`), not retyped. Chosen over MIT for its explicit patent grant, which matters for a crypto tool that companies will adopt.

---

## Open, not decided
- ~~CI actions pinned to major tags~~: done, all workflows are pinned to commit SHAs (2026-11-03).
- Dependabot (or Renovate) to raise PRs for pinned action and Go module updates.
- A "hybrid" flag so the classical half of `X25519MLKEM768` isn't rated as quantum-vulnerable.
