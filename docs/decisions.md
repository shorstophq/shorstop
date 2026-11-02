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
`covers` is a generic helper ("b is unknown, or equals a") used for the four detail fields, so int and string fields use the same rule. Pointer arguments avoid copying the ~250-byte `Finding` on every comparison.

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

## `cmd/shorstop/main.go` — `func detectors() ([]detect.Detector, error)`
Builds every detector from `rules.Builtin()`, in one place, so `run` stays about flags and output. A broken embedded pack exits with code 2 and `loading rules: …`. `TestBuiltinLoads` makes that unreachable for shipped builds, but the path exists for `--rules` later. Order: goast, cert, config, regex. **Order matters for duplicates:** when `detect.Dedupe` finds two identical findings, the earlier detector's is kept. The parsing detectors come before regex, so the more precise rule ID survives.

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
  - Recursive with backtracking at each `**`: simple and obviously correct. Worst case is exponential with many `**` in one pattern (e.g. `**/a/**/b/**/c`), but real patterns have one or two, and paths are shallow.
  - Trailing `/**` requires at least one more segment, so `abc/**` matches everything *inside* `abc` but not `abc` itself (git's documented behaviour).
- **Data structures:** sub-slicing (`parts[i:]`) shares the backing array, so recursion allocates nothing.

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

### Constants `exitOK = 0`, `exitError = 2`, `defaultMaxFileSize = 2 << 20`
- `1` is deliberately unused, reserved for "findings over `--fail-on`" (Phase 5), so CI can tell "your code has RSA" from "the scanner crashed".
- Usage errors, runtime errors and **cancellation** all use `2`. The shell convention for Ctrl+C is 130, but the plan's contract defines only 0, 1 and 2. A cancelled scan is an incomplete scan, so it's treated as an error.
- `2 << 20` = 2 MiB, the plan's default limit.

### `func main()`
- **What it does:** sets up signal handling, calls `run`, exits with its code.
- **Decisions & tradeoffs:**
  - **`signal.NotifyContext` for SIGINT and SIGTERM.** Ctrl+C and CI job cancellation (which sends SIGTERM) both cancel the scan context, so the scan stops cleanly and reports "scan cancelled" instead of dying mid-write.
  - **`context.AfterFunc(ctx, stop)`.** After the first signal, normal signal behaviour is restored, so a **second Ctrl+C kills immediately**. Without this, a hung detector would make the process ignore Ctrl+C entirely.
  - `os.Exit` is called only after `run` returns, so every `defer` inside `run` has already run (output flushed and closed).

### `func run(ctx, args, stdout, stderr) int`
- **What it does:** parses flags, runs the scan, prints warnings and output, returns an exit code.
- **Decisions & tradeoffs:**
  - **Takes a `context.Context`.** Tests can pass a cancelled context to check the cancellation path without sending real signals.
  - **`io.Writer`s instead of `os.Stdout`.** Tests capture output in a buffer; `--output` just changes the destination.
  - **Own `flag.NewFlagSet` with `ContinueOnError`.** The global flag set panics with "flag redefined" when tests call `run` repeatedly, and `ExitOnError` would call `os.Exit` from inside the flag package, bypassing our exit codes.
  - **`-h` returns 0**; asking for help isn't a failure.
  - **`--workers` default is `runtime.GOMAXPROCS(0)`, not `runtime.NumCPU()` (plan said NumCPU).** Since Go 1.25, `GOMAXPROCS` respects container CPU limits (cgroups). In a CI container limited to 2 CPUs on a 64-core host, `NumCPU` returns 64 and would oversubscribe the CPU. `GOMAXPROCS` returns 2.
  - **`--format` isn't added yet.** It belongs with the reporters (Phase 4). A flag that accepts `json` but prints text would be misleading.
  - **No arguments now scans `.`** (default `--dir`), instead of printing usage as in Phase 0. That matches the plan's flag defaults.
  - **Extra positional arguments are an error** (`shorstop ./src`). Silently ignoring them would scan the wrong directory. A positional directory argument can come with cobra in Phase 5.
  - **Warnings go to stderr, results to stdout.** `shorstop --list-files | wc -l` and `--format json > cbom.json` (later) stay clean.
  - **With `--list-files`, the summary moves to stderr**, so stdout holds only paths, one per line, and pipes cleanly into other tools.
  - **No detectors are registered yet** (`var dets []detect.Detector`). The crawler is fully exercised. Phase 2 only needs to fill in this slice.
- **Data structures:** `*flag.FlagSet`; pointer results from `fs.Bool`/`fs.String`; custom `flag.Value` types `byteSize` and `stringList`.

### `func writeOutput(path, stdout, write) error`
- **What it does:** writes output to a file (`--output`) or to stdout, through a buffer.
- **Decisions & tradeoffs:**
  - **`bufio.Writer`.** Listing 100k files with unbuffered writes would cost 100k `write` syscalls. Buffered, it's a few dozen.
  - **The `Close` error is checked** for files. On some filesystems (network, full disk), `Close` is the first place a failed write shows up. Ignoring it could report success for a truncated file.
  - **Takes a `func(io.Writer) error` callback**, so the open/buffer/flush/close logic lives in one place, and each output mode (list, summary, later each reporter) only writes content.
  - Tradeoff: the file isn't written atomically (temp file plus rename). A crash mid-write leaves a partial file. Acceptable for a report; revisit for `--baseline` files in Phase 5, where a corrupt baseline would matter.

### `func summary(res) string`
- One line with every `Stats` counter. It's a stand-in until the terminal reporter (Phase 4) adds colour and severity grouping. It shows **every skip reason**, so a user can see at a glance why the count is lower than expected.

### `func resolveVersion() string`
- Checks, in order:
  1. ldflags `version` (`make build`, GoReleaser).
  2. `debug.ReadBuildInfo().Main.Version`: `go install …@v1.2.3` doesn't pass ldflags, but Go records the module version in the binary.
  3. `"dev"` for local builds, where Go reports the meaningless string `"(devel)"`.
- Not cached: it runs once per process.

---

## `cmd/shorstop/flags.go`

### `type byteSize int64` with `Set` / `String`
- **What it does:** parses `--max-file-size` values like `512KB`, `2MB`, `2 MiB`.
- **Decisions & tradeoffs:**
  - **Implements `flag.Value`**, so parsing errors appear as normal flag errors with usage, and the default shows in `-h` as `2MB`, not `2097152`.
  - **Binary units (1KB = 1024).** This is the common convention for file sizes, and what the plan's "2MB" meant. Both `KB` and `KiB` are accepted, so users don't have to know the distinction. Tradeoff: `KB` technically means 1000 in SI. Documented in the flag help.
  - **Case-insensitive, spaces allowed** (`2 mb`). Typos in CI YAML are common, and leniency costs nothing.
  - **Whole numbers only** (`1.5MB` rejected). Fractional bytes would need rounding rules for no real benefit.
  - **Overflow check** before multiplying, so `9999999999GB` errors instead of silently wrapping to a negative or tiny limit.
  - Units are checked **longest suffix first** (`KIB` before `B`), so `2MB` isn't read as "2M" plus a stray "B".
- **Data structures:** a slice of `{suffix, mult}` structs, not a map, because order matters for longest-suffix matching and Go map iteration order is random.

### `type stringList []string`
- A repeatable flag: `--exclude a --exclude b`. Repeating is the standard flag-package idiom.
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

### `internal/crawler/ignore_test.go`
- One table of `{pattern, path, isDir, want}` covering each gitignore rule. A failure names the exact pattern and path.
- The stack test pushes and pops **in real walk order**, because `popTo` relies on depth-first order. (An earlier draft pushed out of order and failed for that reason, not because of a bug.)

### `cmd/shorstop/main_test.go`, `flags_test.go`
- End-to-end through `run` against a temp tree: flags, `--list-files`, `--exclude`, `--output`, bad sizes, a missing directory, cancellation.
- They change the global `version`, so they can't use `t.Parallel()`. Acceptable at this size.

---

## Build and tooling (no methods; one entry per file)

### `go.mod` — `go 1.27` + `toolchain go1.27.3`
- **Minimum is 1.27, the latest release**, by project-owner decision (2026-10-24). On that date go.dev listed 1.27.3 and 1.26.10 as supported.
- **Tradeoff:** users on 1.26 can't `go install` without Go downloading 1.27 for them. Prebuilt binaries aren't affected. In return, any 1.27 feature can be used.
- **`go 1.27`** is the minimum language/API version required of users. **`toolchain go1.27.3`** only says which Go this repo's builds use: an older local Go downloads it automatically. Bump it with each Go patch release.
- Dependencies: **`go.uber.org/goleak`** (tests only), **`go.yaml.in/yaml/v3`** (rule pack; see `internal/rules`), **`golang.org/x/crypto`** (OpenSSH key parsing; see `internal/detect/cert`).

### `Makefile`
- `CGO_ENABLED=0`: static binary for `FROM scratch` images, easy cross-compiling.
- `-trimpath`: strips local paths from the binary, for privacy and reproducibility.
- No `-s -w` stripping locally, so panics keep readable stack traces.
- `lint` and `release-snapshot` print an install hint when the tool is missing.

### `.golangci.yml`
The `standard` set plus `errorlint`, `misspell`, `unconvert`, `gocritic`. `gosec` is left out for now (it flags every `crypto/md5` and `crypto/sha1` reference, which the detectors must contain on purpose). `testdata/` is excluded.
- **`std-error-handling` exclusion preset** (added 2026-11-02, the first time the linter ran with v2.15.0). Before it was added, errcheck reported 7 issues: `defer f.Close()` on files opened read-only (`readIgnoreFile`, `scanFile`), and `fmt.Fprint*` to stdout/stderr in `run`. Neither error can be acted on: a read-only Close can't lose data, and if the terminal write fails there's nowhere to report the failure.
  - *Options:* (a) `_ = f.Close()` / `_, _ = fmt.Fprintf(...)` at each call site; (b) errcheck's `exclude-functions` list; (c) the preset. **Chose (c):** the preset covers exactly these standard-library cases, and call sites stay idiomatic.
  - *Tradeoff:* errcheck will also ignore an unchecked `Close` on a **writable** file, where the error does matter. Rule: writable files (e.g. `writeOutput`'s `--output` file) must check `Close` explicitly, and code review has to enforce that because the linter no longer will.

### `.github/workflows/ci.yml`
A matrix of Go 1.27 (floor) and stable. Both are 1.27 today; they'll diverge when 1.28 ships, without editing the file. `permissions: contents: read`. Actions are pinned to major tags; switch to SHA pins before public launch.

---

### `LICENSE`
Apache 2.0, as the plan specifies. Downloaded verbatim from apache.org (sha256 `cfc7749b…3d30`), not retyped. Chosen over MIT for its explicit patent grant, which matters for a crypto tool that companies will adopt.

---

## Open, not decided
- CI actions are still pinned to major tags; switch them to SHA pins before public launch.
