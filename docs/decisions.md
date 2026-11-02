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

### `var idPattern` (`^[a-z0-9]+(-[a-z0-9]+)*$`)
IDs appear in `// shorstop:ignore <rule-id>`, SARIF rule IDs and baselines, so they're restricted to characters that need no quoting anywhere. The header of `rules.yaml` says IDs are never renamed or reused, because that would silently break users' suppressions.

### `type Pack` / `type Rule` / `type Match`
- **`Match` is one struct holding every detector's fields**, not a per-detector type or an interface. A tagged union in YAML would need a custom `UnmarshalYAML`, and that loses strict decoding (see `Parse`). Instead, `validate` rejects fields that don't belong to the rule's detector, which gives the same safety with plain struct decoding.
- `KeySizeArg` is `*int` because argument 0 is a valid index. A pointer tells "unset" apart from "0".
- `Rule.re` is unexported and filled by `validate`, so **each regex compiles once at load**, as the plan requires. Detectors read it through `Regexp()` and can't replace it.
- `Rule.Confidence` is filled with the detector default during validation, so consumers never handle the empty case.

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
- `key_size` together with `key_size_arg` or a `(?P<bits>)` group is rejected: two sources for one value would be ambiguous.
- **Mutates the rule** (default confidence, compiled regex). It's called once, on a value `Parse` owns, before the pack is returned, so nothing else can see a half-filled rule.
- **Regex engine is Go's RE2**: linear time, so a user-supplied pattern can't cause catastrophic backtracking during a scan. The cost is no lookarounds or backreferences in rule patterns.

### `rules.yaml` content (initial)
- 22 `goast` rules: every crypto import the plan lists, plus calls where the call adds information. `rsa.GenerateKey` takes its key size from argument 1. `des.NewTripleDESCipher` means 3DES, not DES. `ecdh.X25519` names the curve.
- `crypto/mlkem` and `crypto/mldsa` (both in Go 1.27's standard library; checked with `go list std`) are included so reports show quantum-safe progress.
- SHA-256/512/SHA-3 are included even though they're acceptable: a CBOM is an inventory, not just a list of problems.
- 3 `regex` rules show the pattern schema (`generic-aes128-cbc`, `generic-rsa-bits` with a `bits` group, `generic-3des`). The full regex set comes with the regex detector.
- Flow mappings (`match: { import: crypto/rsa }`) keep each rule compact. Patterns are single-quoted, so `\b` reaches RE2 unescaped.

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
- Dependencies: **`go.uber.org/goleak`** (tests only) and **`go.yaml.in/yaml/v3`** (rule pack; see `internal/rules`).

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
