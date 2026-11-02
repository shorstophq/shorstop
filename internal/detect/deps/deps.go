// Package deps finds known cryptographic libraries among a project's
// declared dependencies (manifests and lockfiles), driven by the "deps"
// rules of the rule pack.
//
// A dependency says a library is present, not how it is used, so findings
// are low-confidence hints: they point at code the other detectors may not
// read (minified bundles, vendored binaries, unsupported languages).
package deps

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/rules"
)

// dep is one declared dependency.
type dep struct {
	name    string // as the file spells it
	version string // exact version, or "" for a range/constraint
	line    int    // 1-based
}

// parser reads one kind of dependency file.
type parser struct {
	eco   string // a rules.Ecosystems value
	parse func([]byte) ([]dep, error)
}

// parserFor picks the parser for a path by file name. Ok is false for
// files that aren't dependency files.
func parserFor(p string) (parser, bool) {
	base := path.Base(p)
	switch base {
	case "go.mod":
		return parser{"golang", goMod}, true
	case "package.json":
		return parser{"npm", packageJSON}, true
	case "package-lock.json", "npm-shrinkwrap.json":
		return parser{"npm", npmLock}, true
	case "yarn.lock":
		return parser{"npm", yarnLock}, true
	case "pnpm-lock.yaml":
		return parser{"npm", pnpmLock}, true
	case "poetry.lock":
		return parser{"pypi", tomlPackages}, true
	case "pyproject.toml":
		return parser{"pypi", pyproject}, true
	case "Pipfile.lock":
		return parser{"pypi", pipfileLock}, true
	case "pom.xml":
		return parser{"maven", pom}, true
	case "build.gradle", "build.gradle.kts":
		return parser{"maven", gradle}, true
	case "composer.json":
		return parser{"composer", composerJSON}, true
	case "composer.lock":
		return parser{"composer", composerLock}, true
	case "Cargo.toml":
		return parser{"cargo", cargoToml}, true
	case "Cargo.lock":
		return parser{"cargo", tomlPackages}, true
	case "Gemfile.lock":
		return parser{"gem", gemLock}, true
	case "packages.config", "Directory.Packages.props":
		return parser{"nuget", nugetXML}, true
	}
	lower := strings.ToLower(base)
	switch path.Ext(lower) {
	case ".csproj", ".fsproj", ".vbproj":
		return parser{"nuget", nugetXML}, true
	case ".txt", ".in": // requirements.txt, requirements-dev.txt, requirements/base.txt, pip-tools .in
		if strings.HasPrefix(lower, "requirements") || path.Base(path.Dir(p)) == "requirements" {
			return parser{"pypi", requirementsTxt}, true
		}
	}
	return parser{}, false
}

// normalize makes two spellings of one package name compare equal, the way
// each ecosystem's registry does.
func normalize(eco, name string) string {
	switch eco {
	case "pypi": // PEP 503
		return pypiSep.ReplaceAllString(strings.ToLower(name), "-")
	case "cargo": // crates.io treats - and _ as the same
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	case "npm", "composer", "gem", "nuget":
		return strings.ToLower(name)
	}
	return name // golang, maven: case-sensitive
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// purl builds a Package URL (github.com/package-url/purl-spec), the
// identifier CycloneDX uses for components.
func purl(eco, name, version string) string {
	var p string
	switch eco {
	case "maven":
		group, artifact, _ := strings.Cut(name, ":")
		p = "pkg:maven/" + group + "/" + artifact
	case "npm":
		p = "pkg:npm/" + strings.Replace(name, "@", "%40", 1) // scoped: @scope/name
	case "pypi":
		p = "pkg:pypi/" + normalize(eco, name)
	default:
		p = "pkg:" + eco + "/" + name
	}
	if version != "" {
		p += "@" + strings.ReplaceAll(url.PathEscape(version), "+", "%2B")
	}
	return p
}

// index holds one ecosystem's rules.
type index struct {
	exact    map[string][]*rules.Rule // normalized name -> rules
	prefixes []prefixRule             // trailing-"*" rules, in pack order
}

type prefixRule struct {
	prefix string // normalized, without the "*"
	rule   *rules.Rule
}

// Detector is the dependency detector. It is read-only after New, so one
// value is safe to share between workers.
type Detector struct {
	byEco map[string]*index
}

// New builds a detector from deps rules. Rules for other detectors are
// ignored.
func New(rs []*rules.Rule) *Detector {
	d := &Detector{byEco: make(map[string]*index)}
	for _, r := range rs {
		if r.Detector != rules.DetectorDeps {
			continue
		}
		eco := r.Match.Ecosystem
		ix := d.byEco[eco]
		if ix == nil {
			ix = &index{exact: make(map[string][]*rules.Rule)}
			d.byEco[eco] = ix
		}
		if prefix, wild := strings.CutSuffix(r.Match.Package, "*"); wild {
			ix.prefixes = append(ix.prefixes, prefixRule{normalize(eco, prefix), r})
		} else {
			n := normalize(eco, r.Match.Package)
			ix.exact[n] = append(ix.exact[n], r)
		}
	}
	return d
}

func (ix *index) match(norm string) []*rules.Rule {
	out := ix.exact[norm]
	for _, p := range ix.prefixes {
		if strings.HasPrefix(norm, p.prefix) {
			out = append(slices.Clip(out), p.rule)
		}
	}
	return out
}

// Name implements detect.Detector.
func (*Detector) Name() string { return rules.DetectorDeps }

// Supports implements detect.Detector: dependency manifests and lockfiles
// of an ecosystem that has rules.
func (d *Detector) Supports(p string, binary bool) bool {
	if binary {
		return false
	}
	ps, ok := parserFor(p)
	return ok && d.byEco[ps.eco] != nil
}

// Detect implements detect.Detector. A file that doesn't parse gives no
// findings and an error; a half-read lockfile could miss libraries silently.
func (d *Detector) Detect(ctx context.Context, f detect.File) ([]detect.Finding, error) {
	ps, ok := parserFor(f.Path)
	if !ok {
		return nil, nil
	}
	ix := d.byEco[ps.eco]
	if ix == nil {
		return nil, nil
	}
	deps, err := ps.parse(f.Content)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path.Base(f.Path), err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lines := splitLines(f.Content)
	var out []detect.Finding
	for _, dp := range deps {
		for _, r := range ix.match(normalize(ps.eco, dp.name)) {
			fd := detect.Finding{
				RuleID:     r.ID,
				Algorithm:  r.Algorithm,
				Primitive:  r.Primitive,
				KeySize:    r.KeySize,
				Mode:       r.Mode,
				Line:       dp.line,
				Confidence: r.Confidence,
				PURL:       purl(ps.eco, dp.name, dp.version),
			}
			if dp.line >= 1 && dp.line <= len(lines) {
				fd.Snippet = detect.SnippetOf(lines[dp.line-1])
			}
			out = append(out, fd)
		}
	}
	slices.SortStableFunc(out, func(a, b detect.Finding) int { return cmp.Compare(a.Line, b.Line) })
	return out, nil
}
