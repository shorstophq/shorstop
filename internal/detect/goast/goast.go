// Package goast finds cryptography in Go source by parsing it, driven by the
// "goast" rules of the rule pack.
package goast

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"strconv"
	"strings"

	"github.com/shorstophq/shorstop/internal/detect"
	"github.com/shorstophq/shorstop/internal/rules"
)

// pkgRules holds the rules for one import path.
type pkgRules struct {
	onImport []*rules.Rule            // rules without match.call: fire on the import line
	calls    map[string][]*rules.Rule // match.call -> rules that fire on each call
}

// Detector is the Go AST detector. It is read-only after New, so one value is
// safe to share between workers.
type Detector struct {
	byImport map[string]*pkgRules // import path -> its rules
}

// New builds a detector from goast rules. Rules for other detectors are ignored.
func New(rs []*rules.Rule) *Detector {
	d := &Detector{byImport: make(map[string]*pkgRules)}
	for _, r := range rs {
		if r.Detector != rules.DetectorGoAST {
			continue
		}
		pr := d.byImport[r.Match.Import]
		if pr == nil {
			pr = &pkgRules{calls: make(map[string][]*rules.Rule)}
			d.byImport[r.Match.Import] = pr
		}
		if r.Match.Call == "" {
			pr.onImport = append(pr.onImport, r)
		} else {
			pr.calls[r.Match.Call] = append(pr.calls[r.Match.Call], r)
		}
	}
	return d
}

// Name implements detect.Detector.
func (*Detector) Name() string { return rules.DetectorGoAST }

// Supports implements detect.Detector: Go source files, test files included.
func (*Detector) Supports(p string, binary bool) bool {
	return !binary && strings.HasSuffix(p, ".go")
}

// Detect implements detect.Detector.
//
// A file that doesn't parse cleanly still yields the findings from the part
// that did parse, and the parse error is returned with them so the scan
// reports the file as only partly analysed.
func (d *Detector) Detect(ctx context.Context, f detect.File) ([]detect.Finding, error) {
	fset := token.NewFileSet()
	// Pass 1: imports only. The parser stops after the import block, so files
	// with no crypto imports (most of them) cost very little.
	af, err := parser.ParseFile(fset, "", f.Content, parser.ImportsOnly|parser.SkipObjectResolution)
	if af == nil {
		return nil, err
	}

	var out []detect.Finding
	selectors := make(map[string]*pkgRules) // local package name -> rules, for pkg.Func(...) calls
	var dotted []*pkgRules                  // dot imports: calls are bare Func(...)
	for _, imp := range af.Imports {
		ip, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			continue
		}
		pr := d.byImport[ip]
		if pr == nil {
			continue
		}
		line := fset.Position(imp.Pos()).Line
		for _, r := range pr.onImport {
			out = append(out, finding(r, line, 0, f.Content))
		}
		if len(pr.calls) == 0 {
			continue
		}
		switch name := localName(imp, ip); name {
		case "_":
			// A blank import can't be called; the import rule covers it.
		case ".":
			dotted = append(dotted, pr)
		default:
			selectors[name] = pr
		}
	}
	if len(selectors) == 0 && len(dotted) == 0 {
		return out, err
	}
	if cerr := ctx.Err(); cerr != nil {
		return out, cerr
	}

	// Pass 2: full parse, only because a matched import has call rules.
	af, err = parser.ParseFile(fset, "", f.Content, parser.SkipObjectResolution)
	if af == nil {
		return out, err
	}
	ast.Inspect(af, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var rs []*rules.Rule
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr: // rsa.GenerateKey(...)
			if x, ok := fn.X.(*ast.Ident); ok {
				if pr := selectors[x.Name]; pr != nil {
					rs = pr.calls[fn.Sel.Name]
				}
			}
		case *ast.Ident: // GenerateKey(...) after a dot import
			for _, pr := range dotted {
				rs = append(rs, pr.calls[fn.Name]...)
			}
		}
		if len(rs) == 0 {
			return true
		}
		line := fset.Position(call.Pos()).Line
		for _, r := range rs {
			bits := 0
			if r.Match.KeySizeArg != nil && *r.Match.KeySizeArg < len(call.Args) {
				bits = intLiteral(call.Args[*r.Match.KeySizeArg])
			}
			out = append(out, finding(r, line, bits, f.Content))
		}
		return true
	})
	return out, err
}

// localName returns the name an import is referred to by in the file: its
// alias if it has one, otherwise the last path element. That equals the
// package name for every path the rule pack lists (standard library and
// golang.org/x/crypto); it would be wrong for a path ending in a major
// version such as /v2, which no rule uses.
func localName(imp *ast.ImportSpec, importPath string) string {
	if imp.Name != nil {
		return imp.Name.Name
	}
	return path.Base(importPath)
}

// intLiteral returns the value of an integer literal such as 2048, 0x800 or
// 2_048, or 0 for anything else (a constant, variable or expression).
func intLiteral(e ast.Expr) int {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0
	}
	v, err := strconv.ParseInt(lit.Value, 0, 32)
	if err != nil || v <= 0 {
		return 0
	}
	return int(v)
}

// finding builds a Finding from a rule. A key size read from the code (bits)
// takes the place of the rule's fixed one.
func finding(r *rules.Rule, line, bits int, content []byte) detect.Finding {
	ks := r.KeySize
	if bits > 0 {
		ks = bits
	}
	return detect.Finding{
		RuleID:     r.ID,
		Algorithm:  r.Algorithm,
		Primitive:  r.Primitive,
		KeySize:    ks,
		Mode:       r.Mode,
		Line:       line,
		Snippet:    detect.Snippet(content, line),
		Confidence: r.Confidence,
	}
}
