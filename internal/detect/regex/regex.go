// Package regex finds cryptography in any text file by matching the
// "regex" rules of the rule pack line by line.
package regex

import (
	"bytes"
	"context"
	"path"
	"slices"
	"strings"

	"github.com/shorstophq/shorstop/internal/detect"
	"github.com/shorstophq/shorstop/internal/rules"
)

// ctxCheckLines is how often, in lines, Detect checks for cancellation.
const ctxCheckLines = 4096

// lowerASCII maps each byte to its ASCII lower case; other bytes map to
// themselves. Keywords are ASCII, so this is all the case-folding they need,
// and it never changes a line's length.
var lowerASCII = func() (t [256]byte) {
	for i := range t {
		t[i] = byte(i)
		if 'A' <= i && i <= 'Z' {
			t[i] = byte(i + 'a' - 'A')
		}
	}
	return t
}()

// triBits is the size, in bits, of a ruleSet's trigram filter: 1<<16 bits
// is 8 KB, small enough to stay in cache.
const triBits = 16

// triHash spreads a 24-bit trigram over the filter.
func triHash(tri uint32) uint32 { return (tri * 2654435761) >> (32 - triBits) }

// ruleSet is the rules that apply to one kind of file, with their keywords
// indexed by first trigram so a line is scanned once for all of them.
type ruleSet struct {
	rules     []*rules.Rule
	keywords  [][]byte                  // distinct, lower-case
	byKeyword [][]int                   // keywords[i] -> indexes into rules
	byTri     map[uint32][]int          // first three bytes of a keyword -> keyword indexes
	filter    [1 << triBits / 64]uint64 // bit triHash(t) set for each key t of byTri
}

func newRuleSet(rs []*rules.Rule) *ruleSet {
	s := &ruleSet{rules: rs, byTri: make(map[uint32][]int)}
	index := make(map[string]int) // keyword -> index in s.keywords
	for ri, r := range rs {
		for _, k := range r.Match.Keywords {
			ki, ok := index[k]
			if !ok {
				ki = len(s.keywords)
				index[k] = ki
				s.keywords = append(s.keywords, []byte(k))
				s.byKeyword = append(s.byKeyword, nil)
				tri := uint32(k[0])<<16 | uint32(k[1])<<8 | uint32(k[2])
				s.byTri[tri] = append(s.byTri[tri], ki)
				h := triHash(tri)
				s.filter[h/64] |= 1 << (h % 64)
			}
			s.byKeyword[ki] = append(s.byKeyword[ki], ri)
		}
	}
	return s
}

// lineRules appends to dst the index of every rule with a keyword in line,
// each once, in rule order. seen and stamp de-duplicate without clearing a
// map per line: seen[ri] == stamp means rule ri is already in dst.
func (s *ruleSet) lineRules(dst []int, line []byte, seen []int, stamp int) []int {
	if len(line) < rules.MinKeywordLen {
		return dst
	}
	tri := uint32(lowerASCII[line[0]])<<8 | uint32(lowerASCII[line[1]])
	for i := 2; i < len(line); i++ {
		tri = (tri<<8 | uint32(lowerASCII[line[i]])) & 0xFFFFFF
		h := triHash(tri)
		if s.filter[h/64]&(1<<(h%64)) == 0 {
			continue // no keyword starts with these three bytes: the common case
		}
		start := i - 2
		for _, ki := range s.byTri[tri] {
			kw := s.keywords[ki]
			if start+len(kw) > len(line) || !equalFoldASCII(line[start:start+len(kw)], kw) {
				continue
			}
			for _, ri := range s.byKeyword[ki] {
				if seen[ri] != stamp {
					seen[ri] = stamp
					dst = append(dst, ri)
				}
			}
		}
	}
	slices.Sort(dst)
	return dst
}

// equalFoldASCII reports whether b, lower-cased, equals lower.
func equalFoldASCII(b, lower []byte) bool {
	for i, c := range b {
		if lowerASCII[c] != lower[i] {
			return false
		}
	}
	return true
}

// Detector is the regex detector. It is read-only after New, so one value
// is safe to share between workers.
type Detector struct {
	byExt   map[string]*ruleSet // lower-case extension -> generic + language rules
	generic *ruleSet            // files of no known language: rules without languages
}

// New builds a detector from regex rules. Rules for other detectors are
// ignored. Each rule set keeps the pack's order, so findings on one line come
// out in rule order.
func New(rs []*rules.Rule) *Detector {
	var generic []*rules.Rule
	for _, r := range rs {
		if r.Detector == rules.DetectorRegex && len(r.Languages) == 0 {
			generic = append(generic, r)
		}
	}
	d := &Detector{byExt: make(map[string]*ruleSet), generic: newRuleSet(generic)}
	for lang, exts := range rules.Languages {
		var set []*rules.Rule
		for _, r := range rs {
			if r.Detector == rules.DetectorRegex && (len(r.Languages) == 0 || slices.Contains(r.Languages, lang)) {
				set = append(set, r)
			}
		}
		s := newRuleSet(set)
		for _, ext := range exts {
			d.byExt[ext] = s
		}
	}
	return d
}

func (d *Detector) setFor(p string) *ruleSet {
	if s, ok := d.byExt[strings.ToLower(path.Ext(p))]; ok {
		return s
	}
	return d.generic
}

// Name implements detect.Detector.
func (*Detector) Name() string { return rules.DetectorRegex }

// Supports implements detect.Detector: text files that at least one rule
// applies to.
func (d *Detector) Supports(p string, binary bool) bool {
	return !binary && len(d.setFor(p).rules) > 0
}

// Detect implements detect.Detector. It reports each distinct match of each
// rule on each line. Comments are matched like code: telling them apart
// needs a parser per language, and commented-out crypto is still worth
// seeing.
func (d *Detector) Detect(ctx context.Context, f detect.File) ([]detect.Finding, error) {
	set := d.setFor(f.Path)
	if len(set.rules) == 0 {
		return nil, nil
	}

	var out []detect.Finding
	var (
		seen   = make([]int, len(set.rules)) // per-rule stamp for lineRules
		active []int                         // rules with a keyword on the current line
		hits   []hit                         // their matches; both reused across lines
	)
	content := f.Content
	for lineNo, start := 1, 0; start <= len(content); lineNo++ {
		if lineNo%ctxCheckLines == 0 {
			if err := ctx.Err(); err != nil {
				return out, err
			}
		}
		end := bytes.IndexByte(content[start:], '\n')
		if end < 0 {
			end = len(content)
		} else {
			end += start
		}
		line := bytes.TrimSuffix(content[start:end], []byte("\r"))
		start = end + 1

		active = set.lineRules(active[:0], line, seen, lineNo)
		if len(active) == 0 {
			continue
		}
		hits = hits[:0]
		for _, ri := range active {
			r := set.rules[ri]
			for _, m := range r.MatchAll(line) {
				hits = append(hits, hit{r: r, m: m})
			}
		}
		if len(hits) == 0 {
			continue
		}
		snippet := detect.SnippetOf(line)
		for _, h := range hits {
			if h.coveredBy(hits) {
				continue
			}
			out = append(out, detect.Finding{
				RuleID:     h.r.ID,
				Algorithm:  h.r.Algorithm,
				Primitive:  h.r.Primitive,
				KeySize:    h.m.KeySize,
				Mode:       h.m.Mode,
				Line:       lineNo,
				Snippet:    snippet,
				Confidence: h.r.Confidence,
			})
		}
	}
	return out, nil
}

// hit is one rule's match on the current line.
type hit struct {
	r *rules.Rule
	m rules.LineMatch
}

// coveredBy reports whether a generic hit repeats what a language rule found
// on the same line, such as generic-3des and cs-3des both matching
// "TripleDES.Create()". The language rule is kept: its ID says which API was
// used. Hits from two generic rules, or two language rules, are all kept.
func (h hit) coveredBy(line []hit) bool {
	if len(h.r.Languages) > 0 {
		return false
	}
	for _, o := range line {
		if len(o.r.Languages) > 0 && o.r.Algorithm == h.r.Algorithm {
			return true
		}
	}
	return false
}
