package detect

import (
	"cmp"
	"slices"
)

// confidenceRank orders confidence levels; unknown values rank lowest.
var confidenceRank = map[string]int{"low": 1, "medium": 2, "high": 3}

// Dedupe merges findings that describe the same thing on the same line,
// typically one line seen by two detectors: `Ciphers aes128-ctr` in an
// sshd_config is matched by both the regex and the config detector.
//
// Finding a subsumes finding b when they share a line and a subject
// (algorithm, asset type, material type, protocol, package) and every detail b states
// (key size, mode, parameter set, primitive) a states the same way; b may
// leave any of them unknown. b is then dropped, and a keeps the higher of
// the two confidences. Findings that disagree on a stated detail, such as
// AES-256-GCM and AES-128-CTR on one line, are both kept.
//
// Certificate findings are never merged: two certificates can't share a line.
// The input order is kept for what remains. fs is reordered in place and
// the result shares its backing array.
func Dedupe(fs []Finding) []Finding {
	if len(fs) < 2 {
		return fs
	}
	// Group by line without losing the original order: sort indexes.
	idx := make([]int, len(fs))
	for i := range idx {
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(a, b int) int { return cmp.Compare(fs[a].Line, fs[b].Line) })

	drop := make([]bool, len(fs))
	for start := 0; start < len(idx); {
		end := start + 1
		for end < len(idx) && fs[idx[end]].Line == fs[idx[start]].Line {
			end++
		}
		group := idx[start:end]
		for _, i := range group {
			if drop[i] {
				continue
			}
			for _, j := range group {
				if i == j || drop[j] || !subsumes(&fs[i], &fs[j]) {
					continue
				}
				// When both subsume each other (identical details), keep the
				// earlier one, so the result doesn't depend on loop order.
				if subsumes(&fs[j], &fs[i]) && j < i {
					continue
				}
				if confidenceRank[fs[j].Confidence] > confidenceRank[fs[i].Confidence] {
					fs[i].Confidence = fs[j].Confidence
				}
				drop[j] = true
			}
		}
		start = end
	}

	out := fs[:0]
	for i := range fs {
		if !drop[i] {
			out = append(out, fs[i])
		}
	}
	return out
}

// subsumes reports whether a says everything b says about the same subject.
func subsumes(a, b *Finding) bool {
	if a.Cert != nil || b.Cert != nil {
		return false
	}
	if a.Line != b.Line || a.Algorithm != b.Algorithm || a.AssetType != b.AssetType ||
		a.MaterialType != b.MaterialType || a.Protocol != b.Protocol || a.PURL != b.PURL {
		return false
	}
	return covers(a.KeySize, b.KeySize) && covers(a.Mode, b.Mode) &&
		covers(a.ParameterSet, b.ParameterSet) && covers(a.Primitive, b.Primitive)
}

// covers: b's value is unknown, or equal to a's.
func covers[T comparable](a, b T) bool {
	var zero T
	return b == zero || a == b
}
