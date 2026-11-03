package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/shorstop/shorstop/internal/classify"
	"github.com/shorstop/shorstop/internal/detect"
)

// rated is a finding with its rating.
type rated struct {
	f detect.Finding
	r classify.Result
}

// assetGroup is every finding of one asset with one rating: "MD5, BROKEN,
// critical" with the 22 places it was seen.
type assetGroup struct {
	label string
	r     classify.Result
	items []rated
}

// severities lists the severities reports show, most severe first.
var severities = []classify.Severity{classify.Critical, classify.High, classify.Medium, classify.Low, classify.Info}

// groupFindings rates findings and groups them by asset and rating, most
// severe first, then most frequent, then by name. Findings that need no
// action (info) are dropped unless includeInfo is set.
func groupFindings(fs []detect.Finding, includeInfo bool) []assetGroup {
	idx := make(map[string]int)
	var groups []assetGroup
	for _, f := range fs {
		r := classify.Classify(f)
		if r.Severity == classify.Info && !includeInfo {
			continue
		}
		label := groupLabel(f)
		key := strings.Join([]string{string(r.Severity), label, string(r.Status), r.Reason}, "\x00")
		i, ok := idx[key]
		if !ok {
			i = len(groups)
			idx[key] = i
			groups = append(groups, assetGroup{label: label, r: r})
		}
		groups[i].items = append(groups[i].items, rated{f, r})
	}
	slices.SortStableFunc(groups, func(a, b assetGroup) int {
		return cmp.Or(
			cmp.Compare(b.r.Severity.Rank(), a.r.Severity.Rank()),
			cmp.Compare(len(b.items), len(a.items)),
			cmp.Compare(a.label, b.label),
		)
	})
	return groups
}

// Counts are a scan's findings by severity, plus how many are quantum-safe.
type Counts struct {
	BySeverity  map[classify.Severity]int
	QuantumSafe int
}

// Count rates every finding.
func Count(fs []detect.Finding) Counts {
	c := Counts{BySeverity: make(map[classify.Severity]int)}
	for _, f := range fs {
		r := classify.Classify(f)
		c.BySeverity[r.Severity]++
		if r.Status == classify.QuantumSafe {
			c.QuantumSafe++
		}
	}
	return c
}

// String is the plan's summary suffix: " · 12 critical · 48 high · 3
// quantum-safe". Severities with no findings, and info, are left out.
func (c Counts) String() string {
	var b strings.Builder
	for _, sev := range severities[:4] {
		if n := c.BySeverity[sev]; n > 0 {
			fmt.Fprintf(&b, " · %d %s", n, sev)
		}
	}
	if c.QuantumSafe > 0 {
		fmt.Fprintf(&b, " · %d quantum-safe", c.QuantumSafe)
	}
	return b.String()
}

// groupLabel is assetLabel without a library's version, so a package.json
// range and the lockfile's exact version are one library, as in the CBOM.
func groupLabel(f detect.Finding) string {
	if f.PURL == "" {
		return assetLabel(f)
	}
	g := f
	if i := strings.LastIndex(g.PURL, "@"); i > 0 {
		g.PURL = g.PURL[:i]
	}
	return assetLabel(g)
}

// loc renders a finding's location as "path:line", or "path" for binary
// files.
func loc(f detect.Finding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return f.File
}
