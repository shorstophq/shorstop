package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/shorstop/shorstop/internal/classify"
	"github.com/shorstop/shorstop/internal/detect"
)

// TableOptions control the terminal report.
type TableOptions struct {
	// Color adds ANSI colours. The CLI turns it on only for a terminal,
	// and never when NO_COLOR is set.
	Color bool
	// MaxLocations is how many places to list per asset before
	// "... and N more"; 0 means 5. The CBOM and SARIF list them all.
	MaxLocations int
	IncludeInfo  bool
}

// ANSI escape sequences.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

var severityColor = map[classify.Severity]string{
	classify.Critical: ansiBold + ansiRed,
	classify.High:     ansiRed,
	classify.Medium:   ansiYellow,
	classify.Low:      ansiCyan,
	classify.Info:     ansiGreen,
}

// WriteTable writes the findings grouped by severity, then by asset:
//
//	CRITICAL · 3
//	  MD5 · BROKEN · 2 places
//	    MD5 has practical collision attacks: ...
//	    → Use SHA-256 or stronger (SHA-384, SHA-3).
//	      app/hash.py:2       py-hashlib-md5
//	      lib/legacy.go:7     go-md5-import
//
// It doesn't write the summary line; the caller adds it, with the scan
// statistics it alone has.
func WriteTable(w io.Writer, fs []detect.Finding, opts TableOptions) error {
	limit := opts.MaxLocations
	if limit <= 0 {
		limit = 5
	}
	paint := func(code, s string) string {
		if !opts.Color {
			return s
		}
		return code + s + ansiReset
	}

	groups := groupFindings(fs, opts.IncludeInfo)
	var b strings.Builder
	for _, sev := range severities {
		n := 0
		for _, g := range groups {
			if g.r.Severity == sev {
				n += len(g.items)
			}
		}
		if n == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s\n", paint(severityColor[sev], fmt.Sprintf("%s · %d", strings.ToUpper(string(sev)), n)))
		for _, g := range groups {
			if g.r.Severity != sev {
				continue
			}
			places := "1 place"
			if len(g.items) != 1 {
				places = fmt.Sprintf("%d places", len(g.items))
			}
			fmt.Fprintf(&b, "  %s · %s · %s\n", paint(ansiBold, clean(g.label)), g.r.Status, places)
			fmt.Fprintf(&b, "    %s\n", g.r.Reason)
			if g.r.Recommendation != "" {
				fmt.Fprintf(&b, "    %s %s\n", paint(ansiGreen, "→"), g.r.Recommendation)
			}
			tw := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)
			for i, it := range g.items {
				if i == limit {
					break
				}
				fmt.Fprintf(tw, "      %s\t%s\n", clean(loc(it.f)), it.f.RuleID)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if more := len(g.items) - limit; more > 0 {
				fmt.Fprintf(&b, "      %s\n", paint(ansiDim, fmt.Sprintf("… and %d more (all are in --format json or sarif)", more)))
			}
		}
		b.WriteByte('\n')
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// clean replaces control characters, so a file named with escape
// sequences can't rewrite the user's terminal.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}
