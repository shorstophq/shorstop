// Package baseline lets a team adopt ShorStop without fixing everything
// first: findings recorded in a previous scan's output are set aside, and
// only new ones are reported and can fail the build.
//
// A baseline is a previous `--format sarif` or `--format json` (CBOM)
// output. Findings are matched by fingerprint (report.Fingerprint), which
// leaves out the line number, so moving code doesn't make old findings new.
package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/report"
)

// Baseline counts the findings of a previous scan by fingerprint.
type Baseline struct {
	counts map[string]int
	size   int
}

// Len is how many findings the baseline holds.
func (b *Baseline) Len() int { return b.size }

// Load reads a baseline from a SARIF log or a CycloneDX CBOM written by
// ShorStop. The format is detected from the content.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	return b, nil
}

// Parse reads a baseline from SARIF or CBOM bytes.
func Parse(data []byte) (*Baseline, error) {
	// "version" is a string in SARIF ("2.1.0") and a number in CycloneDX
	// (the BOM's own version), so it is read raw.
	var probe struct {
		BOMFormat string          `json:"bomFormat"`
		Version   json.RawMessage `json:"version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	b := &Baseline{counts: make(map[string]int)}
	add := func(fp string) {
		if fp != "" {
			b.counts[fp]++
			b.size++
		}
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		var bom struct {
			Components []struct {
				Evidence *struct {
					Occurrences []struct {
						BOMRef string `json:"bom-ref"`
					} `json:"occurrences"`
				} `json:"evidence"`
			} `json:"components"`
		}
		if err := json.Unmarshal(data, &bom); err != nil {
			return nil, err
		}
		for _, c := range bom.Components {
			if c.Evidence == nil {
				continue
			}
			for _, o := range c.Evidence.Occurrences {
				// "shorstop:fp:<fingerprint>#<n>"
				if fp, ok := strings.CutPrefix(o.BOMRef, "shorstop:fp:"); ok {
					fp, _, _ = strings.Cut(fp, "#")
					add(fp)
				}
			}
		}
	case string(probe.Version) == `"2.1.0"`:
		var log struct {
			Runs []struct {
				Results []struct {
					PartialFingerprints map[string]string `json:"partialFingerprints"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(data, &log); err != nil {
			return nil, err
		}
		for _, r := range log.Runs {
			for _, res := range r.Results {
				add(res.PartialFingerprints[report.FingerprintKey])
			}
		}
	default:
		return nil, errors.New("neither a CycloneDX CBOM nor a SARIF 2.1.0 log")
	}
	return b, nil
}

// Split separates findings into those not in the baseline (new) and those
// that are (known). Each baseline entry is used once, so if the baseline
// had one MD5 import in a file and the scan finds two identical ones, one
// is new. The order of fs is kept in both results.
func (b *Baseline) Split(fs []detect.Finding) (fresh, known []detect.Finding) {
	left := make(map[string]int, len(b.counts))
	for fp, n := range b.counts {
		left[fp] = n
	}
	for _, f := range fs {
		fp := report.Fingerprint(f)
		if left[fp] > 0 {
			left[fp]--
			known = append(known, f)
		} else {
			fresh = append(fresh, f)
		}
	}
	return fresh, known
}
