package report

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/shorstop/shorstop/internal/classify"
	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/rules"
)

// Catalog describes rule IDs, for formats that list the rules they report.
type Catalog map[string]string

// NewCatalog collects the descriptions of a rule pack's rules and of the
// built-in rules of detectors that have no rule pack (cert, config).
func NewCatalog(pack *rules.Pack, builtins ...map[string]string) Catalog {
	c := make(Catalog)
	if pack != nil {
		for _, r := range pack.Rules {
			c[r.ID] = r.Description
		}
	}
	for _, b := range builtins {
		for id, d := range b {
			c[id] = d
		}
	}
	return c
}

// SARIFOptions are the parts of a SARIF log that don't come from findings.
type SARIFOptions struct {
	ToolVersion string
	Catalog     Catalog
	// IncludeInfo also reports findings that need no action (acceptable and
	// quantum-safe). Off by default: SARIF results become code-scanning
	// alerts, and an alert for AES-256 is noise. The CBOM lists everything.
	IncludeInfo bool
}

const (
	informationURI = "https://github.com/shorstop/shorstop"
	FingerprintKey = "shorstop/v1" // partialFingerprints key; baselines read it
)

// SARIF types: the subset of SARIF 2.1.0 ShorStop writes.
type (
	sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version,omitempty"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	sarifRule struct {
		ID                   string         `json:"id"`
		ShortDescription     sarifText      `json:"shortDescription"`
		Help                 sarifHelp      `json:"help"`
		DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
		Properties           sarifRuleProps `json:"properties"`
	}
	sarifText struct {
		Text string `json:"text"`
	}
	sarifHelp struct {
		Text     string `json:"text"`
		Markdown string `json:"markdown"`
	}
	sarifConfig struct {
		Level string `json:"level"`
	}
	sarifRuleProps struct {
		Tags []string `json:"tags"`
		// GitHub code scanning reads this (0.1-10) to show
		// Critical/High/Medium/Low for security alerts.
		SecuritySeverity string `json:"security-severity"`
	}
	sarifResult struct {
		RuleID              string            `json:"ruleId"`
		RuleIndex           int               `json:"ruleIndex"`
		Level               string            `json:"level"`
		Message             sarifText         `json:"message"`
		Locations           []sarifLocation   `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Properties          sarifResultProps  `json:"properties"`
	}
	sarifLocation struct {
		PhysicalLocation sarifPhysical `json:"physicalLocation"`
	}
	sarifPhysical struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
		Region           *sarifRegion  `json:"region,omitempty"`
	}
	sarifArtifact struct {
		URI       string `json:"uri"`
		URIBaseID string `json:"uriBaseId"`
	}
	sarifRegion struct {
		StartLine int        `json:"startLine"`
		Snippet   *sarifText `json:"snippet,omitempty"`
	}
	sarifResultProps struct {
		Status     string `json:"shorstop:status"`
		Severity   string `json:"shorstop:severity"`
		Confidence string `json:"shorstop:confidence,omitempty"`
		Asset      string `json:"shorstop:asset,omitempty"`
		PURL       string `json:"shorstop:purl,omitempty"`
	}
)

// securityScore is GitHub's security-severity for each of our severities:
// GitHub shows >= 9.0 as Critical, 7.0-8.9 High, 4.0-6.9 Medium, 0.1-3.9 Low.
var securityScore = map[classify.Severity]string{
	classify.Critical: "9.5",
	classify.High:     "8.0",
	classify.Medium:   "5.5",
	classify.Low:      "3.0",
	classify.Info:     "0.1",
}

// sarifLevel maps severity to SARIF's result level.
func sarifLevel(s classify.Severity) string {
	switch s {
	case classify.Critical, classify.High:
		return "error"
	case classify.Medium:
		return "warning"
	}
	return "note"
}

// WriteSARIF writes findings as a SARIF 2.1.0 log with one run.
//
// Rules: only those with results are listed. SARIF and GitHub take a rule's
// security-severity from the rule, not the result, but one rule can find
// both RSA-1024 (critical) and RSA-4096 (high); the rule carries the worst
// severity among its results, and each result's level and
// shorstop:severity property carry its own.
//
// Fingerprints don't use the line number, so a finding keeps its identity
// (and its dismissed/open state in GitHub) when code above it moves.
func WriteSARIF(w io.Writer, fs []detect.Finding, opts SARIFOptions) error {
	type ruleAcc struct {
		worst classify.Result
		index int
	}
	acc := map[string]*ruleAcc{}
	var ruleIDs []string
	var results []sarifResult
	for _, f := range fs {
		r := classify.Classify(f)
		if r.Severity == classify.Info && !opts.IncludeInfo {
			continue
		}
		a, ok := acc[f.RuleID]
		if !ok {
			a = &ruleAcc{worst: r}
			acc[f.RuleID] = a
			ruleIDs = append(ruleIDs, f.RuleID)
		} else if r.Severity.Rank() > a.worst.Severity.Rank() {
			a.worst = r
		}
		results = append(results, sarifResult{
			RuleID:              f.RuleID,
			Level:               sarifLevel(r.Severity),
			Message:             sarifText{Text: message(f, r)},
			Locations:           []sarifLocation{location(f)},
			PartialFingerprints: map[string]string{FingerprintKey: Fingerprint(f)},
			Properties: sarifResultProps{
				Status: string(r.Status), Severity: string(r.Severity), Confidence: f.Confidence,
				Asset: assetLabel(f), PURL: f.PURL,
			},
		})
	}

	slices.Sort(ruleIDs)
	rulesOut := make([]sarifRule, len(ruleIDs))
	for i, id := range ruleIDs {
		a := acc[id]
		a.index = i
		desc := cmp.Or(opts.Catalog[id], "ShorStop rule "+id+".")
		help := desc
		if a.worst.Recommendation != "" {
			help += "\n\nRecommendation: " + a.worst.Recommendation
		}
		rulesOut[i] = sarifRule{
			ID:                   id,
			ShortDescription:     sarifText{Text: desc},
			Help:                 sarifHelp{Text: help, Markdown: strings.ReplaceAll(help, "Recommendation:", "**Recommendation:**")},
			DefaultConfiguration: sarifConfig{Level: sarifLevel(a.worst.Severity)},
			Properties: sarifRuleProps{
				Tags:             []string{"security", "cryptography", "post-quantum"},
				SecuritySeverity: securityScore[a.worst.Severity],
			},
		}
	}
	for i := range results {
		results[i].RuleIndex = acc[results[i].RuleID].index
	}
	// Results in file, line, rule order (the crawler's order) for stable output.
	slices.SortStableFunc(results, func(a, b sarifResult) int {
		la, lb := a.Locations[0].PhysicalLocation, b.Locations[0].PhysicalLocation
		return cmp.Or(cmp.Compare(la.ArtifactLocation.URI, lb.ArtifactLocation.URI), cmp.Compare(line(la), line(lb)), cmp.Compare(a.RuleID, b.RuleID))
	})
	if results == nil {
		results = []sarifResult{}
	}

	log := sarifLog{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "shorstop", Version: opts.ToolVersion, InformationURI: informationURI, Rules: rulesOut}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func line(p sarifPhysical) int {
	if p.Region == nil {
		return 0
	}
	return p.Region.StartLine
}

// message is the alert text: what was found, how it is rated, why, and
// what to do.
func message(f detect.Finding, r classify.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s, %s). %s", assetLabel(f), r.Status, r.Severity, r.Reason)
	if r.Recommendation != "" {
		b.WriteString(" " + r.Recommendation)
	}
	return b.String()
}

// assetLabel names what a finding is about: "RSA-2048", "TLSv1.0",
// "RSA-2048 private key", "pkg:npm/node-forge".
func assetLabel(f detect.Finding) string {
	switch {
	case f.AssetType == detect.AssetProtocol:
		return f.Protocol
	case f.PURL != "":
		if f.Algorithm != "" {
			return f.PURL + " (" + algName(f) + ")"
		}
		return f.PURL
	case f.AssetType == detect.AssetMaterial:
		return strings.TrimSpace(cmp.Or(algName(f), "unknown-algorithm") + " " + strings.ReplaceAll(f.MaterialType, "-", " "))
	case f.AssetType == detect.AssetCertificate:
		return "certificate with " + cmp.Or(algName(f), "unknown") + " key"
	}
	return cmp.Or(algName(f), "unknown algorithm")
}

// location is a finding's place, relative to the scanned root
// (%SRCROOT%), which code scanning resolves against the repository. Binary
// files have no line, so no region.
func location(f detect.Finding) sarifLocation {
	segs := strings.Split(f.File, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	p := sarifPhysical{ArtifactLocation: sarifArtifact{URI: strings.Join(segs, "/"), URIBaseID: "%SRCROOT%"}}
	if f.Line > 0 {
		p.Region = &sarifRegion{StartLine: f.Line}
		if f.Snippet != "" {
			p.Region.Snippet = &sarifText{Text: f.Snippet}
		}
	}
	return sarifLocation{PhysicalLocation: p}
}

// Fingerprint identifies a finding across scans without its line number:
// rule, file, what was found and the trimmed source line.
func Fingerprint(f detect.Finding) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		f.RuleID, f.File, f.Algorithm, strconv.Itoa(f.KeySize), f.Mode, f.ParameterSet,
		f.MaterialType, f.Protocol, f.PURL, f.Snippet,
	}, "\x00")))
	return hex.EncodeToString(h[:16])
}
