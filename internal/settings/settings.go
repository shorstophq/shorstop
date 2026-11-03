// Package settings reads .shorstop.yaml, a repository's ShorStop
// configuration:
//
//	version: 1
//	exclude: [third_party/, "*.min.js"]
//	fail-on: high
//	baseline: .shorstop/baseline.sarif
//	max-file-size: 4MB
//	rules: [.shorstop/rules.yaml]        # extra rule files
//	disable: [generic-rsa-bits]          # rule IDs to turn off
//
// Paths are relative to the file itself, so the config works whatever
// directory ShorStop is run from.
package settings

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// FileName is the config file looked for at the root of a scan.
const FileName = ".shorstop.yaml"

// FormatVersion is the only config format version this build understands.
const FormatVersion = 1

// Settings is a parsed .shorstop.yaml. Empty fields mean "not set": the
// command-line default applies.
type Settings struct {
	Version     int      `yaml:"version"`
	Exclude     []string `yaml:"exclude"`
	FailOn      string   `yaml:"fail-on"`
	Baseline    string   `yaml:"baseline"` // resolved to a path usable from the working directory
	MaxFileSize string   `yaml:"max-file-size"`
	Rules       []string `yaml:"rules"` // resolved like Baseline
	Disable     []string `yaml:"disable"`

	// Path is the file the settings came from, or "" when none was found.
	Path string `yaml:"-"`
}

// Find returns the config file at the root of dir, or "" if there is none.
func Find(dir string) (string, error) {
	p := filepath.Join(dir, FileName)
	info, err := os.Stat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", nil
	case err != nil:
		return "", err
	case info.IsDir():
		return "", fmt.Errorf("%s is a directory", p)
	}
	return p, nil
}

// Load reads and checks a config file. Unknown keys are errors, so a
// misspelt "fail_on" can't be silently ignored.
func Load(path string) (*Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.Path = path
	base := filepath.Dir(path)
	if s.Baseline != "" {
		s.Baseline = resolve(base, s.Baseline)
	}
	for i, r := range s.Rules {
		s.Rules[i] = resolve(base, r)
	}
	return s, nil
}

// Parse decodes config bytes. Paths are left as written.
func Parse(data []byte) (*Settings, error) {
	s := &Settings{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(s); err != nil {
		if errors.Is(err, io.EOF) {
			return &Settings{Version: FormatVersion}, nil // an empty file is a valid, empty config
		}
		return nil, err
	}
	switch s.Version {
	case 0:
		s.Version = FormatVersion // version may be left out
	case FormatVersion:
	default:
		return nil, fmt.Errorf("unsupported config version %d (this build supports %d)", s.Version, FormatVersion)
	}
	return s, nil
}

// resolve makes a path from the config file relative to the config's
// directory, unless it is absolute.
func resolve(base, p string) string {
	p = filepath.FromSlash(p)
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}
