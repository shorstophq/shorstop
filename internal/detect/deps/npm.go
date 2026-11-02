package deps

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// packageJSON reads the four dependency maps of a package.json. Versions
// there are ranges, so only exact pins are kept.
func packageJSON(content []byte) ([]dep, error) {
	var pj struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(content, &pj); err != nil {
		return nil, err
	}
	var out []dep
	for _, m := range []map[string]string{pj.Dependencies, pj.DevDependencies, pj.OptionalDependencies, pj.PeerDependencies} {
		for name, v := range m {
			out = append(out, dep{name: name, version: exact(v), line: jsonKeyLine(content, name)})
		}
	}
	return sortDeps(out), nil
}

// npmLock reads package-lock.json / npm-shrinkwrap.json. Lockfile v2 and
// v3 list every installed package under "packages", keyed by its path
// ("node_modules/a/node_modules/b"); v1 nests "dependencies" instead.
func npmLock(content []byte) ([]dep, error) {
	type v1dep struct {
		Version      string                     `json:"version"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, err
	}
	var out []dep
	if len(lock.Packages) > 0 {
		for key, p := range lock.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 {
				continue // "" is the project itself; workspace paths aren't dependencies
			}
			out = append(out, dep{name: key[i+len("node_modules/"):], version: p.Version, line: jsonKeyLine(content, key)})
		}
		return sortDeps(out), nil
	}
	// v1: walk the nested tree.
	var walk func(map[string]json.RawMessage) error
	walk = func(m map[string]json.RawMessage) error {
		for name, raw := range m {
			var d v1dep
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			out = append(out, dep{name: name, version: d.Version, line: jsonKeyLine(content, name)})
			if err := walk(d.Dependencies); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(lock.Dependencies); err != nil {
		return nil, err
	}
	return sortDeps(out), nil
}

// yarnLock reads yarn.lock, classic (v1) and Berry. Each entry starts at
// column 0 with one or more comma-separated specs ending in ":", and has an
// indented version line:
//
//	"node-forge@^1.2.0", node-forge@^1.3.0:      (classic)
//	  version "1.3.1"
//	"node-forge@npm:^1.3.0":                      (Berry)
//	  version: 1.3.1
func yarnLock(content []byte) ([]dep, error) {
	var out []dep
	var cur *dep
	for i, raw := range splitLines(content) {
		line := string(raw)
		switch {
		case line == "" || line[0] == '#':
			continue
		case line[0] != ' ':
			cur = nil
			if !strings.HasSuffix(line, ":") {
				continue
			}
			spec := strings.Trim(strings.TrimSpace(strings.SplitN(strings.TrimSuffix(line, ":"), ",", 2)[0]), `"`)
			name := yarnSpecName(spec)
			if name == "" {
				continue // __metadata and other non-package keys
			}
			out = append(out, dep{name: name, line: i + 1})
			cur = &out[len(out)-1]
		case cur != nil && cur.version == "":
			t := strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(t, "version "); ok {
				cur.version = strings.Trim(v, `"`)
			} else if v, ok := strings.CutPrefix(t, "version: "); ok {
				cur.version = strings.Trim(v, `"`)
			}
		}
	}
	return out, nil
}

// yarnSpecName returns the package name of a yarn spec: "node-forge@^1",
// "@noble/curves@~1.4", "node-forge@npm:^1.3.0".
func yarnSpecName(spec string) string {
	if i := strings.Index(spec, "@npm:"); i > 0 {
		return spec[:i]
	}
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return spec[:i]
	}
	return ""
}

// pnpmLock reads pnpm-lock.yaml. Package keys under "packages" are
// "/name@1.2.3" (v6), "name@1.2.3" (v9) or "/name/1.2.3" (v5), possibly with
// a peer-dependency suffix: "(react@18.2.0)" or "_react@18.2.0".
func pnpmLock(content []byte) ([]dep, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("not a pnpm lockfile")
	}
	root := doc.Content[0]
	var pkgs *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "packages" {
			pkgs = root.Content[i+1]
		}
	}
	if pkgs == nil || pkgs.Kind != yaml.MappingNode {
		return nil, nil
	}
	var out []dep
	for i := 0; i+1 < len(pkgs.Content); i += 2 {
		k := pkgs.Content[i]
		key := strings.TrimPrefix(k.Value, "/")
		if j := strings.IndexByte(key, '('); j >= 0 {
			key = key[:j]
		}
		var name, version string
		if j := strings.LastIndex(key, "/"); j > 0 && j+1 < len(key) && key[j+1] >= '0' && key[j+1] <= '9' {
			// v5: "name/1.2.3" or "@scope/name/1.2.3", maybe "_peer@ver" after.
			// Checked first: the peer suffix contains an "@" of its own.
			name, version = key[:j], key[j+1:]
			if k := strings.IndexByte(version, '_'); k >= 0 {
				version = version[:k]
			}
		} else if j := strings.LastIndex(key, "@"); j > 0 {
			name, version = key[:j], key[j+1:]
		} else {
			continue
		}
		out = append(out, dep{name: name, version: version, line: k.Line})
	}
	return out, nil
}

// sortDeps orders deps by line, then name, so map iteration order never
// shows in the output.
func sortDeps(ds []dep) []dep {
	slices.SortFunc(ds, func(a, b dep) int {
		if a.line != b.line {
			return a.line - b.line
		}
		return strings.Compare(a.name, b.name)
	})
	return slices.CompactFunc(ds, func(a, b dep) bool { return a == b })
}
