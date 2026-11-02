package deps

import (
	"encoding/json"
	"regexp"
	"strings"
)

// pep508Name reads the distribution name at the start of a PEP 508
// requirement ("pycryptodome[extra]==3.20; python_version<'4'").
var pep508Name = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)

// pep508Exact reads an exact "==" pin (not "===", not a "==3.*" wildcard).
var pep508Exact = regexp.MustCompile(`==\s*([0-9][0-9A-Za-z.+!-]*)\s*(?:[;,]|$)`)

// requirement parses one PEP 508 requirement string.
func requirement(s string) (name, version string, ok bool) {
	m := pep508Name.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	if v := pep508Exact.FindStringSubmatch(s[len(m[0]):]); v != nil {
		version = v[1]
	}
	return m[1], version, true
}

// requirementsTxt reads a pip requirements file. Options (-r, -e, -c,
// --hash ...) and plain URLs are skipped; "name @ url" direct references
// keep their name.
func requirementsTxt(content []byte) ([]dep, error) {
	var out []dep
	for i, raw := range splitLines(content) {
		line := string(raw)
		if j := strings.Index(line, " #"); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSuffix(strings.TrimSpace(line), `\`)
		if line == "" || line[0] == '#' || line[0] == '-' {
			continue
		}
		if strings.Contains(line, "://") && !strings.Contains(line, " @ ") {
			continue
		}
		if name, version, ok := requirement(line); ok {
			out = append(out, dep{name: name, version: version, line: i + 1})
		}
	}
	return out, nil
}

// tomlPackages reads the [[package]] tables of poetry.lock and Cargo.lock:
//
//	[[package]]
//	name = "pycryptodome"
//	version = "3.20.0"
//
// It is a line reader, not a TOML parser: lockfiles are machine-written in
// exactly this shape, and a parser would be a dependency for two keys.
func tomlPackages(content []byte) ([]dep, error) {
	var out []dep
	var cur *dep
	for i, raw := range splitLines(content) {
		line := strings.TrimSpace(string(raw))
		if strings.HasPrefix(line, "[") {
			cur = nil
			if line == "[[package]]" {
				out = append(out, dep{})
				cur = &out[len(out)-1]
			}
			continue
		}
		if cur == nil {
			continue
		}
		key, val, ok := tomlKeyString(line)
		switch {
		case !ok:
		case key == "name" && cur.name == "":
			cur.name, cur.line = val, i+1
		case key == "version" && cur.version == "":
			cur.version = val
		}
	}
	// Drop tables that had no name.
	kept := out[:0]
	for _, d := range out {
		if d.name != "" {
			kept = append(kept, d)
		}
	}
	return kept, nil
}

// tomlKeyString reads `key = "value"` (or 'value'). ok is false for any
// other shape.
func tomlKeyString(line string) (key, val string, ok bool) {
	k, v, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}
	v = strings.TrimSpace(v)
	if len(v) < 2 || (v[0] != '"' && v[0] != '\'') {
		return "", "", false
	}
	end := strings.IndexByte(v[1:], v[0])
	if end < 0 {
		return "", "", false
	}
	return strings.Trim(strings.TrimSpace(k), `"'`), v[1 : 1+end], true
}

// tomlHeader returns the name of a "[section]" or "[[array]]" header line.
func tomlHeader(line string) (string, bool) {
	if !strings.HasPrefix(line, "[") {
		return "", false
	}
	name := strings.Trim(line, "[] \t")
	if j := strings.IndexByte(name, '#'); j >= 0 { // trailing comment after "]"
		name = strings.TrimRight(strings.Trim(name[:j], "[] \t"), "]")
	}
	return name, true
}

var tomlQuoted = regexp.MustCompile(`"([^"]*)"|'([^']*)'`)

// pyproject reads the dependencies of a pyproject.toml:
//   - PEP 621: [project] dependencies = [...], [project.optional-dependencies]
//     and PEP 735 [dependency-groups] arrays of requirement strings;
//   - Poetry: [tool.poetry.dependencies], [tool.poetry.dev-dependencies] and
//     [tool.poetry.group.<name>.dependencies] tables of `name = constraint`.
//
// Like tomlPackages it reads lines, which covers how these files are
// written in practice; an array closed on a later line is followed.
func pyproject(content []byte) ([]dep, error) {
	var out []dep
	section, inArray := "", false
	for i, raw := range splitLines(content) {
		line := strings.TrimSpace(string(raw))
		if line == "" || line[0] == '#' {
			continue
		}
		if name, ok := tomlHeader(line); ok && !inArray {
			section = name
			continue
		}
		arrays := section == "project.optional-dependencies" || section == "dependency-groups"
		poetry := strings.HasPrefix(section, "tool.poetry.") && strings.HasSuffix(section, "dependencies")
		if !inArray {
			k, v, found := strings.Cut(line, "=")
			if !found {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch {
			case (section == "project" && k == "dependencies") || (arrays && strings.HasPrefix(v, "[")):
				inArray = true
				line = v
			case poetry && k != "python":
				name := strings.Trim(k, `"'`)
				version := ""
				if _, s, ok := tomlKeyString(line); ok {
					version = exact(strings.TrimPrefix(s, "=="))
				}
				out = append(out, dep{name: name, version: version, line: i + 1})
				continue
			default:
				continue
			}
		}
		// Inside a requirement array: every quoted string is a requirement.
		code := line
		if j := strings.Index(code, "#"); j >= 0 && !strings.ContainsAny(code[:j], `"'`) {
			code = code[:j]
		}
		for _, m := range tomlQuoted.FindAllStringSubmatch(code, -1) {
			if name, version, ok := requirement(m[1] + m[2]); ok {
				out = append(out, dep{name: name, version: version, line: i + 1})
			}
		}
		if strings.Contains(tomlQuoted.ReplaceAllString(code, ""), "]") {
			inArray = false
		}
	}
	return out, nil
}

// pipfileLock reads Pipfile.lock: {"default": {name: {"version": "==1.2"}}, "develop": {...}}.
func pipfileLock(content []byte) ([]dep, error) {
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, err
	}
	var out []dep
	for _, section := range []string{"default", "develop"} {
		var pkgs map[string]struct {
			Version string `json:"version"`
		}
		if raw, ok := lock[section]; ok {
			if err := json.Unmarshal(raw, &pkgs); err != nil {
				return nil, err
			}
		}
		for name, p := range pkgs {
			out = append(out, dep{name: name, version: strings.TrimPrefix(p.Version, "=="), line: jsonKeyLine(content, name)})
		}
	}
	return sortDeps(out), nil
}
