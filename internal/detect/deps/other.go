package deps

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
)

// goMod reads the require directives of a go.mod, single-line and block
// form. replace and exclude are not dependencies of their own.
func goMod(content []byte) ([]dep, error) {
	var out []dep
	inRequire := false
	for i, raw := range splitLines(content) {
		line := string(raw)
		if j := strings.Index(line, "//"); j >= 0 {
			line = line[:j]
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case inRequire && f[0] == ")":
			inRequire = false
		case inRequire && len(f) >= 2:
			out = append(out, dep{name: f[0], version: f[1], line: i + 1})
		case f[0] == "require" && len(f) >= 2 && f[1] == "(":
			inRequire = true
		case f[0] == "require" && len(f) >= 3:
			out = append(out, dep{name: f[1], version: f[2], line: i + 1})
		}
	}
	return out, nil
}

// composerJSON reads require and require-dev, skipping the PHP version and
// extension requirements ("php", "ext-openssl").
func composerJSON(content []byte) ([]dep, error) {
	var cj struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(content, &cj); err != nil {
		return nil, err
	}
	var out []dep
	for _, m := range []map[string]string{cj.Require, cj.RequireDev} {
		for name, v := range m {
			if !strings.Contains(name, "/") {
				continue // php, ext-*, lib-*: platform requirements
			}
			out = append(out, dep{name: name, version: exact(v), line: jsonKeyLine(content, name)})
		}
	}
	return sortDeps(out), nil
}

// composerLock reads the packages and packages-dev arrays of composer.lock.
func composerLock(content []byte) ([]dep, error) {
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var cl struct {
		Packages    []pkg `json:"packages"`
		PackagesDev []pkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(content, &cl); err != nil {
		return nil, err
	}
	var out []dep
	for _, p := range append(cl.Packages, cl.PackagesDev...) {
		out = append(out, dep{name: p.Name, version: strings.TrimPrefix(p.Version, "v"), line: jsonValueLine(content, "name", p.Name)})
	}
	return sortDeps(out), nil
}

// cargoToml reads the dependency tables of a Cargo.toml: [dependencies],
// [dev-dependencies], [build-dependencies], their [target.*.] forms and
// [workspace.dependencies]; and [dependencies.<name>] headers. A renamed
// dependency (`alias = { package = "real" }`) is reported by its real name.
func cargoToml(content []byte) ([]dep, error) {
	var out []dep
	section := ""
	for i, raw := range splitLines(content) {
		line := strings.TrimSpace(string(raw))
		if line == "" || line[0] == '#' {
			continue
		}
		if name, ok := tomlHeader(line); ok {
			section = name
			// [dependencies.rsa] and [target.'cfg(unix)'.dependencies.rsa]
			for _, kind := range []string{"dependencies.", "dev-dependencies.", "build-dependencies."} {
				if j := strings.LastIndex(name, kind); j >= 0 && (j == 0 || name[j-1] == '.') {
					out = append(out, dep{name: name[j+len(kind):], line: i + 1})
					section = "" // its keys (version = ...) are not dependencies
				}
			}
			continue
		}
		if !isCargoDepSection(section) {
			continue
		}
		k, _, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		name := strings.Trim(strings.TrimSpace(k), `"'`)
		if m := cargoPackage.FindStringSubmatch(line); m != nil {
			name = m[1]
		}
		// A bare Cargo version ("0.9") is a caret range; only "=0.9.6" is exact.
		v := ""
		if _, s, ok := tomlKeyString(line); ok {
			v = s
		} else if m := cargoVersion.FindStringSubmatch(line); m != nil {
			v = m[1] // inline table: { version = "=0.10.6", ... }
		}
		version := ""
		if exactReq, ok := strings.CutPrefix(v, "="); ok {
			version = exact(exactReq)
		}
		out = append(out, dep{name: name, version: version, line: i + 1})
	}
	return out, nil
}

var (
	cargoPackage = regexp.MustCompile(`\bpackage\s*=\s*["']([^"']+)["']`)
	cargoVersion = regexp.MustCompile(`\bversion\s*=\s*["']([^"']+)["']`)
)

func isCargoDepSection(s string) bool {
	for _, kind := range []string{"dependencies", "dev-dependencies", "build-dependencies"} {
		if s == kind || s == "workspace."+kind || (strings.HasPrefix(s, "target.") && strings.HasSuffix(s, "."+kind)) {
			return true
		}
	}
	return false
}

// gemSpec is a gem line under GEM/specs in Gemfile.lock. Gems are indented
// four spaces; their own dependencies, six.
var gemSpec = regexp.MustCompile(`^    ([A-Za-z0-9_.-]+) \(([^)]+)\)$`)

// gemLock reads the resolved gems of a Gemfile.lock.
func gemLock(content []byte) ([]dep, error) {
	var out []dep
	inSpecs := false
	for i, raw := range splitLines(content) {
		line := string(raw)
		switch {
		case line == "  specs:":
			inSpecs = true
		case line != "" && line[0] != ' ':
			inSpecs = false // the next section (PLATFORMS, DEPENDENCIES ...)
		case inSpecs:
			if m := gemSpec.FindStringSubmatch(line); m != nil {
				out = append(out, dep{name: m[1], version: m[2], line: i + 1})
			}
		}
	}
	return out, nil
}

// nugetXML reads NuGet references from project files (<PackageReference>),
// central package management (<PackageVersion> in Directory.Packages.props)
// and the older packages.config (<package id="" version="">).
func nugetXML(content []byte) ([]dep, error) {
	dec := xml.NewDecoder(bytes.NewReader(content))
	dec.Strict = false
	var out []dep
	var cur *dep // an element whose version may come in a child <Version>
	inVersion := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "PackageReference", "PackageVersion", "package":
				line, _ := dec.InputPos()
				d := dep{line: line}
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "Include", "Update", "id":
						if d.name == "" {
							d.name = a.Value
						}
					case "Version", "version":
						d.version = exact(a.Value)
					}
				}
				if d.name != "" {
					out = append(out, d)
					cur = &out[len(out)-1]
				}
			case "Version":
				inVersion = cur != nil
			}
		case xml.CharData:
			if inVersion && cur.version == "" {
				cur.version = exact(string(t))
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "Version":
				inVersion = false
			case "PackageReference", "PackageVersion", "package":
				cur = nil
			}
		}
	}
	return out, nil
}
