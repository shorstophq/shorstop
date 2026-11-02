package deps

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
)

// pom reads the <dependency> elements of a Maven pom.xml, wherever they
// are (dependencies, dependencyManagement, plugin dependencies). A version
// that is a property reference ("${bc.version}") is left unknown: resolving
// it needs the parent POM chain.
func pom(content []byte) ([]dep, error) {
	dec := xml.NewDecoder(bytes.NewReader(content))
	dec.Strict = false // real POMs carry odd entities and encodings
	var out []dep
	var cur *dep
	var group, artifact string
	var field *string
	sawProject := false
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
			case "project":
				sawProject = true
			case "dependency":
				line, _ := dec.InputPos()
				cur, group, artifact = &dep{line: line}, "", ""
			case "groupId":
				field = ptrIf(cur != nil, &group)
			case "artifactId":
				field = ptrIf(cur != nil, &artifact)
			case "version":
				if cur != nil {
					field = &cur.version
				}
			default:
				field = nil
			}
		case xml.CharData:
			if field != nil {
				*field += strings.TrimSpace(string(t))
			}
		case xml.EndElement:
			field = nil
			if t.Name.Local == "dependency" && cur != nil {
				if group != "" && artifact != "" {
					cur.name = group + ":" + artifact
					if strings.Contains(cur.version, "${") {
						cur.version = ""
					}
					out = append(out, *cur)
				}
				cur = nil
			}
		}
	}
	// Non-strict decoding accepts almost any text, so check it was a POM.
	if !sawProject {
		return nil, errors.New("no <project> element: not a Maven POM")
	}
	return out, nil
}

func ptrIf(ok bool, p *string) *string {
	if ok {
		return p
	}
	return nil
}

var (
	// "group:artifact:version" or "group:artifact" in quotes, as in
	// implementation("org.bouncycastle:bcprov-jdk18on:1.78").
	gradleCoord = regexp.MustCompile(`["']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)(?::([A-Za-z0-9_.+-]+))?(?:@[a-z]+)?["']`)
	// group: 'org.bouncycastle', name: 'bcprov-jdk18on', version: '1.78'
	gradleMap = regexp.MustCompile(`group\s*[:=]\s*["']([A-Za-z0-9_.-]+)["']\s*,\s*name\s*[:=]\s*["']([A-Za-z0-9_.-]+)["'](?:\s*,\s*version\s*[:=]\s*["']([A-Za-z0-9_.+-]+)["'])?`)
)

// gradle reads dependency coordinates from build.gradle (Groovy) and
// build.gradle.kts (Kotlin). Gradle files are programs, so this reads the
// two literal notations people write; versions from variables or catalogs
// ("libs.bouncycastle") are not resolved.
func gradle(content []byte) ([]dep, error) {
	var out []dep
	for i, raw := range splitLines(content) {
		line := string(raw)
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") {
			continue
		}
		for _, re := range []*regexp.Regexp{gradleCoord, gradleMap} {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				out = append(out, dep{name: m[1] + ":" + m[2], version: exact(m[3]), line: i + 1})
			}
		}
	}
	return out, nil
}
