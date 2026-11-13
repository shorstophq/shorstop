package deps

import (
	"testing"

	"github.com/shorstophq/shorstop/internal/detect/detecttest"
)

// FuzzDetect: manifests and lockfiles (JSON, YAML, TOML, XML, line formats)
// come from untrusted repositories. The first argument picks the file name,
// which decides the parser.
func FuzzDetect(f *testing.F) {
	names := []string{
		"go.mod", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
		"pyproject.toml", "Pipfile.lock", "pom.xml", "build.gradle.kts", "composer.json", "composer.lock",
		"Cargo.toml", "Cargo.lock", "Gemfile.lock", "packages.config", "App.csproj", "requirements.txt",
	}
	seeds := map[string]int{}
	dir := "testdata/fixtures/deps/"
	for file, name := range map[string]string{
		"golang/go.mod": "go.mod", "npm/package.json": "package.json", "npm/package-lock.json": "package-lock.json",
		"npm/yarn.lock": "yarn.lock", "npm/pnpm-lock.yaml": "pnpm-lock.yaml", "pypi/poetry.lock": "poetry.lock",
		"pypi/pyproject.toml": "pyproject.toml", "pypi/Pipfile.lock": "Pipfile.lock", "maven/pom.xml": "pom.xml",
		"maven/build.gradle.kts": "build.gradle.kts", "composer/composer.json": "composer.json",
		"composer/composer.lock": "composer.lock", "cargo/Cargo.toml": "Cargo.toml", "cargo/Cargo.lock": "Cargo.lock",
		"gem/Gemfile.lock": "Gemfile.lock", "nuget/packages.config": "packages.config", "nuget/App.csproj": "App.csproj",
		"pypi/requirements.txt": "requirements.txt", "pypi/requirements/base.txt": "requirements.txt",
	} {
		for i, n := range names {
			if n == name {
				seeds[dir+file] = i
			}
		}
	}
	detecttest.Seed(f, names, seeds)
	d := builtin(f)
	f.Fuzz(func(t *testing.T, name uint8, content []byte) {
		detecttest.Check(t, d, detecttest.File(names[int(name)%len(names)], content))
	})
}
