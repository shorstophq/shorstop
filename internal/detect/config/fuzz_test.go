package config

import (
	"testing"

	"github.com/shorstophq/shorstop/internal/detect/detecttest"
)

// FuzzDetect: server configs and Kubernetes Secrets come from untrusted
// repositories. The first argument picks the file name, which decides the
// dialect (OpenSSH, Kubernetes YAML, or the generic TLS directives).
func FuzzDetect(f *testing.F) {
	names := []string{"nginx.conf", "sshd_config", "k8s/secret.yaml", "haproxy.cfg", "sites-enabled/default", "openssl.cnf"}
	dir := "testdata/fixtures/config/"
	detecttest.Seed(f, names, map[string]int{
		dir + "nginx.conf": 0, dir + "apache-ssl.conf": 0, dir + "stunnel.conf": 0, dir + "postgresql.conf": 0,
		dir + "sshd_config": 1, dir + "sshd_config.d/legacy.conf": 1, dir + "k8s/tls-secret.yaml": 2,
		dir + "helm/templates/secret.yaml": 2, dir + "haproxy.cfg": 3, dir + "sites-enabled/example.com": 4,
		dir + "openssl.cnf": 5,
	})
	d := New()
	f.Fuzz(func(t *testing.T, name uint8, content []byte) {
		detecttest.Check(t, d, detecttest.File(names[int(name)%len(names)], content))
	})
}
