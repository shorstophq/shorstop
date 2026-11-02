package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/shorstop/shorstop/internal/detect"
	"github.com/shorstop/shorstop/internal/detect/cert"
)

// k8sSecrets reports the certificates and keys inside Kubernetes Secret
// manifests. Secret `data` values are base64, so the cert detector, which
// reads the raw file, can't see them; this decodes each value and hands any
// PEM inside to cert.FindPEM. `stringData` values are plain text, which the
// cert detector already reads, so they are left to it.
//
// Findings are placed on the line of the data key, and their snippet names
// the key and the Secret, never the value.
func k8sSecrets(ctx context.Context, content []byte) ([]detect.Finding, error) {
	if !bytes.Contains(content, []byte("Secret")) || !bytes.Contains(content, []byte("kind")) {
		return nil, nil
	}
	// A Helm or other Go template is not YAML until it is rendered, and its
	// values are placeholders, so there is nothing to decode.
	if bytes.Contains(content, []byte("{{")) {
		return nil, nil
	}

	var out []detect.Finding
	var errs []error
	dec := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Decoding can't continue past a syntax error.
			errs = append(errs, fmt.Errorf("yaml: %w", err))
			break
		}
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		if v := mapValue(root, "kind"); v == nil || v.Value != "Secret" {
			continue
		}
		name := "?"
		if v := mapValue(mapValue(root, "metadata"), "name"); v != nil {
			name = v.Value
		}
		data := mapValue(root, "data")
		if data == nil || data.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(data.Content); i += 2 {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			k, v := data.Content[i], data.Content[i+1]
			// Base64 in YAML is often wrapped over several lines.
			raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v.Value), ""))
			if err != nil || !bytes.Contains(raw, []byte("-----BEGIN ")) {
				continue
			}
			found, err := cert.FindPEM(ctx, raw)
			if err != nil {
				errs = append(errs, fmt.Errorf("line %d: Secret %s, %s: %w", k.Line, name, k.Value, err))
			}
			for _, f := range found {
				f.Line = k.Line
				f.Snippet = detect.SnippetOf(fmt.Appendf(nil, "%s in Secret %s (base64): %s", k.Value, name, f.Snippet))
				out = append(out, f)
			}
		}
	}
	return out, errors.Join(errs...)
}

// mapValue returns the value node of key in a YAML mapping, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
