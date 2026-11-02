package detect

import (
	"slices"
	"testing"
)

func TestDedupe(t *testing.T) {
	aes := func(line, bits int, mode, conf, det string) Finding {
		return Finding{Line: line, Algorithm: "AES", Primitive: "block-cipher", KeySize: bits, Mode: mode, Confidence: conf, Detector: det}
	}
	tests := []struct {
		name string
		in   []Finding
		want []Finding
	}{
		{
			"same line, same details: keep the first, take the higher confidence",
			[]Finding{aes(3, 128, "CTR", "medium", "regex"), aes(3, 128, "CTR", "high", "config")},
			[]Finding{aes(3, 128, "CTR", "high", "regex")},
		},
		{
			"the more specific finding wins, wherever it is",
			[]Finding{aes(3, 0, "", "medium", "regex"), aes(3, 256, "GCM", "high", "config")},
			[]Finding{aes(3, 256, "GCM", "high", "config")},
		},
		{
			"conflicting details are both kept",
			[]Finding{aes(3, 256, "GCM", "high", "config"), aes(3, 128, "CTR", "high", "config")},
			[]Finding{aes(3, 256, "GCM", "high", "config"), aes(3, 128, "CTR", "high", "config")},
		},
		{
			"different lines are never merged, and order is kept",
			[]Finding{aes(9, 128, "CBC", "high", "x"), aes(2, 128, "CBC", "high", "x"), aes(9, 0, "", "low", "y")},
			[]Finding{aes(9, 128, "CBC", "high", "x"), aes(2, 128, "CBC", "high", "x")},
		},
		{
			"different subjects are kept",
			[]Finding{
				{Line: 1, Algorithm: "RSA", Primitive: "signature"},
				{Line: 1, Algorithm: "RSA", AssetType: AssetMaterial, MaterialType: MaterialPrivateKey},
				{Line: 1, AssetType: AssetProtocol, Protocol: TLSv10},
				{Line: 1, AssetType: AssetProtocol, Protocol: TLSv11},
			},
			[]Finding{
				{Line: 1, Algorithm: "RSA", Primitive: "signature"},
				{Line: 1, Algorithm: "RSA", AssetType: AssetMaterial, MaterialType: MaterialPrivateKey},
				{Line: 1, AssetType: AssetProtocol, Protocol: TLSv10},
				{Line: 1, AssetType: AssetProtocol, Protocol: TLSv11},
			},
		},
		{
			"certificates are never merged",
			[]Finding{{Line: 0, Algorithm: "RSA", Cert: &Certificate{}}, {Line: 0, Algorithm: "RSA", Cert: &Certificate{}}},
			[]Finding{{Line: 0, Algorithm: "RSA", Cert: &Certificate{}}, {Line: 0, Algorithm: "RSA", Cert: &Certificate{}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Dedupe(slices.Clone(tt.in))
			if len(got) != len(tt.want) {
				t.Fatalf("got %d findings, want %d:\n%+v", len(got), len(tt.want), got)
			}
			for i := range got {
				g, w := got[i], tt.want[i]
				g.Cert, w.Cert = nil, nil
				if g != w {
					t.Errorf("finding %d = %+v, want %+v", i, g, w)
				}
			}
		})
	}
}
