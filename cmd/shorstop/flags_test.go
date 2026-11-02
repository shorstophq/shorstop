package main

import "testing"

func TestByteSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"1", 1, false},
		{"512B", 512, false},
		{"2KB", 2 << 10, false},
		{"2kb", 2 << 10, false},
		{"2K", 2 << 10, false},
		{"2KiB", 2 << 10, false},
		{"2MB", 2 << 20, false},
		{"2 MB", 2 << 20, false},
		{"1GB", 1 << 30, false},
		{"0", 0, true},
		{"-1MB", 0, true},
		{"1.5MB", 0, true},
		{"MB", 0, true},
		{"2XB", 0, true},
		{"", 0, true},
		{"9999999999GB", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			var b byteSize
			err := b.Set(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Set(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && int64(b) != tt.want {
				t.Errorf("Set(%q) = %d, want %d", tt.in, b, tt.want)
			}
		})
	}
}

func TestByteSizeString(t *testing.T) {
	for in, want := range map[int64]string{
		2 << 20: "2MB", 1 << 30: "1GB", 1536: "1536B", 3 << 10: "3KB", 100: "100B",
	} {
		b := byteSize(in)
		if got := b.String(); got != want {
			t.Errorf("byteSize(%d).String() = %q, want %q", in, got, want)
		}
	}
}
