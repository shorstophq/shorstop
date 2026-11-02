package main

import (
	"fmt"
	"strconv"
	"strings"
)

// byteSize is a flag value such as "512KB" or "2MB". Units are binary
// multiples (1KB = 1024 bytes), matching how file sizes are usually shown.
type byteSize int64

var byteUnits = []struct {
	suffix string
	mult   int64
}{
	// Longest suffixes first, so "MB" is not read as "B".
	{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
	{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30},
	{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30},
	{"B", 1},
}

func (b *byteSize) Set(s string) error {
	num := strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range byteUnits {
		if strings.HasSuffix(num, u.suffix) {
			num, mult = strings.TrimSpace(strings.TrimSuffix(num, u.suffix)), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n < 1 {
		return fmt.Errorf("invalid size %q: want a positive whole number with an optional unit (B, KB, MB, GB)", s)
	}
	if n > (1<<63-1)/mult {
		return fmt.Errorf("invalid size %q: too large", s)
	}
	*b = byteSize(n * mult)
	return nil
}

func (b *byteSize) String() string {
	n := int64(*b)
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return strconv.FormatInt(n>>30, 10) + "GB"
	case n >= 1<<20 && n%(1<<20) == 0:
		return strconv.FormatInt(n>>20, 10) + "MB"
	case n >= 1<<10 && n%(1<<10) == 0:
		return strconv.FormatInt(n>>10, 10) + "KB"
	}
	return strconv.FormatInt(n, 10) + "B"
}

// stringList is a flag that can be repeated, e.g. --exclude a --exclude b.
type stringList []string

func (l *stringList) Set(s string) error {
	*l = append(*l, s)
	return nil
}

func (l *stringList) String() string { return strings.Join(*l, ",") }
