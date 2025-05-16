package main

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	var cases = []struct {
		s string
		d time.Duration
		e bool
	}{
		{"0s", 0, false},
		{"1s", time.Second, false},
		{"1m", time.Minute, false},
		{"1h", time.Hour, false},
		{"1d", time.Hour * 24, false},
		{"1y", time.Hour * 24 * 365, false},
		{"1d1s", time.Hour*24 + time.Second, false},
		{"1g", 0, true},
	}
	for _, c := range cases {
		d, err := ParseCustomDuration(c.s)
		if err != nil {
			if !c.e {
				t.Errorf("ParseCustomDuration(%s) error: %v", c.s, err)
			}
		} else {
			if c.e {
				t.Errorf("ParseCustomDuration(%s) should error", c.s)
			}
			if d != c.d {
				t.Errorf("ParseCustomDuration(%s) = %v, want %v", c.s, d, c.d)
			}
		}
	}
}
