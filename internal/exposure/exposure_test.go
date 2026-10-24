package exposure

import (
	"reflect"
	"testing"
)

func TestTargetPort(t *testing.T) {
	cases := map[string]int{
		"http://127.0.0.1:8781":            8781,
		"https://umbrel.tailaaeff3.ts.net": 443,
		"http://example.test/path":         80,
		"188.230.154.243:51413":            51413,
		"51413":                            51413,
		"":                                 0,
		"not-a-target":                     0,
		"host:port":                        0,
	}
	for target, want := range cases {
		if got := targetPort(target); got != want {
			t.Errorf("targetPort(%q) = %d, want %d", target, got, want)
		}
	}
}

func TestIsPublicAddr(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":         true,
		"188.230.154.243": true,
		"192.168.1.196":   false, // RFC1918
		"10.0.0.5":        false,
		"127.0.0.1":       false, // loopback
		"100.64.0.1":      false, // Tailscale CGNAT range
		"100.127.255.255": false,
		"not-an-ip":       false,
		"":                false,
	}
	for ip, want := range cases {
		if got := isPublicAddr(ip); got != want {
			t.Errorf("isPublicAddr(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestAppPortsFirst(t *testing.T) {
	in := []int{22, 8096, 443, 51413, 80}
	got := appPortsFirst(in)

	// Preferred ports come first in preference order, the rest ascending.
	want := []int{51413, 8096, 22, 80, 443}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("appPortsFirst(%v) = %v, want %v", in, got, want)
	}
	// The caller's slice must not be reordered in place.
	if in[0] != 22 {
		t.Errorf("input slice mutated: %v", in)
	}
}
