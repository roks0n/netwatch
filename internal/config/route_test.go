package config

import "testing"

func TestParseGateway(t *testing.T) {
	cases := map[string]string{
		// Linux: `ip -4 route get 1.1.1.1`
		"1.1.1.1 via 192.0.2.1 dev wlan0 src 192.0.2.77 uid 1000\n    cache": "192.0.2.1",
		// Linux, multipath / secondary line noise — first via wins.
		"default via 192.0.2.254 dev eth0 metric 100": "192.0.2.254",
		// macOS: `route -n get default`
		"route to: default\ndestination: default\n        gateway: 198.51.100.1\n": "198.51.100.1",
		// Directly connected default route: no gateway, and "via" must not
		// match substrings of other words.
		"1.1.1.1 dev eth0 src 192.0.2.77\n    cache": "",
		"nothing useful here":                        "",
		"":                                           "",
	}
	for out, want := range cases {
		got := parseGateway(out)
		if want == "" {
			if got != nil {
				t.Errorf("parseGateway(%q) = %v, want nil", out, got)
			}
			continue
		}
		if got == nil || got.String() != want {
			t.Errorf("parseGateway(%q) = %v, want %s", out, got, want)
		}
	}
}
