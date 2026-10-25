package vulndb

import (
	"strings"
	"testing"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		latest, installed string
		want              bool
	}{
		{"4.1.4", "4.1.3", true},
		{"4.1.3", "4.1.3", false},
		{"4.1.2", "4.1.3", false},
		{"v1.2.0", "1.1.9", true},
		{"1.2", "1.2.0", false}, // missing components compare as zero
		{"1.2.1", "1.2", true},
		{"12.3", "12.2.0", true},
		{"12.3.0", "12.3", false},
		{"1.2.3", "1.2.3-rc1", true}, // release beats its own pre-release
		{"1.2.3-rc1", "1.2.3", false},
		{"release-4.1.3", "4.1.2", true},
		{"", "4.1.3", false}, // unparseable never nags
		{"4.1.4", "", false}, // unknown installed is not an update
		{"nonsense", "4.1.3", false},
	}
	for _, c := range cases {
		if got := isNewer(c.latest, c.installed); got != c.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", c.latest, c.installed, got, c.want)
		}
	}
}

// The detail view distinguishes "behind", "current", and "we cannot tell".
// Guessing the third as either of the first two is how a scanner loses
// credibility, so Outdated reports known separately from behind.
func TestOutdated(t *testing.T) {
	cases := []struct {
		installed, latest string
		behind, known     bool
	}{
		{"4.1.3", "4.1.5", true, true},
		{"4.1.5", "4.1.5", false, true},
		{"4.2.0", "4.1.5", false, true}, // running something newer than upstream
		{"", "4.1.5", false, false},
		{"4.1.3", "", false, false},
		{"nonsense", "4.1.5", false, false},
		{"4.1.3", "nonsense", false, false},
	}
	for _, c := range cases {
		behind, known := Outdated(c.installed, c.latest)
		if behind != c.behind || known != c.known {
			t.Errorf("Outdated(%q, %q) = %v,%v want %v,%v",
				c.installed, c.latest, behind, known, c.behind, c.known)
		}
	}
}

// An advisory is only worth alarming the user about if the version they run
// predates the fix.
func TestAffectsInstalled(t *testing.T) {
	cases := []struct {
		installed, fixed string
		affected, known  bool
	}{
		{"4.1.3", "4.1.4", true, true},  // fix is newer: still exposed
		{"4.1.4", "4.1.4", false, true}, // exactly the fixed version
		{"4.2.0", "4.1.4", false, true}, // already past the fix
		{"9.2p1", "9.2p2", true, true},  // distro suffixes still order
		{"", "4.1.4", false, false},
		{"4.1.3", "", false, false},
		{"4.1.3", "unreleased", false, false},
	}
	for _, c := range cases {
		affected, known := AffectsInstalled(c.installed, c.fixed)
		if affected != c.affected || known != c.known {
			t.Errorf("AffectsInstalled(%q, %q) = %v,%v want %v,%v",
				c.installed, c.fixed, affected, known, c.affected, c.known)
		}
	}
}

func TestExtractVersion(t *testing.T) {
	cases := map[string]string{
		"v4.1.3":          "4.1.3",
		"release-10.8.13": "10.8.13",
		"jellyfin_10.9.7": "10.9.7",
		"no-numbers-here": "",
		"1.2":             "1.2",
	}
	for tag, want := range cases {
		if got := extractVersion(tag); got != want {
			t.Errorf("extractVersion(%q) = %q, want %q", tag, got, want)
		}
	}
}

func TestVersionInRange(t *testing.T) {
	cases := []struct {
		version, spec string
		hit, known    bool
	}{
		{"1.1.0", ">= 1.0, < 1.2", true, true},
		{"1.2.0", ">= 1.0, < 1.2", false, true},
		{"0.9.0", ">= 1.0, < 1.2", false, true},
		{"2.0.0", ">= 1.0, < 1.2", false, true},
		{"1.0.0", "", false, false},
		{"abc", ">= 1.0", false, false},
		{"1.5", "== v1.5", true, true},
	}
	for _, c := range cases {
		hit, known := versionInRange(c.version, c.spec)
		if hit != c.hit || known != c.known {
			t.Errorf("versionInRange(%q, %q) = %v,%v want %v,%v",
				c.version, c.spec, hit, known, c.hit, c.known)
		}
	}
}

func TestVersionIsPatched(t *testing.T) {
	cases := []struct {
		version, spec  string
		patched, known bool
	}{
		{"4.1.4", "4.1.4", true, true},
		{"4.1.3", "4.1.4", false, true},
		{"4.1.4", "< 4.1.4", false, true},
		{"4.1.3", "< 4.1.4", true, true},
		{"4.1.4", "", false, false},
	}
	for _, c := range cases {
		patched, known := versionIsPatched(c.version, c.spec)
		if patched != c.patched || known != c.known {
			t.Errorf("versionIsPatched(%q, %q) = %v,%v want %v,%v",
				c.version, c.spec, patched, known, c.patched, c.known)
		}
	}
}

func TestSecurityNotes(t *testing.T) {
	body := "## What's new\n\nAdds dark mode. Fixes a crash on startup.\n\n" +
		"Fixed a security vulnerability in subtitle parsing (CVE-2025-1234). Thanks!"
	got := securityNotes(body)
	if got == "" {
		t.Fatal("expected the security sentence to survive")
	}
	if !strings.Contains(got, "CVE-2025-1234") {
		t.Errorf("securityNotes lost the CVE sentence: %q", got)
	}
	if strings.Contains(got, "dark mode") {
		t.Errorf("securityNotes kept noise: %q", got)
	}
}
