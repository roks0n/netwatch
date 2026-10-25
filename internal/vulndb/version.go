package vulndb

import (
	"regexp"
	"strconv"
	"strings"
)

// A tolerant version comparator. The apps we track emit tags like "v4.1.3",
// "12.3", "1.36.1-rc1", so strict semver is the wrong tool; numeric components
// with a suffix tie-break cover every case the catalog hits.

var (
	leadingVersionRE = regexp.MustCompile(`^(\d+(?:\.\d+)*)(?:[-._+]?([0-9A-Za-z][0-9A-Za-z.+-]*))?$`)
	looseVersionRE   = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)
	rangePartRE      = regexp.MustCompile(`^(<=|>=|<|>|==|=)\s*v?([0-9][0-9A-Za-z.\-+]*)`)
)

type version struct {
	nums []uint64
	pre  string
	ok   bool
}

// parseVersion reads a version string, tolerating a leading "v", build
// metadata, and trailing junk. ok is false when no digits were found at all.
func parseVersion(s string) version {
	s = strings.TrimSpace(s)
	if s == "" {
		return version{}
	}
	s = strings.TrimLeft(s, "vV")
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}

	if m := leadingVersionRE.FindStringSubmatch(s); m != nil {
		return version{nums: components(m[1]), pre: m[2], ok: true}
	}
	// Tags like "release-4.1.3" or "jellyfin-10.8.13".
	if m := looseVersionRE.FindString(s); m != "" {
		return version{nums: components(m), ok: true}
	}
	return version{}
}

func components(dotted string) []uint64 {
	var out []uint64
	for _, part := range strings.Split(dotted, ".") {
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// compare returns -1, 0 or 1. Missing components compare as zero, so 12.3 is
// newer than 12.2.0, and a release is newer than its own pre-release.
func compare(a, b version) int {
	if !a.ok || !b.ok {
		if a.ok == b.ok {
			return 0
		}
		if a.ok {
			return 1
		}
		return -1
	}
	n := max(len(a.nums), len(b.nums))
	for i := 0; i < n; i++ {
		var x, y uint64
		if i < len(a.nums) {
			x = a.nums[i]
		}
		if i < len(b.nums) {
			y = b.nums[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.pre == b.pre:
		return 0
	case a.pre == "":
		return 1 // 1.2.3 is newer than 1.2.3-rc1
	case b.pre == "":
		return -1
	case a.pre < b.pre:
		return -1
	default:
		return 1
	}
}

func (a version) less(b version) bool { return compare(a, b) < 0 }
func (a version) lte(b version) bool  { return compare(a, b) <= 0 }
func (a version) gt(b version) bool   { return compare(a, b) > 0 }
func (a version) gte(b version) bool  { return compare(a, b) >= 0 }
func (a version) eq(b version) bool   { return compare(a, b) == 0 }

// extractVersion pulls the first dotted number out of a git tag.
func extractVersion(tag string) string {
	if tag == "" {
		return ""
	}
	return looseVersionRE.FindString(tag)
}

// isNewer reports whether latest is strictly newer than installed.
// Unparseable versions never count as an update, so the tool never nags.
func isNewer(latest, installed string) bool {
	a, b := parseVersion(latest), parseVersion(installed)
	if !a.ok || !b.ok {
		return false
	}
	return a.gt(b)
}

// Outdated reports whether latest is a newer release than installed. known is
// false when either side is missing or unparseable, so callers can print
// "unknown" instead of guessing about someone's version.
func Outdated(installed, latest string) (behind, known bool) {
	a, b := parseVersion(latest), parseVersion(installed)
	if !a.ok || !b.ok {
		return false, false
	}
	return a.gt(b), true
}

// AffectsInstalled reports whether an advisory whose fix landed in fixed still
// applies to the installed version — i.e. the installed version is older than
// the fix. known is false when either version is missing or unparseable.
func AffectsInstalled(installed, fixed string) (affected, known bool) {
	a, b := parseVersion(fixed), parseVersion(installed)
	if !a.ok || !b.ok {
		return false, false
	}
	return a.gt(b), true
}

// versionInRange evaluates GitHub's ">= 1.0, < 1.2" style range.
// The bool result is false when we cannot tell.
func versionInRange(v, spec string) (hit bool, known bool) {
	if strings.TrimSpace(spec) == "" {
		return false, false
	}
	current := parseVersion(v)
	if !current.ok {
		return false, false
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		m := rangePartRE.FindStringSubmatch(part)
		if m == nil {
			return false, false
		}
		target := parseVersion(m[2])
		if !target.ok {
			return false, false
		}
		var ok bool
		switch m[1] {
		case "<":
			ok = current.less(target)
		case "<=":
			ok = current.lte(target)
		case ">":
			ok = current.gt(target)
		case ">=":
			ok = current.gte(target)
		default:
			ok = current.eq(target)
		}
		if !ok {
			return false, true
		}
	}
	return true, true
}

// versionIsPatched reports whether the installed version has the fix GitHub
// names in patched_versions. The bool result is false when we cannot tell.
func versionIsPatched(v, spec string) (patched bool, known bool) {
	if strings.TrimSpace(spec) == "" {
		return false, false
	}
	m := looseVersionRE.FindString(spec)
	if m == "" {
		m = regexp.MustCompile(`[0-9][0-9A-Za-z.\-+]*`).FindString(spec)
	}
	if m == "" {
		return false, false
	}
	current, target := parseVersion(v), parseVersion(m)
	if !current.ok || !target.ok {
		return false, false
	}
	if strings.HasPrefix(strings.TrimSpace(spec), "<") {
		return current.less(target), true
	}
	return current.gte(target), true
}
