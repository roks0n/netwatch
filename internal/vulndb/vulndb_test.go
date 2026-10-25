package vulndb

import (
	"encoding/json"
	"testing"

	"github.com/roks0n/netwatch/internal/config"
)

// osvRecord is one OSV entry as api.osv.dev would return it.
const osvRecord = `{
  "id": "GHSA-xxxx-xxxx-xxxx",
  "aliases": ["CVE-2024-99999"],
  "summary": "Test vulnerability",
  "severity": [{"type": "CVSS_V3", "score": "9.8"}],
  "affected": [
    {"package": {"name": "sonarr", "ecosystem": "PyPI"},
     "ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "3.0.0"}, {"fixed": "4.0.10"}]}]}
  ],
  "references": [{"type": "ADVISORY", "url": "https://example.test/advisory"}]
}`

// distroRecord only describes Debian packaging, which must be ignored unless
// include_distro_advisories is on.
const distroRecord = `{
  "id": "DLA-9999-1",
  "summary": "openssh security update",
  "affected": [
    {"package": {"name": "openssh", "ecosystem": "Debian"},
     "versions": ["1:8.9p1-3"]}
  ]
}`

func decodeEntry(t *testing.T, raw string) osvEntry {
	t.Helper()
	var entry osvEntry
	if err := json.Unmarshal([]byte(raw), &entry); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return entry
}

func TestAffectedByUpstreamRange(t *testing.T) {
	entry := decodeEntry(t, osvRecord)

	if hit, known := affectedBy(entry, "4.0.8", false); !hit || !known {
		t.Errorf("4.0.8 should be vulnerable (hit=%v known=%v)", hit, known)
	}
	if hit, known := affectedBy(entry, "4.0.10", false); hit || !known {
		t.Errorf("4.0.10 has the fix (hit=%v known=%v)", hit, known)
	}
	if hit, known := affectedBy(entry, "2.0.0", false); hit || !known {
		t.Errorf("2.0.0 predates the range (hit=%v known=%v)", hit, known)
	}
}

// mixedRecord carries upstream version data next to distro packaging. The
// upstream verdict must win regardless of what the distro entries say.
const mixedRecord = `{
  "id": "GHSA-yyyy-yyyy-yyyy",
  "affected": [
    {"package": {"name": "openssh", "ecosystem": "Debian"},
     "versions": ["1:8.9p1-3"]},
    {"package": {"name": "openssh", "ecosystem": "PyPI"},
     "ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "9.0"}, {"fixed": "9.8"}]}]}
  ]
}`

// emptyRecord carries no version data at all, so its applicability stays
// unknown and it must be kept.
const emptyRecord = `{
  "id": "GHSA-zzzz-zzzz-zzzz",
  "affected": [
    {"package": {"name": "openssh"}}
  ]
}`

func TestAffectedByDistroOnlyIsKnownAndNotHit(t *testing.T) {
	entry := decodeEntry(t, distroRecord)

	// A record whose only version data is another vendor's packaging says
	// nothing about the software we scanned: known, and not us.
	if hit, known := affectedBy(entry, "1:8.9p1-3", false); hit || !known {
		t.Errorf("distro-only should be known-and-not-hit (hit=%v known=%v)", hit, known)
	}
	// Unless the user explicitly asked for distro advisories.
	if hit, known := affectedBy(entry, "1:8.9p1-3", true); !hit || !known {
		t.Error("distro records apply when explicitly included")
	}
}

func TestAffectedByMixedPrefersUpstream(t *testing.T) {
	entry := decodeEntry(t, mixedRecord)

	// The distro version list matches, but upstream says this version is fine.
	if hit, known := affectedBy(entry, "1:8.9p1-3", false); hit || !known {
		t.Errorf("upstream verdict should win (hit=%v known=%v)", hit, known)
	}
	// And when upstream says vulnerable, a distro entry cannot talk us out of it.
	if hit, known := affectedBy(entry, "9.5", false); !hit || !known {
		t.Errorf("9.5 should be vulnerable (hit=%v known=%v)", hit, known)
	}
}

func TestAffectedByWithoutVersionDataStaysUnknown(t *testing.T) {
	entry := decodeEntry(t, emptyRecord)

	if hit, known := affectedBy(entry, "9.5", false); hit || known {
		t.Errorf("no version data must stay unknown (hit=%v known=%v)", hit, known)
	}
}

// TestBuildAdvisoriesDropsDistroOnlyRecords is the regression for the "373
// OpenSSH advisories" report: distro packaging records must never reach the
// finding list, while genuine hits and unknown-applicability records do.
func TestBuildAdvisoriesDropsDistroOnlyRecords(t *testing.T) {
	cfg := &config.Config{} // distro advisories off by default

	distro := decodeEntry(t, distroRecord)
	upstream := decodeEntry(t, osvRecord)
	unknown := decodeEntry(t, emptyRecord)

	got := buildAdvisories([]osvEntry{distro, upstream, unknown}, "4.0.8", cfg)
	if len(got) != 2 {
		ids := []string{}
		for _, a := range got {
			ids = append(ids, a.ID)
		}
		t.Fatalf("kept %d advisories %v, want 2 (distro dropped)", len(got), ids)
	}
	if got[0].ID != upstream.ID || got[0].Applies == nil || !*got[0].Applies {
		t.Errorf("upstream hit wrong: %+v", got[0])
	}
	if got[1].ID != unknown.ID || got[1].Applies != nil {
		t.Errorf("unknown-applicability record should be kept unjudged: %+v", got[1])
	}

	// With distro advisories explicitly on, the distro record comes back.
	on := &config.Config{}
	on.Vulns.IncludeDistroAdvisories = true
	got = buildAdvisories([]osvEntry{distro}, "1:8.9p1-3", on)
	if len(got) != 1 || got[0].ID != distro.ID {
		t.Errorf("include_distro_advisories should keep the record, got %+v", got)
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	entry := decodeEntry(t, osvRecord)
	if got := severityOf(entry); got != "CRITICAL" {
		t.Errorf("severityOf = %q, want CRITICAL", got)
	}
}

func TestFixedVersionPicksHighest(t *testing.T) {
	entry := decodeEntry(t, `{
      "id": "X",
      "affected": [{"ranges": [{"events": [
        {"introduced": "1.0"}, {"fixed": "1.2.3"},
        {"introduced": "2.0"}, {"fixed": "2.1.0"}]}]}]
    }`)
	if got := fixedVersionOf(entry); got != "2.1.0" {
		t.Errorf("fixedVersionOf = %q, want 2.1.0", got)
	}
}

func TestLookupIsCaseInsensitive(t *testing.T) {
	if info, ok := Lookup(" Jellyfin "); !ok || info.Repo != "jellyfin/jellyfin" {
		t.Errorf("Lookup did not normalise the name: %+v", info)
	}
	if _, ok := Lookup("not-a-real-app"); ok {
		t.Error("unknown app must not match")
	}
}
