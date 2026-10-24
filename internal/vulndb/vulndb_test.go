package vulndb

import (
	"encoding/json"
	"testing"
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

func TestAffectedByIgnoresDistroEcosystem(t *testing.T) {
	entry := decodeEntry(t, distroRecord)

	if _, known := affectedBy(entry, "1:8.9p1-3", false); known {
		t.Error("distro-only records must not count as upstream signal")
	}
	if hit, known := affectedBy(entry, "1:8.9p1-3", true); !hit || !known {
		t.Error("distro records apply when explicitly included")
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
