package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/roks0n/netwatch/internal/model"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "netwatch.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func resultWith(services []model.Service, findings []model.Finding) *model.ScanResult {
	r := model.NewScanResult()
	r.Started = model.UTCNow()
	r.Finished = model.UTCNow()
	r.PublicIP = "203.0.113.7"
	r.Hosts = []model.Host{{IP: "192.0.2.10", Hostname: "nas", Services: services}}
	r.Exposures = []model.Exposure{
		{Kind: "external", Target: "203.0.113.7:51413", Public: true, Verified: true, Detail: "confirmed"},
		{Kind: "serve", Target: "https://umbrel.tailnet.ts.net", Public: false, Detail: "tailnet only"},
	}
	r.Findings = findings
	return r
}

func TestSaveAndReloadRoundTrip(t *testing.T) {
	st := openTemp(t)
	original := resultWith(
		[]model.Service{
			{IP: "192.0.2.10", Port: 8096, Proto: "tcp", App: "Jellyfin", Version: "12.2.0",
				Reach: model.ReachTailnet, Confidence: "high",
				Evidence: []string{"server: Kestrel"}, Exposures: []string{"verified external :8096"}},
			{IP: "192.0.2.10", Port: 51413, Proto: "tcp", App: "Transmission", Version: "4.1.3",
				Reach: model.ReachPublic, Confidence: "medium"},
		},
		[]model.Finding{{Kind: "update", App: "Jellyfin", Ref: "12.2.0->12.3",
			Title: "Update available", Severity: "info", Installed: "12.2.0", Fixed: "12.3"}},
	)

	if _, err := st.Save(original); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := st.Latest()
	if err != nil {
		t.Fatalf("latest: %v", err)
	}

	if loaded.PublicIP != original.PublicIP || len(loaded.Hosts) != 1 {
		t.Fatalf("run header lost: %+v", loaded)
	}
	got := loaded.ServiceByKey()["192.0.2.10:8096/tcp"]
	if got.App != "Jellyfin" || got.Version != "12.2.0" || got.Reach != model.ReachTailnet {
		t.Errorf("service round-trip broken: %+v", got)
	}
	if len(got.Evidence) != 1 || got.Evidence[0] != "server: Kestrel" {
		t.Errorf("evidence lost: %+v", got.Evidence)
	}
	if len(loaded.Exposures) != 2 || loaded.Exposures[0].Verified != true {
		t.Errorf("exposures lost: %+v", loaded.Exposures)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].Fixed != "12.3" {
		t.Errorf("findings lost: %+v", loaded.Findings)
	}
}

func TestFirstSeenSurvivesRescan(t *testing.T) {
	st := openTemp(t)
	finding := model.Finding{Kind: "cve", App: "Jellyfin", Ref: "CVE-2024-1", Severity: "HIGH"}
	if _, err := st.Save(resultWith(nil, []model.Finding{finding})); err != nil {
		t.Fatalf("save: %v", err)
	}

	second := resultWith(nil, []model.Finding{finding})
	if _, err := st.Save(second); err != nil {
		t.Fatalf("second save: %v", err)
	}
	loaded, _ := st.Latest()
	if len(loaded.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(loaded.Findings))
	}
	first := loaded.Findings[0].FirstSeen
	if first == "" || first > model.UTCNow() {
		t.Errorf("first_seen should be preserved, got %q", first)
	}
}

func TestDiffDetectsNewGoneAndReachChanges(t *testing.T) {
	st := openTemp(t)
	base := resultWith([]model.Service{
		{IP: "192.0.2.10", Port: 8096, Proto: "tcp", App: "Jellyfin", Reach: model.ReachLAN},
		{IP: "192.0.2.10", Port: 9091, Proto: "tcp", App: "Transmission", Reach: model.ReachLAN},
	}, nil)
	if _, err := st.Save(base); err != nil {
		t.Fatalf("baseline save: %v", err)
	}

	next := resultWith([]model.Service{
		{IP: "192.0.2.10", Port: 8096, Proto: "tcp", App: "Jellyfin", Reach: model.ReachPublic}, // reach up
		{IP: "192.0.2.10", Port: 8989, Proto: "tcp", App: "Sonarr", Reach: model.ReachLAN},      // new
	}, []model.Finding{{Kind: "update", App: "Sonarr", Ref: "4->5", Severity: "info"}})
	if _, err := st.Save(next); err != nil {
		t.Fatalf("second save: %v", err)
	}

	if next.Diff == nil {
		t.Fatal("diff missing")
	}
	if next.Diff.Baseline {
		t.Error("second scan must not be baseline")
	}
	if len(next.Diff.NewServices) != 1 || next.Diff.NewServices[0] != "192.0.2.10:8989/tcp" {
		t.Errorf("new services: %+v", next.Diff.NewServices)
	}
	if len(next.Diff.GoneServices) != 1 || next.Diff.GoneServices[0] != "192.0.2.10:9091/tcp" {
		t.Errorf("gone services: %+v", next.Diff.GoneServices)
	}
	if len(next.Diff.ReachChanges) != 1 || next.Diff.ReachChanges[0].To != "public" {
		t.Errorf("reach changes: %+v", next.Diff.ReachChanges)
	}
	if len(next.Diff.NewFindings) != 1 || next.Diff.NewFindings[0].App != "Sonarr" {
		t.Errorf("new findings: %+v", next.Diff.NewFindings)
	}

	// The diff must survive a save/reload cycle, not live only in memory.
	loaded, _ := st.Latest()
	if loaded.Diff == nil || len(loaded.Diff.ReachChanges) != 1 {
		t.Errorf("diff was not persisted: %+v", loaded.Diff)
	}
}

func TestHistoryAndPrune(t *testing.T) {
	st := openTemp(t)
	for i := 0; i < 5; i++ {
		if _, err := st.Save(resultWith([]model.Service{
			{IP: "192.0.2.10", Port: 22, Proto: "tcp", App: "OpenSSH", Reach: model.ReachLAN},
		}, nil)); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	rows, err := st.History(10)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(rows) != 5 || rows[0].ID < rows[4].ID {
		t.Fatalf("history wrong: %+v", rows)
	}
	if rows[0].Services != 1 {
		t.Errorf("service count not recorded: %+v", rows[0])
	}

	if err := st.Prune(2); err != nil {
		t.Fatalf("prune: %v", err)
	}
	rows, _ = st.History(10)
	if len(rows) != 2 {
		t.Errorf("prune kept %d runs, want 2", len(rows))
	}
	orphan, err := st.History(10)
	if err != nil || len(orphan) != 2 {
		t.Errorf("post-prune history broken: %v", err)
	}
}

func TestLoadPicksTheRightRun(t *testing.T) {
	st := openTemp(t)

	first := resultWith([]model.Service{
		{IP: "192.0.2.10", Port: 8096, Proto: "tcp", App: "Jellyfin", Version: "10.9.6",
			Reach: model.ReachLAN, Confidence: "high"},
	}, nil)
	first.Started = "2026-10-01T10:00:00Z"
	firstID, err := st.Save(first)
	if err != nil {
		t.Fatalf("save first: %v", err)
	}

	second := resultWith([]model.Service{
		{IP: "192.0.2.10", Port: 51413, Proto: "tcp", App: "Transmission", Version: "4.1.3",
			Reach: model.ReachPublic, Confidence: "high",
			Exposures: []string{"external 203.0.113.7:51413 verified"}},
	}, []model.Finding{{Kind: "cve", App: "Transmission", Ref: "CVE-2025-1111",
		Severity: "critical", Installed: "4.1.3", Fixed: "4.1.4"}})
	second.Started = "2026-10-02T10:00:00Z"
	secondID, err := st.Save(second)
	if err != nil {
		t.Fatalf("save second: %v", err)
	}
	if firstID == secondID {
		t.Fatalf("both saves returned id %d", firstID)
	}

	// Latest is the newest; Load is whichever run you name. The TUI's history
	// tab depends on that difference.
	latest, err := st.Latest()
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.Started != second.Started {
		t.Errorf("Latest returned %s, want the newer scan", latest.Started)
	}

	old, err := st.Load(firstID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if old == nil || old.Started != first.Started {
		t.Fatalf("Load(%d) returned %+v, want the first scan", firstID, old)
	}
	if len(old.Services()) != 1 || old.Services()[0].App != "Jellyfin" {
		t.Errorf("old run services = %+v, want only Jellyfin", old.Services())
	}
	if len(old.Findings) != 0 {
		t.Errorf("old run carries findings from the newer scan: %+v", old.Findings)
	}

	fresh, err := st.Load(secondID)
	if err != nil {
		t.Fatalf("load second: %v", err)
	}
	if len(fresh.Findings) != 1 || fresh.Findings[0].Ref != "CVE-2025-1111" {
		t.Errorf("new run findings = %+v", fresh.Findings)
	}
	if got := fresh.Services()[0].Exposures; len(got) == 0 {
		t.Errorf("exposure evidence lost from the reloaded run")
	}

	// An id that was pruned away is not an error: it is simply nothing.
	missing, err := st.Load(firstID + 1000)
	if err != nil {
		t.Fatalf("load of a missing run: %v", err)
	}
	if missing != nil {
		t.Errorf("missing run returned %+v, want nil", missing)
	}
	if zero, err := st.Load(0); err != nil || zero != nil {
		t.Errorf("Load(0) = %+v,%v want nil,nil", zero, err)
	}
}

func TestCacheGetSet(t *testing.T) {
	st := openTemp(t)
	st.CacheSet("ext:203.0.113.7:22", "public")

	raw, ok := st.CacheGet("ext:203.0.113.7:22", time.Hour)
	if !ok || string(raw) != `"public"` {
		t.Fatalf("cache round-trip failed: %q %v", raw, ok)
	}
	if _, ok := st.CacheGet("ext:203.0.113.7:23", time.Hour); ok {
		t.Error("missing key must miss")
	}
	// Same value written a second time must not duplicate or fail.
	st.CacheSet("ext:203.0.113.7:22", "closed")
	raw, _ = st.CacheGet("ext:203.0.113.7:22", time.Hour)
	if string(raw) != `"closed"` {
		t.Errorf("cache update failed: %q", raw)
	}
	// Anything older than the TTL is a miss.
	st.db.Exec("UPDATE cache SET checked_at = ? WHERE key = ?",
		time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339), "ext:203.0.113.7:22")
	if _, ok := st.CacheGet("ext:203.0.113.7:22", time.Hour); ok {
		t.Error("expired entry must miss")
	}
}
