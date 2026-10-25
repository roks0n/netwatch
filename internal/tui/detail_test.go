package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/roks0n/netwatch/internal/model"
)

// fixture is the scan a detail view is judged against: a box with one
// internet-facing service whose version is behind and carries a live CVE plus a
// stale advisory, one tailnet service with a MODERATE advisory, and one LAN
// host whose app has no published fix.
func fixture() *model.ScanResult {
	trans := model.Service{
		IP: "192.0.2.10", Port: 51413, Proto: "tcp",
		App: "Transmission", Version: "4.1.3", Reach: model.ReachPublic, Confidence: "high",
		Evidence:  []string{"banner: Transmission/4.1.3"},
		Exposures: []string{"external 203.0.113.7:51413 verified"},
	}
	jelly := model.Service{
		IP: "192.0.2.10", Port: 8096, Proto: "tcp",
		App: "Jellyfin", Version: "10.9.6", Reach: model.ReachTailnet, Confidence: "medium",
	}
	ssh := model.Service{
		IP: "192.0.2.20", Port: 22, Proto: "tcp",
		App: "OpenSSH", Version: "9.2p1", Reach: model.ReachLAN, Confidence: "high",
	}
	noVersion := model.Service{
		IP: "192.0.2.30", Port: 8781, Proto: "tcp",
		App: "dashboard", Reach: model.ReachPublic, Confidence: "low",
	}

	r := model.NewScanResult()
	r.Started = "2026-10-25T12:00:00Z"
	r.PublicIP = "203.0.113.7"
	r.Hosts = []model.Host{
		{IP: "192.0.2.10", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "umbrel", Services: []model.Service{trans, jelly}},
		{IP: "192.0.2.20", Hostname: "nas", Services: []model.Service{ssh}},
		{IP: "192.0.2.30", Hostname: "laptop", Services: []model.Service{noVersion}},
	}
	r.Exposures = []model.Exposure{
		{Kind: "external", Target: "203.0.113.7:51413", Public: true, Verified: true,
			Detail: "confirmed from the VPS", App: "Transmission"},
		{Kind: "funnel", Target: "https://dashboard.example.ts.net:8781", Public: true, Verified: true,
			Detail: "tailscale funnel", App: "dashboard"},
		{Kind: "upnp", Target: "203.0.113.7:32400", Public: false, Detail: "mapped, not verified"},
	}
	r.Findings = []model.Finding{
		{Kind: "update", App: "Transmission", Ref: "4.1.3->4.1.5",
			Title: "Update available: Transmission 4.1.3 -> 4.1.5", Severity: "info",
			ServiceKey: trans.Key(), Installed: "4.1.3", Fixed: "4.1.5",
			URL: "https://example.test/transmission/releases"},
		{Kind: "cve", App: "Transmission", Ref: "CVE-2025-1111",
			Title: "Remote code execution in the peer handler", Severity: "critical",
			ServiceKey: trans.Key(), Installed: "4.1.3", Fixed: "4.1.4",
			URL: "https://example.test/advisories/CVE-2025-1111"},
		{Kind: "advisory", App: "Transmission", Ref: "CVE-2023-2222",
			Title: "Bug fixed long before this release", Severity: "high",
			ServiceKey: trans.Key(), Installed: "4.1.3", Fixed: "4.0.0"},
		{Kind: "advisory", App: "Jellyfin", Ref: "GHSA-3333", Title: "Cross-site scripting in the player",
			Severity: "MODERATE", ServiceKey: jelly.Key(), Installed: "10.9.6", Fixed: "10.10.0"},
		{Kind: "advisory", App: "OpenSSH", Ref: "DISTRO-4444", Title: "Distro advisory with no fix yet",
			Severity: "critical", ServiceKey: ssh.Key(), Installed: "9.2p1"},
	}
	return r
}

// --------------------------------------------------------------- test helpers

func sectionByName(t *testing.T, secs []detailSection, heading string) detailSection {
	t.Helper()
	for _, s := range secs {
		if strings.EqualFold(s.heading, heading) {
			return s
		}
	}
	var have []string
	for _, s := range secs {
		have = append(have, s.heading)
	}
	t.Fatalf("no section %q, got %v", heading, have)
	return detailSection{}
}

func (d detailSection) text() string {
	parts := make([]string, 0, len(d.lines))
	for _, l := range d.lines {
		parts = append(parts, l.label+" "+l.value)
	}
	return strings.Join(parts, "\n")
}

func wantLine(t *testing.T, sec detailSection, substr string) {
	t.Helper()
	if !strings.Contains(sec.text(), substr) {
		t.Errorf("section %q has no line containing %q:\n%s", sec.heading, substr, sec.text())
	}
}

func wantNoLine(t *testing.T, sec detailSection, substr string) {
	t.Helper()
	if strings.Contains(sec.text(), substr) {
		t.Errorf("section %q should not mention %q:\n%s", sec.heading, substr, sec.text())
	}
}

// -------------------------------------------------------------------- versions

func TestServiceDetailVersionOutdated(t *testing.T) {
	secs := serviceDetail(fixture(), "192.0.2.10:51413/tcp")
	ver := sectionByName(t, secs, "Version")
	wantLine(t, ver, "4.1.3")
	wantLine(t, ver, "4.1.5 — update available")
	wantLine(t, ver, "example.test/transmission/releases")
}

func TestServiceDetailVersionCurrent(t *testing.T) {
	r := fixture()
	for i, f := range r.Findings {
		if f.Kind == "update" {
			r.Findings[i].Fixed = f.Installed // upstream release is the one we run
		}
	}
	ver := sectionByName(t, serviceDetail(r, "192.0.2.10:51413/tcp"), "Version")
	wantLine(t, ver, "already the newest")
	wantNoLine(t, ver, "update available")
}

func TestServiceDetailVersionUnknown(t *testing.T) {
	ver := sectionByName(t, serviceDetail(fixture(), "192.0.2.30:8781/tcp"), "Version")
	wantLine(t, ver, "not detected")
	// The point of saying so is telling the user how to fix it.
	wantLine(t, ver, `[overrides] "192.0.2.30:8781/tcp" = "Dashboard <version>"`)
}

func TestApplicabilityVerdicts(t *testing.T) {
	cases := []struct {
		name, installed, fixed, want string
		kind                         lineKind
	}{
		{"still affects", "4.1.3", "4.1.4", "affects 4.1.3 — fixed in 4.1.4", lineBad},
		{"already fixed", "4.1.3", "4.0.0", "4.1.3 already contains the fix (4.0.0)", lineOK},
		{"no fix published", "9.2p1", "", "affects 9.2p1 — no fixed version published", lineWarn},
		{"uncomparable", "9.2p1", "unreleased", "cannot compare", lineDim},
		{"nothing known", "", "", "version unknown — applicability unknown", lineDim},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, kind := applicability(c.installed, c.fixed)
			if !strings.Contains(got, c.want) {
				t.Errorf("applicability(%q, %q) = %q, want it to contain %q", c.installed, c.fixed, got, c.want)
			}
			if kind != c.kind {
				t.Errorf("applicability(%q, %q) kind = %v, want %v", c.installed, c.fixed, kind, c.kind)
			}
		})
	}
}

// ------------------------------------------------------------------- severities

func TestSeverityTally(t *testing.T) {
	cases := []struct {
		name string
		in   []model.Finding
		want string
	}{
		{"empty", nil, ""},
		{"moderate counts as medium",
			[]model.Finding{{Severity: "MODERATE"}, {Severity: "medium"}, {Severity: "critical"}},
			"1 critical, 2 medium"},
		{"ordered worst first",
			[]model.Finding{{Severity: "low"}, {Severity: "high"}, {Severity: "low"}},
			"1 high, 2 low"},
		{"blank is unknown", []model.Finding{{Severity: "  "}}, "1 unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := severityTally(c.in); got != c.want {
				t.Errorf("severityTally() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestUpdatesNeverDiluteTheTally(t *testing.T) {
	// Transmission carries two advisories plus one "update available" notice.
	// Counting the update as a vulnerability would report three.
	vulns := vulnerabilities(findingsFor(fixture(), "192.0.2.10:51413/tcp"))
	if len(vulns) != 2 {
		t.Fatalf("want 2 advisories, got %d: %v", len(vulns), vulns)
	}
	if got := severityTally(vulns); got != "1 critical, 1 high" {
		t.Errorf("tally = %q", got)
	}
}

func TestVulnerabilitySectionShowsImpactPerAdvisory(t *testing.T) {
	sec := sectionByName(t, serviceDetail(fixture(), "192.0.2.10:51413/tcp"), "Vulnerabilities")
	wantLine(t, sec, "2 advisories affect this service (1 critical, 1 high)")
	wantLine(t, sec, "CVE-2025-1111")
	wantLine(t, sec, "affects 4.1.3 — fixed in 4.1.4")
	// The stale advisory must not be presented as a live problem.
	if strings.Contains(sec.text(), "affects 4.1.3 — fixed in 4.0.0") {
		t.Errorf("already-fixed advisory shown as live:\n%s", sec.text())
	}
}

func TestVulnerabilitySectionUnknownApp(t *testing.T) {
	r := fixture()
	r.Hosts[2].Services[0].App = ""
	sec := sectionByName(t, serviceDetail(r, "192.0.2.30:8781/tcp"), "Vulnerabilities")
	wantLine(t, sec, "app not identified")
}

// ------------------------------------------------------------------- exposure

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		target   string
		wantHost string
		wantPort int
	}{
		{"203.0.113.7:51413", "203.0.113.7", 51413},
		{"https://dashboard.example.ts.net:8781", "dashboard.example.ts.net", 8781},
		{"https://dashboard.example.ts.net", "dashboard.example.ts.net", 443},
		{"http://dashboard.example.ts.net/", "dashboard.example.ts.net", 80},
		{"203.0.113.7", "203.0.113.7", 0},
	}
	for _, c := range cases {
		host, port := splitTarget(c.target)
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("splitTarget(%q) = %q,%d want %q,%d", c.target, host, port, c.wantHost, c.wantPort)
		}
	}
}

func TestExposureDetailNamesTheServiceBehindIt(t *testing.T) {
	// A router forward names the public address, so the port is the only link
	// to the internal service. Getting this wrong hides what was opened.
	e, ok := findExposure(fixture().PublicExposures(), "203.0.113.7:51413")
	if !ok {
		t.Fatal("exposure not found")
	}
	secs := exposureDetail(fixture(), e)
	wantLine(t, sectionByName(t, secs, "Exposure"), "confirmed from the VPS")
	wantLine(t, sectionByName(t, secs, "Service behind it"), "Transmission 4.1.3")
	wantLine(t, sectionByName(t, secs, "Service behind it"), "PUBLIC")
	adv := sectionByName(t, secs, "Advisories on the exposed service")
	wantLine(t, adv, "CVE-2025-1111")
	wantNoLine(t, adv, "GHSA-3333") // Jellyfin is not behind this forward
}

func TestExposureDetailFunnelMatchesByPort(t *testing.T) {
	e, _ := findExposure(fixture().PublicExposures(), "https://dashboard.example.ts.net:8781")
	secs := exposureDetail(fixture(), e)
	wantLine(t, sectionByName(t, secs, "Service behind it"), "dashboard")
}

func TestExposureDetailWithoutAService(t *testing.T) {
	// A forward to a port nothing listens on must say so rather than invent a
	// service, which is what an empty target used to do.
	e := model.Exposure{Kind: "upnp", Target: "203.0.113.7:32400", Public: true, Detail: "mapped, not verified"}
	secs := exposureDetail(fixture(), e)
	wantLine(t, sectionByName(t, secs, "Service behind it"), "no internal service matched")
}

func TestServiceDetailExposureExplainsPublic(t *testing.T) {
	sec := sectionByName(t, serviceDetail(fixture(), "192.0.2.10:51413/tcp"), "Exposure")
	wantLine(t, sec, "PUBLIC")
	wantLine(t, sec, "reachable from the internet")
}

// ----------------------------------------------------------------------- hosts

func TestHostDetailRollsUpTheWorstThing(t *testing.T) {
	secs := hostDetail(fixture(), "192.0.2.10")
	host := sectionByName(t, secs, "Host")
	wantLine(t, host, "umbrel")
	wantLine(t, host, "aa:bb:cc:dd:ee:ff")
	wantLine(t, host, "2 open")
	wantLine(t, host, "1 service(s) reachable from the internet")
	// 2 on Transmission + 1 on Jellyfin, with MODERATE bucketed as medium.
	wantLine(t, host, "1 critical, 1 high, 1 medium")

	wantLine(t, sectionByName(t, secs, "Ports"), "Transmission 4.1.3")
	wantLine(t, sectionByName(t, secs, "Ports"), "Jellyfin 10.9.6")
	wantLine(t, sectionByName(t, secs, "Advisories"), "CVE-2025-1111")

	// Evidence that something is reachable belongs on the host too.
	wantLine(t, sectionByName(t, secs, "Exposure evidence"), "203.0.113.7:51413")
}

func TestHostDetailCleanHost(t *testing.T) {
	r := fixture()
	r.Findings = nil
	secs := hostDetail(r, "192.0.2.20")
	wantLine(t, sectionByName(t, secs, "Host"), "none known")
	if _, ok := findSection(secs, "Advisories"); ok {
		t.Error("clean host should not carry an Advisories section")
	}
}

func findSection(secs []detailSection, heading string) (detailSection, bool) {
	for _, s := range secs {
		if strings.EqualFold(s.heading, heading) {
			return s, true
		}
	}
	return detailSection{}, false
}

func TestSortHostsPutsPublicFirst(t *testing.T) {
	r := fixture()
	sorted := sortHosts(r, r.Hosts)
	if len(sorted) != 3 {
		t.Fatalf("want 3 hosts, got %d", len(sorted))
	}
	if sorted[0].IP != "192.0.2.10" { // the only host with a public service
		t.Errorf("first host = %s, want the internet-facing one", sorted[0].IP)
	}
	if sorted[1].IP != "192.0.2.30" { // public too, but no advisories on it
		t.Errorf("second host = %s, want 192.0.2.30", sorted[1].IP)
	}
	if sorted[2].IP != "192.0.2.20" { // lan only, yet it holds a critical advisory
		t.Errorf("third host = %s, want 192.0.2.20", sorted[2].IP)
	}
}

// -------------------------------------------------------------------- findings

func TestFindingDetailImpactAndAffectedService(t *testing.T) {
	r := fixture()
	f := r.Findings[1] // CVE-2025-1111
	secs := findingDetail(r, f)
	adv := sectionByName(t, secs, "Advisory")
	wantLine(t, adv, "critical")
	wantLine(t, adv, "affects 4.1.3 — fixed in 4.1.4")
	wantLine(t, sectionByName(t, secs, "Affected services"), "192.0.2.10:51413/tcp")
	wantLine(t, sectionByName(t, secs, "Reference"), "https://")
}

func TestFindingDetailUpdateIsNotAnIncident(t *testing.T) {
	r := fixture()
	secs := findingDetail(r, r.Findings[0]) // the "update" finding
	adv := sectionByName(t, secs, "Advisory")
	wantLine(t, adv, "4.1.3")
	wantLine(t, adv, "4.1.5")
	wantNoLine(t, adv, "impact") // an available update is not an applicability verdict
}

func TestFindingDetailSortsWorstFirstWithinAService(t *testing.T) {
	fs := findingsFor(fixture(), "192.0.2.10:51413/tcp")
	if len(fs) < 2 {
		t.Fatalf("want findings, got %d", len(fs))
	}
	if fs[0].Severity != "critical" {
		t.Errorf("first finding = %s/%s, want the critical one", fs[0].Severity, fs[0].Ref)
	}
}

// ------------------------------------------------------------------- rendering

func TestRenderSectionsStaysInsideTheWidth(t *testing.T) {
	const width = 72
	out := renderSections(hostDetail(fixture(), "192.0.2.10"), width)
	if out == "" {
		t.Fatal("nothing rendered")
	}
	for i, line := range strings.Split(out, "\n") {
		if w := lipgloss.Width(line); w > width {
			t.Errorf("line %d is %d wide (max %d): %q", i, w, width, line)
		}
	}
	// Headings are the signposts; they must survive wrapping.
	if !strings.Contains(out, "VULNERABILITIES") && !strings.Contains(out, "ADVISORIES") {
		t.Errorf("headings missing from:\n%s", out)
	}
}

func TestWrapWords(t *testing.T) {
	got := wrapWords("one two three four five", 9)
	want := []string{"one two", "three", "four five"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q want %q", got, want)
	}
	if got := wrapWords("supercalifragilistic", 10); len(got) != 2 {
		t.Errorf("a long word must be cut, got %q", got)
	}
	if got := wrapWords("   ", 10); got != nil {
		t.Errorf("blank wraps to nothing, got %q", got)
	}
}

func TestRenderLineAlignsValuesUnderEachOther(t *testing.T) {
	secs := []detailSection{section("X", kv("a", "1"), kv("longer", "2"))}
	lines := strings.Split(renderSections(secs, 60), "\n")
	if len(lines) != 3 { // heading + two rows
		t.Fatalf("got %d lines:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	a, b := strings.Index(lines[1], "1"), strings.Index(lines[2], "2")
	if a < 0 || b < 0 || a != b {
		t.Errorf("values not aligned: %q / %q", lines[1], lines[2])
	}
}
