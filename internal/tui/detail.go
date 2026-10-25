package tui

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/roks0n/netwatch/internal/model"
	"github.com/roks0n/netwatch/internal/report"
	"github.com/roks0n/netwatch/internal/vulndb"
)

// The detail view answers "tell me more about this row": what it is, whether
// its version is behind, how bad its vulnerabilities are for the version
// actually installed, and how far it is exposed.
//
// The builders are pure functions over a ScanResult and return plain text, so
// they are testable without a terminal; renderSections is the only place that
// applies colour or wraps.

// lineKind selects the colour a line is rendered in.
type lineKind int

const (
	linePlain lineKind = iota
	lineOK
	lineWarn
	lineBad
	lineDim
)

// detailLine is one row of a section: an optional label column plus text.
type detailLine struct {
	label string
	value string
	kind  lineKind
}

// detailSection is a titled block of lines.
type detailSection struct {
	heading string
	lines   []detailLine
}

func section(heading string, lines ...detailLine) detailSection {
	return detailSection{heading: heading, lines: lines}
}

func kv(label, value string) detailLine { return detailLine{label: label, value: value} }
func kvKind(label, value string, k lineKind) detailLine {
	return detailLine{label: label, value: value, kind: k}
}
func note(value string) detailLine                 { return detailLine{value: value} }
func noteKind(value string, k lineKind) detailLine { return detailLine{value: value, kind: k} }

// --------------------------------------------------------------- data lookups

// findingsFor returns the findings attached to one service, worst first.
func findingsFor(r *model.ScanResult, key string) []model.Finding {
	var out []model.Finding
	for _, f := range r.Findings {
		if f.ServiceKey == key {
			out = append(out, f)
		}
	}
	sortFindings(out)
	return out
}

// findingsForApp matches findings by app name, for scans whose findings were
// written before service keys were recorded.
func findingsForApp(r *model.ScanResult, app string) []model.Finding {
	var out []model.Finding
	for _, f := range r.Findings {
		if f.ServiceKey == "" && strings.EqualFold(f.App, app) {
			out = append(out, f)
		}
	}
	sortFindings(out)
	return out
}

// sortFindings orders worst first, reusing the report package's triage order.
func sortFindings(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if report.SeverityRank(a.Severity) != report.SeverityRank(b.Severity) {
			return report.SeverityRank(a.Severity) < report.SeverityRank(b.Severity)
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Ref < b.Ref
	})
}

// updateFinding returns the "update" finding naming a newer release, if any.
func updateFinding(r *model.ScanResult, key, app string) (model.Finding, bool) {
	for _, f := range r.Findings {
		if f.Kind != "update" || !strings.EqualFold(f.App, app) {
			continue
		}
		if f.ServiceKey == "" || f.ServiceKey == key {
			return f, true
		}
	}
	return model.Finding{}, false
}

func hostByIP(r *model.ScanResult, ip string) (model.Host, bool) {
	for _, h := range r.Hosts {
		if h.IP == ip {
			return h, true
		}
	}
	return model.Host{}, false
}

// vulnerabilities excludes the bookkeeping "update" findings, which are not
// security problems and must not dilute a severity tally.
func vulnerabilities(fs []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(fs))
	for _, f := range fs {
		if f.Kind != "update" {
			out = append(out, f)
		}
	}
	return out
}

// severityTally counts severities the way a triager reads them: "1 critical,
// 2 high". moderate and medium are the same thing under different vendor
// labels, so they share a bucket.
func severityTally(fs []model.Finding) string {
	if len(fs) == 0 {
		return ""
	}
	counts := map[string]int{}
	for _, f := range fs {
		s := strings.ToLower(strings.TrimSpace(f.Severity))
		if s == "" {
			s = "unknown"
		}
		if s == "moderate" {
			s = "medium"
		}
		counts[s]++
	}
	names := []string{"critical", "high", "medium", "low", "info", "unknown"}
	parts := make([]string, 0, len(names))
	for _, name := range names {
		if n := counts[name]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, name))
		}
	}
	return strings.Join(parts, ", ")
}

// applicability says whether an advisory still bites the installed version.
func applicability(installed, fixed string) (string, lineKind) {
	if strings.TrimSpace(fixed) == "" {
		if strings.TrimSpace(installed) == "" {
			return "version unknown — applicability unknown", lineDim
		}
		return fmt.Sprintf("affects %s — no fixed version published", installed), lineWarn
	}
	affected, known := vulndb.AffectsInstalled(installed, fixed)
	switch {
	case !known:
		return fmt.Sprintf("cannot compare %s with fix %s", orDash(installed), fixed), lineDim
	case affected:
		return fmt.Sprintf("affects %s — fixed in %s", installed, fixed), lineBad
	default:
		return fmt.Sprintf("%s already contains the fix (%s)", installed, fixed), lineOK
	}
}

// -------------------------------------------------------------- the builders

// serviceDetail is what you get for pressing enter on a service row.
func serviceDetail(r *model.ScanResult, key string) []detailSection {
	svc, ok := lookupService(r, key)
	if !ok {
		return nil
	}
	host, _ := hostByIP(r, svc.IP)

	ident := []detailLine{
		kv("host", hostLabel(svc, host)),
		kv("endpoint", svc.Key()),
		kv("app", orDash(svc.Label())),
	}
	if svc.Confidence != "" {
		ident = append(ident, kv("confidence", svc.Confidence))
	}
	if svc.Product != "" && svc.Product != svc.App {
		ident = append(ident, kv("product", svc.Product))
	}

	out := []detailSection{section("Identity", ident...), versionSection(r, svc)}

	if exp := exposureSection(r, svc); len(exp.lines) > 0 {
		out = append(out, exp)
	}
	out = append(out, vulnerabilitySection(r, svc))

	if siblings := sameHostSection(r, svc); len(siblings.lines) > 0 {
		out = append(out, siblings)
	}
	return out
}

// hostDetail is the per-host answer: every port on it, with versions and
// vulnerabilities rolled up so the worst thing is visible at a glance.
func hostDetail(r *model.ScanResult, ip string) []detailSection {
	host, ok := hostByIP(r, ip)
	if !ok {
		return nil
	}

	var all []model.Finding
	public := 0
	for _, s := range host.Services {
		all = append(all, findingsFor(r, s.Key())...)
		if s.Reach == model.ReachPublic {
			public++
		}
	}
	vulns := vulnerabilities(all)

	ident := []detailLine{
		kv("name", orDash(host.Hostname)),
		kv("address", host.IP),
		kv("mac", orDash(host.MAC)),
		kv("ports", fmt.Sprintf("%d open", len(host.Services))),
	}
	kind := lineOK
	if public > 0 {
		kind = lineBad
	}
	ident = append(ident, kvKind("public", fmt.Sprintf("%d service(s) reachable from the internet", public), kind))
	if t := severityTally(vulns); t != "" {
		ident = append(ident, kvKind("vulnerabilities", t, vulnKind(vulns)))
	} else {
		ident = append(ident, kvKind("vulnerabilities", "none known", lineOK))
	}
	out := []detailSection{section("Host", ident...)}

	rows := make([]detailLine, 0, len(host.Services))
	for _, s := range host.Services {
		rows = append(rows, noteKind(summariseService(r, s), serviceKind(r, s)))
	}
	if len(rows) == 0 {
		rows = append(rows, noteKind("no services recorded", lineDim))
	}
	out = append(out, section("Ports", rows...))

	if exps := exposuresForHost(r, host); len(exps) > 0 {
		lines := make([]detailLine, 0, len(exps))
		for _, e := range exps {
			lines = append(lines, noteKind(fmt.Sprintf("%s  %s", e.Kind, e.Target), exposureKind(e)))
			if e.Detail != "" {
				lines = append(lines, noteKind("  "+e.Detail, lineDim))
			}
		}
		out = append(out, section("Exposure evidence", lines...))
	}

	if len(vulns) > 0 {
		lines := make([]detailLine, 0, 12)
		for i, f := range vulns {
			if i >= 12 {
				lines = append(lines, noteKind(fmt.Sprintf("… %d more", len(vulns)-i), lineDim))
				break
			}
			lines = append(lines, noteKind(findingLine(f), vulnKind([]model.Finding{f})))
		}
		out = append(out, section("Advisories", lines...))
	}
	return out
}

// findingDetail explains one advisory: how bad, whether the installed version
// is affected, and what to click to read more.
func findingDetail(r *model.ScanResult, f model.Finding) []detailSection {
	kind := vulnKind([]model.Finding{f})
	head := []detailLine{
		kvKind("severity", orDash(f.Severity), kind),
		kv("kind", f.Kind),
		kv("ref", orDash(f.Ref)),
		kv("app", orDash(f.App)),
	}
	if f.Title != "" {
		head = append(head, kv("title", f.Title))
	}
	if f.Kind == "update" {
		head = append(head, kv("installed", orDash(f.Installed)))
		head = append(head, kvKind("latest", f.Fixed, lineWarn))
	} else {
		verdict, vKind := applicability(f.Installed, f.Fixed)
		head = append(head, kv("installed", orDash(f.Installed)))
		head = append(head, kvKind("impact", verdict, vKind))
	}
	if f.FirstSeen != "" {
		head = append(head, kv("first seen", f.FirstSeen))
	}
	out := []detailSection{section("Advisory", head...)}

	if f.Detail != "" {
		lines := []detailLine{}
		for _, ln := range strings.Split(f.Detail, "\n") {
			if strings.TrimSpace(ln) != "" {
				lines = append(lines, note(ln))
			}
		}
		if len(lines) > 0 {
			out = append(out, section("Notes", lines...))
		}
	}

	if refs := affectedServices(r, f); len(refs) > 0 {
		out = append(out, section("Affected services", refs...))
	}
	if f.URL != "" {
		out = append(out, section("Reference", kv("link", f.URL)))
	}
	return out
}

// exposureDetail explains one public exposure and the service behind it, which
// is the question a port forward raises: what did I just open?
func exposureDetail(r *model.ScanResult, e model.Exposure) []detailSection {
	kind := exposureKind(e)
	head := []detailLine{
		kv("kind", e.Kind),
		kv("target", e.Target),
		kvKind("public", yesNo(e.Public), kind),
		kvKind("verified", yesNo(e.Verified), boolKind(e.Verified)),
	}
	if e.App != "" {
		head = append(head, kv("app", e.App))
	}
	if e.Detail != "" {
		head = append(head, kv("evidence", e.Detail))
	}
	out := []detailSection{section("Exposure", head...)}

	svcs := servicesForExposure(r, e)
	if len(svcs) == 0 {
		out = append(out, section("Service behind it",
			noteKind("no internal service matched this target", lineDim)))
		return out
	}
	lines := make([]detailLine, 0, len(svcs)*2)
	for _, s := range svcs {
		lines = append(lines, noteKind(summariseService(r, s), serviceKind(r, s)))
		for _, ev := range s.Evidence {
			lines = append(lines, noteKind("  "+ev, lineDim))
		}
	}
	out = append(out, section("Service behind it", lines...))

	// The vulnerabilities on the thing that is internet-facing matter most.
	var vulns []model.Finding
	for _, s := range svcs {
		vulns = append(vulns, vulnerabilities(findingsFor(r, s.Key()))...)
	}
	if len(vulns) > 0 {
		sortFindings(vulns)
		lines := make([]detailLine, 0, 8)
		for i, f := range vulns {
			if i >= 8 {
				lines = append(lines, noteKind(fmt.Sprintf("… %d more", len(vulns)-i), lineDim))
				break
			}
			lines = append(lines, noteKind(findingLine(f), vulnKind([]model.Finding{f})))
		}
		out = append(out, section("Advisories on the exposed service", lines...))
	}
	return out
}

// ------------------------------------------------------------------ fragments

func versionSection(r *model.ScanResult, s model.Service) detailSection {
	if strings.TrimSpace(s.Version) == "" {
		return section("Version",
			kvKind("installed", "not detected", lineWarn),
			noteKind(fmt.Sprintf(
				"add an override to enable CVE matching: [overrides] %q = \"%s <version>\"",
				s.Key(), titleCase(s.App)), lineDim))
	}
	lines := []detailLine{kv("installed", s.Version)}
	if up, ok := updateFinding(r, s.Key(), s.App); ok {
		behind, known := vulndb.Outdated(s.Version, up.Fixed)
		switch {
		case !known:
			lines = append(lines, kvKind("latest", up.Fixed+" (versions not comparable)", lineDim))
		case behind:
			lines = append(lines, kvKind("latest", up.Fixed+" — update available", lineWarn))
		default:
			lines = append(lines, kvKind("latest", up.Fixed+" — already the newest", lineOK))
		}
		if up.URL != "" {
			lines = append(lines, kv("release", up.URL))
		}
	} else {
		lines = append(lines, kvKind("latest", "no newer release known", lineOK))
	}
	return section("Version", lines...)
}

func exposureSection(r *model.ScanResult, s model.Service) detailSection {
	var lines []detailLine
	kind := lineOK
	switch s.Reach {
	case model.ReachPublic:
		kind = lineBad
	case model.ReachTailnet:
		kind = lineWarn
	}
	lines = append(lines, kvKind("reach", reachLabel(s.Reach)+reachHint(s.Reach), kind))
	for _, e := range s.Exposures {
		lines = append(lines, noteKind(e, lineDim))
	}
	if s.Reach == model.ReachPublic {
		lines = append(lines, noteKind(
			"reachable from the internet — close the forward or restrict it if that is not intended",
			lineWarn))
	}
	return section("Exposure", lines...)
}

func vulnerabilitySection(r *model.ScanResult, s model.Service) detailSection {
	all := append(findingsFor(r, s.Key()), findingsForApp(r, s.App)...)
	vulns := vulnerabilities(all)
	if len(vulns) == 0 {
		if s.App == "" || strings.EqualFold(s.App, "unknown") {
			return section("Vulnerabilities",
				noteKind("app not identified, so no advisories were looked up", lineDim))
		}
		return section("Vulnerabilities",
			noteKind(fmt.Sprintf("none known for %s %s", s.App, s.Version), lineOK))
	}
	noun, verb := "advisories", "affect"
	if len(vulns) == 1 {
		noun, verb = "advisory", "affects"
	}
	lines := []detailLine{
		noteKind(fmt.Sprintf("%d %s %s this service (%s)", len(vulns), noun, verb, severityTally(vulns)),
			vulnKind(vulns)),
	}
	for i, f := range vulns {
		if i >= 10 {
			lines = append(lines, noteKind(fmt.Sprintf("… %d more", len(vulns)-i), lineDim))
			break
		}
		lines = append(lines, noteKind(findingLine(f), vulnKind([]model.Finding{f})))
		if verdict, _ := applicability(f.Installed, f.Fixed); strings.HasPrefix(verdict, "affects") {
			lines = append(lines, noteKind("  "+verdict, lineBad))
		}
		if f.URL != "" {
			lines = append(lines, noteKind("  "+f.URL, lineDim))
		}
	}
	return section("Vulnerabilities", lines...)
}

func sameHostSection(r *model.ScanResult, s model.Service) detailSection {
	host, ok := hostByIP(r, s.IP)
	if !ok || len(host.Services) < 2 {
		return detailSection{}
	}
	lines := make([]detailLine, 0, len(host.Services))
	for _, other := range host.Services {
		if other.Key() == s.Key() {
			continue
		}
		lines = append(lines, noteKind(summariseService(r, other), serviceKind(r, other)))
	}
	return section("Also on this host", lines...)
}

func affectedServices(r *model.ScanResult, f model.Finding) []detailLine {
	var lines []detailLine
	for _, s := range r.Services() {
		match := s.Key() == f.ServiceKey
		if !match && f.ServiceKey == "" {
			match = strings.EqualFold(s.App, f.App) &&
				(f.Installed == "" || f.Installed == s.Version)
		}
		if match {
			lines = append(lines, noteKind(summariseService(r, s), serviceKind(r, s)))
		}
	}
	return lines
}

// summariseService is the one-line form used wherever services are listed
// inside a detail view: "51413/tcp Transmission 4.1.3  PUBLIC  update · 2 vulns".
func summariseService(r *model.ScanResult, s model.Service) string {
	parts := []string{fmt.Sprintf("%-16s", s.Key()), padRight(orDash(s.Label()), 22), reachLabel(s.Reach)}
	var notes []string
	if _, out := updateFinding(r, s.Key(), s.App); out {
		notes = append(notes, "update available")
	}
	if v := vulnerabilities(findingsFor(r, s.Key())); len(v) > 0 {
		noun := "advisories"
		if len(v) == 1 {
			noun = "advisory"
		}
		notes = append(notes, fmt.Sprintf("%d %s (%s)", len(v), noun, severityTally(v)))
	}
	if len(notes) > 0 {
		parts = append(parts, strings.Join(notes, " · "))
	}
	return strings.Join(parts, "  ")
}

func findingLine(f model.Finding) string {
	line := fmt.Sprintf("%-9s %-22s %s", strings.ToUpper(orDash(f.Severity)), f.Ref, f.Title)
	if f.Fixed != "" && f.Kind != "update" {
		line += "  (fixed in " + f.Fixed + ")"
	}
	return strings.TrimSpace(line)
}

// servicesForExposure works out what internal service an exposed target leads
// to. A router forward names the public address and a funnel names a tailnet
// hostname, so neither address ever equals the LAN address of the thing behind
// it: the port is the reliable link. The address only matters when it is one of
// our own hosts, where it must agree.
func servicesForExposure(r *model.ScanResult, e model.Exposure) []model.Service {
	if strings.TrimSpace(e.Target) == "" {
		return nil
	}
	host, port := splitTarget(e.Target)
	hostIsOurs := host == "" || hostIsLocal(r, host)

	var named, byPort []model.Service
	for _, s := range r.Services() {
		if strings.Contains(strings.Join(s.Exposures, "\n"), e.Target) {
			named = append(named, s)
			continue
		}
		if port <= 0 || s.Port != port {
			continue
		}
		// Either the target names this host exactly, or it names an address we
		// do not own (the router's public IP, a funnel hostname) and the port
		// is all we have to go on.
		if !hostIsOurs || s.IP == host {
			byPort = append(byPort, s)
		}
	}
	out := named
	if len(out) == 0 {
		out = byPort
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

// hostIsLocal reports whether an address belongs to a host this scan saw.
func hostIsLocal(r *model.ScanResult, host string) bool {
	for _, h := range r.Hosts {
		if h.IP == host {
			return true
		}
	}
	return false
}

func exposuresForHost(r *model.ScanResult, host model.Host) []model.Exposure {
	var out []model.Exposure
	for _, e := range r.Exposures {
		for _, s := range servicesForExposure(r, e) {
			if s.IP == host.IP {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

func lookupService(r *model.ScanResult, key string) (model.Service, bool) {
	for _, s := range r.Services() {
		if s.Key() == key {
			return s, true
		}
	}
	return model.Service{}, false
}

// splitTarget pulls host and port out of "1.2.3.4:51413", "http://host:8781/"
// or "https://host" (which implies 443).
func splitTarget(target string) (host string, port int) {
	t := strings.TrimSpace(target)
	if u, err := url.Parse(t); err == nil && u.Scheme != "" {
		host = u.Hostname()
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		} else if strings.EqualFold(u.Scheme, "https") {
			port = 443
		} else if strings.EqualFold(u.Scheme, "http") {
			port = 80
		}
		return host, port
	}
	if h, p, err := net.SplitHostPort(t); err == nil {
		port, _ = strconv.Atoi(p)
		return h, port
	}
	if ip := net.ParseIP(t); ip != nil {
		return t, 0
	}
	return t, 0
}

// ------------------------------------------------------------------- rendering

var (
	headingStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	labelStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

func styleFor(k lineKind) lipgloss.Style {
	switch k {
	case lineOK:
		return okStyle
	case lineWarn:
		return warnStyle
	case lineBad:
		return badStyle
	case lineDim:
		return subtitleStyle
	default:
		return lipgloss.NewStyle()
	}
}

// renderSections lays out a detail view: bold heading, aligned label column,
// colour per line kind, word-wrapped to the terminal width.
func renderSections(sections []detailSection, width int) string {
	if width < 40 {
		width = 40
	}
	var b strings.Builder
	for i, sec := range sections {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(headingStyle.Render(strings.ToUpper(sec.heading)) + "\n")
		labelW := 0
		for _, l := range sec.lines {
			if l.label != "" && len(l.label) > labelW {
				labelW = len(l.label)
			}
		}
		if labelW > 0 && labelW < 10 {
			labelW = 10
		}
		for _, l := range sec.lines {
			for _, ln := range renderLine(l, labelW, width) {
				b.WriteString(ln + "\n")
			}
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// renderLine wraps one line, keeping the label column and indenting the
// continuation lines under the value.
func renderLine(l detailLine, labelW, width int) []string {
	head, cont := "  ", "  "
	if l.label != "" {
		head = "  " + labelStyle.Render(padRight(l.label, labelW)) + "  "
		cont = "  " + strings.Repeat(" ", labelW+2)
	}
	style := styleFor(l.kind)
	indent := lipgloss.Width(head)
	avail := width - indent
	if avail < 20 {
		avail = 20
	}
	var out []string
	for _, para := range strings.Split(l.value, "\n") {
		chunks := wrapWords(para, avail)
		if len(chunks) == 0 {
			chunks = []string{""}
		}
		for j, c := range chunks {
			if j == 0 {
				out = append(out, head+style.Render(c))
			} else {
				out = append(out, cont+style.Render(c))
			}
		}
	}
	return out
}

// wrapWords breaks plain text on spaces, never wider than n.
func wrapWords(s string, n int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, w := range words {
		switch {
		case cur == "":
			cur = w
		case lipgloss.Width(cur)+1+lipgloss.Width(w) <= n:
			cur += " " + w
		default:
			lines = append(lines, cur)
			cur = w
		}
		for lipgloss.Width(cur) > n { // single word longer than the line
			r := []rune(cur)
			cut := n
			if cut > len(r) {
				cut = len(r)
			}
			lines = append(lines, string(r[:cut]))
			cur = string(r[cut:])
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// ------------------------------------------------------------------ small util

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func hostLabel(s model.Service, h model.Host) string {
	name := orDash(h.Hostname)
	if h.MAC != "" {
		return fmt.Sprintf("%s · %s · %s", name, s.IP, h.MAC)
	}
	return fmt.Sprintf("%s · %s", name, s.IP)
}

func reachHint(r model.Reach) string {
	switch r {
	case model.ReachPublic:
		return "  ← reachable from the internet"
	case model.ReachTailnet:
		return "  ← tailnet only"
	default:
		return "  ← local network only"
	}
}

func vulnKind(fs []model.Finding) lineKind {
	worst := 99
	for _, f := range fs {
		if r := report.SeverityRank(f.Severity); r < worst {
			worst = r
		}
	}
	switch {
	case worst <= 1:
		return lineBad
	case worst <= 3:
		return lineWarn
	case worst == 4:
		return lineDim
	default:
		return linePlain
	}
}

func serviceKind(r *model.ScanResult, s model.Service) lineKind {
	if s.Reach == model.ReachPublic {
		return lineBad
	}
	if len(vulnerabilities(findingsFor(r, s.Key()))) > 0 {
		return lineWarn
	}
	return linePlain
}

func exposureKind(e model.Exposure) lineKind {
	switch {
	case e.Public && e.Verified:
		return lineBad
	case e.Public:
		return lineWarn
	case e.Verified:
		return lineOK
	default:
		return lineDim
	}
}

func boolKind(b bool) lineKind {
	if b {
		return lineOK
	}
	return lineWarn
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] -= 32
	}
	return string(r)
}
