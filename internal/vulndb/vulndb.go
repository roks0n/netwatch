// Package vulndb tracks CVEs and new releases for the apps this network runs.
package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/roks0n/netwatch/internal/config"
	"github.com/roks0n/netwatch/internal/model"
)

// Progress reports percent-complete and a human-readable stage.
type Progress func(pct int, msg string)

// Cache lets advisory lookups survive between scans. Store implements it.
type Cache interface {
	CacheGet(key string, ttl time.Duration) (json.RawMessage, bool)
	CacheSet(key string, value any)
}

// AppInfo is what we know about a fingerprinted application upstream.
type AppInfo struct {
	Name string
	Repo string // owner/name on GitHub, empty when the project has no public repo
	OSV  string // package name in the OSV upstream ecosystems, empty when absent
}

// catalog maps a canonical app name to its upstream sources.
var catalog = map[string]AppInfo{
	"transmission":   {"Transmission", "transmission/transmission", "transmission"},
	"jellyfin":       {"Jellyfin", "jellyfin/jellyfin", "jellyfin"},
	"sonarr":         {"Sonarr", "Sonarr/Sonarr", "sonarr"},
	"radarr":         {"Radarr", "Radarr/Radarr", "radarr"},
	"prowlarr":       {"Prowlarr", "Prowlarr/Prowlarr", "prowlarr"},
	"bazarr":         {"Bazarr", "morpheus65535/bazarr", "bazarr"},
	"jellyseerr":     {"Jellyseerr", "Fallenbagel/jellyseerr", "jellyseerr"},
	"uptime kuma":    {"Uptime Kuma", "louislam/uptime-kuma", "uptime-kuma"},
	"tailscale":      {"Tailscale", "tailscale/tailscale", "tailscale"},
	"umbrel":         {"Umbrel", "getumbrel/umbrel", "umbrel"},
	"nginx":          {"nginx", "nginx/nginx", "nginx"},
	"openssh":        {"OpenSSH", "", "openssh"},
	"apache":         {"Apache", "", "apache2"},
	"postgresql":     {"PostgreSQL", "postgres/postgres", "postgresql"},
	"valkey":         {"Valkey", "valkey-io/valkey", "valkey"},
	"redis":          {"Redis", "redis/redis", "redis"},
	"home assistant": {"Home Assistant", "home-assistant/core", "home-assistant"},
	"grafana":        {"Grafana", "grafana/grafana", "grafana"},
	"portainer":      {"Portainer", "portainer/portainer", "portainer"},
	"plex":           {"Plex", "", "plex"},
	"docker api":     {"Docker", "moby/moby", "docker"},
}

// Lookup returns the catalog entry for an app name, case-insensitively.
func Lookup(app string) (AppInfo, bool) {
	info, ok := catalog[strings.TrimSpace(strings.ToLower(app))]
	return info, ok
}

// AllApps returns every catalogued app sorted by name, for `netwatch catalog`.
func AllApps() []AppInfo {
	out := make([]AppInfo, 0, len(catalog))
	for _, info := range catalog {
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

var (
	cveRE        = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
	securityRE   = regexp.MustCompile(`(?i)\b(security|vulnerab\w*|cve-|rce|remote code execution)\b`)
	anyVersionRE = regexp.MustCompile(`[0-9][0-9A-Za-z.\-+]*`)
)

// ------------------------------------------------------------------ OSV queries

// osvEntry is the subset of an OSV record this tool reads.
type osvEntry struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Versions []string `json:"versions"`
		Ranges   []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

// Advisory is one normalised vulnerability, from OSV or GitHub.
type Advisory struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity string   `json:"severity"`
	Fixed    string   `json:"fixed,omitempty"`
	Applies  *bool    `json:"applies"`
	URL      string   `json:"url,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

func severityOf(v osvEntry) string {
	if s := strings.TrimSpace(v.DatabaseSpecific.Severity); s != "" {
		return strings.ToUpper(s)
	}
	for _, s := range v.Severity {
		score := strings.TrimSpace(s.Score)
		if score == "" {
			continue
		}
		// CVSS vectors ("CVSS:3.1/AV:N/...") carry no usable scalar.
		var n float64
		if _, err := fmt.Sscanf(score, "%f", &n); err != nil {
			continue
		}
		switch {
		case n >= 9:
			return "CRITICAL"
		case n >= 7:
			return "HIGH"
		case n >= 4:
			return "MEDIUM"
		default:
			return "LOW"
		}
	}
	return "unknown"
}

func fixedVersionOf(v osvEntry) string {
	var fixed []string
	for _, aff := range v.Affected {
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if f, ok := ev["fixed"]; ok && f != "" {
					fixed = append(fixed, f)
				}
			}
		}
	}
	if len(fixed) == 0 {
		return ""
	}
	sort.SliceStable(fixed, func(i, j int) bool {
		return parseVersion(fixed[i]).less(parseVersion(fixed[j]))
	})
	return fixed[len(fixed)-1]
}

// inRange evaluates a version against one OSV SEMVER/ECOSYSTEM range.
func inRange(v string, events []map[string]string) (hit bool, known bool) {
	current := parseVersion(v)
	if !current.ok {
		return false, false
	}
	var introduced, fixed, last version
	sawAny := false
	for _, ev := range events {
		if s, ok := ev["introduced"]; ok && s != "0" {
			if p := parseVersion(s); p.ok {
				introduced, sawAny = p, true
			}
		}
		if s, ok := ev["fixed"]; ok {
			if p := parseVersion(s); p.ok {
				fixed, sawAny = p, true
			}
		}
		if s, ok := ev["last_affected"]; ok {
			if p := parseVersion(s); p.ok {
				last, sawAny = p, true
			}
		}
	}
	if !sawAny {
		return false, false
	}
	if introduced.ok && current.less(introduced) {
		return false, true
	}
	if fixed.ok && current.gte(fixed) {
		return false, true
	}
	if last.ok && current.gt(last) {
		return false, true
	}
	return true, true
}

// upstreamEcosystems are the OSV ecosystems that describe the software itself.
// Distro ecosystems (Debian, Alpine, Ubuntu...) describe patched packaging and
// would bury a homelab in hundreds of OpenSSH CVEs that do not apply here.
var upstreamEcosystems = []string{
	"pypi", "npm", "go", "crates.io", "maven", "nuget", "rubygems",
	"packagist", "composer", "hex", "pub", "swifturl", "github actions",
}

// affectedBy reports whether an installed version is in the vulnerable set.
// The second result is false when the record says nothing about versions at
// all. A record whose only version data lives in distro ecosystems (Alpine's
// "10.1_p1-r0", Ubuntu's epoch-suffixed debs) says nothing about the software
// we scanned — those vendors' backports are not our vulnerability state — so
// it counts as known-and-not-hit and gets dropped instead of filed as unknown.
func affectedBy(v osvEntry, version string, includeDistro bool) (hit bool, known bool) {
	any := false
	distroOnly := false
	results := []bool{}
	for _, aff := range v.Affected {
		eco := strings.ToLower(strings.TrimSpace(aff.Package.Ecosystem))
		if !includeDistro && eco != "" && !slices.Contains(upstreamEcosystems, eco) {
			distroOnly = true
			continue
		}
		if len(aff.Versions) > 0 {
			any = true
			trimmed := strings.TrimLeft(version, "vV")
			for _, candidate := range aff.Versions {
				if strings.TrimLeft(candidate, "vV") == trimmed {
					results = append(results, true)
					break
				}
			}
		}
		for _, r := range aff.Ranges {
			if strings.EqualFold(r.Type, "GIT") {
				continue
			}
			any = true
			if got, ok := inRange(version, r.Events); ok {
				results = append(results, got)
			}
		}
	}
	if !any {
		return false, distroOnly
	}
	return slices.Contains(results, true), true
}

// ------------------------------------------------------------------ HTTP helpers

type client struct {
	http  *http.Client
	token string
}

func newClient(cfg *config.Config) *client {
	return &client{
		http:  &http.Client{Timeout: 20 * time.Second},
		token: cfg.Vulns.GitHubToken,
	}
}

func (c *client) get(ctx context.Context, endpoint string, params map[string]string, headers map[string]string) ([]byte, int, error) {
	if len(params) > 0 {
		var parts []string
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, k+"="+params[k])
		}
		endpoint += "?" + strings.Join(parts, "&")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "netwatch/0.1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return body, resp.StatusCode, err
}

func (c *client) githubHeaders() map[string]string {
	headers := map[string]string{"Accept": "application/vnd.github+json"}
	if c.token != "" {
		headers["Authorization"] = "Bearer " + c.token
	}
	return headers
}

func (c *client) cachedGet(ctx context.Context, endpoint, key string, cache Cache, ttl time.Duration, headers map[string]string, params map[string]string) ([]byte, bool) {
	if cache != nil {
		if raw, ok := cache.CacheGet(key, ttl); ok {
			return raw, true
		}
	}
	body, status, err := c.get(ctx, endpoint, params, headers)
	if err != nil || status != http.StatusOK {
		return nil, false
	}
	if !json.Valid(body) {
		return nil, false
	}
	if cache != nil {
		cache.CacheSet(key, json.RawMessage(body))
	}
	return body, true
}

// ---------------------------------------------------------------- GitHub releases

// Release is the latest published release of a catalogued app.
type Release struct {
	Version   string `json:"version,omitempty"`
	Tag       string `json:"tag,omitempty"`
	URL       string `json:"url,omitempty"`
	Body      string `json:"body,omitempty"`
	Published string `json:"published_at,omitempty"`
}

// LatestRelease asks GitHub for the newest release of an app's repository.
func LatestRelease(ctx context.Context, app AppInfo, cfg *config.Config, cache Cache) (Release, bool) {
	if app.Repo == "" {
		return Release{}, false
	}
	c := newClient(cfg)
	body, ok := c.cachedGet(ctx, "https://api.github.com/repos/"+app.Repo+"/releases/latest",
		"gh:"+app.Repo, cache, cfg.VulnCacheTTL(), c.githubHeaders(), nil)
	if !ok {
		return Release{}, false
	}
	var payload struct {
		TagName     string `json:"tag_name"`
		HTMLURL     string `json:"html_url"`
		Body        string `json:"body"`
		PublishedAt string `json:"published_at"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.TagName == "" {
		return Release{}, false
	}
	release := Release{
		Version:   extractVersion(payload.TagName),
		Tag:       payload.TagName,
		URL:       payload.HTMLURL,
		Published: payload.PublishedAt,
	}
	if len(payload.Body) > 4000 {
		release.Body = payload.Body[:4000]
	} else {
		release.Body = payload.Body
	}
	return release, true
}

// securityNotes pulls the sentences a release notes body devoted to security,
// so an "update available" line says whether the upgrade matters.
func securityNotes(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	var hits []string
	for _, sentence := range splitSentences(body) {
		sentence = strings.TrimSpace(sentence)
		if sentence == "" {
			continue
		}
		if securityRE.MatchString(sentence) || cveRE.MatchString(sentence) {
			hits = append(hits, sentence)
		}
	}
	joined := strings.Join(hits, " ")
	if len(joined) > 400 {
		joined = joined[:400]
	}
	return joined
}

// splitSentences breaks text at ". ! ?" followed by whitespace, keeping the marks.
func splitSentences(text string) []string {
	var out []string
	start := 0
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		if (runes[i] == '.' || runes[i] == '!' || runes[i] == '?') &&
			i+1 < len(runes) && (runes[i+1] == ' ' || runes[i+1] == '\n' || runes[i+1] == '\t') {
			out = append(out, string(runes[start:i+1]))
			start = i + 1
		}
	}
	if start < len(runes) {
		out = append(out, string(runes[start:]))
	}
	return out
}

// ------------------------------------------------------------ GitHub advisories

type ghAdvisory struct {
	CVEID       string `json:"cve_id"`
	GHSAID      string `json:"ghsa_id"`
	Summary     string `json:"summary"`
	Severity    string `json:"severity"`
	HTMLURL     string `json:"html_url"`
	Description string `json:"description"`
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	Vulnerabilities []struct {
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		PatchedVersions        string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

// RepoAdvisories lists GitHub Security Advisories published by the app's own
// repository. This is the signal OSV misses for native apps that are not
// published to a package registry.
func RepoAdvisories(ctx context.Context, app AppInfo, version string, cfg *config.Config, cache Cache) []Advisory {
	if app.Repo == "" {
		return nil
	}
	key := fmt.Sprintf("ghsa:%s:%s", app.Repo, version)
	c := newClient(cfg)
	body, ok := c.cachedGet(ctx, "https://api.github.com/repos/"+app.Repo+"/security-advisories",
		key, cache, cfg.VulnCacheTTL(), c.githubHeaders(), map[string]string{"per_page": "50"})
	if !ok {
		return nil
	}
	var advisories []ghAdvisory
	if err := json.Unmarshal(body, &advisories); err != nil {
		return nil
	}

	out := []Advisory{}
	for _, adv := range advisories {
		var applies *bool
		fixed := ""
		patched := false
		for _, vuln := range adv.Vulnerabilities {
			if isPatched, known := versionIsPatched(version, vuln.PatchedVersions); known && isPatched {
				patched = true
				break
			}
			hit, known := versionInRange(version, vuln.VulnerableVersionRange)
			switch {
			case known && hit:
				yes := true
				applies = &yes
				if vuln.PatchedVersions != "" {
					fixed = vuln.PatchedVersions
				}
			case known && !hit:
				if applies == nil {
					no := false
					applies = &no
				}
			}
		}
		if patched || (applies != nil && !*applies) {
			continue
		}
		id := adv.CVEID
		if id == "" {
			id = adv.GHSAID
		}
		var aliases []string
		for _, identifier := range adv.Identifiers {
			if identifier.Value != "" {
				aliases = append(aliases, identifier.Value)
			}
		}
		severity := strings.ToUpper(orDefault(adv.Severity, "unknown"))
		detail := adv.Description
		if len(detail) > 400 {
			detail = detail[:400]
		}
		out = append(out, Advisory{
			ID:       id,
			Aliases:  aliases,
			Summary:  adv.Summary,
			Severity: severity,
			Fixed:    fixed,
			Applies:  applies,
			URL:      adv.HTMLURL,
			Detail:   detail,
		})
	}
	return out
}

// ------------------------------------------------------------ OSV advisories

// osvResponse is the api.osv.dev query result, and the shape stored in the
// cache: what we read back must match what we wrote.
type osvResponse struct {
	Vulns []osvEntry `json:"vulns"`
}

// OSVAdvisories queries api.osv.dev for a package version.
func OSVAdvisories(ctx context.Context, app AppInfo, version string, cfg *config.Config, cache Cache) []Advisory {
	if app.OSV == "" {
		return nil
	}
	key := fmt.Sprintf("osv:%s:%s", app.OSV, version)
	c := newClient(cfg)

	if cache != nil {
		if raw, ok := cache.CacheGet(key, cfg.VulnCacheTTL()); ok {
			var cached osvResponse
			if json.Unmarshal(raw, &cached) == nil {
				return buildAdvisories(cached.Vulns, version, cfg)
			}
		}
	}

	payload, _ := json.Marshal(map[string]any{
		"version": version,
		"package": map[string]string{"name": app.OSV},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/query",
		strings.NewReader(string(payload)))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "netwatch/0.1")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var response osvResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil
	}
	if cache != nil && json.Valid(body) {
		cache.CacheSet(key, json.RawMessage(body))
	}
	return buildAdvisories(response.Vulns, version, cfg)
}

func buildAdvisories(vulns []osvEntry, version string, cfg *config.Config) []Advisory {
	out := []Advisory{}
	for _, v := range vulns {
		hit, known := affectedBy(v, version, cfg.Vulns.IncludeDistroAdvisories)
		if known && !hit {
			continue
		}
		var applies *bool
		if known {
			yes := hit
			applies = &yes
		}
		url := ""
		for _, ref := range v.References {
			if ref.URL != "" {
				url = ref.URL
				break
			}
		}
		if url == "" {
			url = "https://osv.dev/vulnerability/" + v.ID
		}
		summary := v.Summary
		if summary == "" {
			summary = v.Details
			if len(summary) > 300 {
				summary = summary[:300]
			}
		}
		out = append(out, Advisory{
			ID:       v.ID,
			Aliases:  v.Aliases,
			Summary:  summary,
			Severity: severityOf(v),
			Fixed:    fixedVersionOf(v),
			Applies:  applies,
			URL:      url,
		})
	}
	return out
}

// ------------------------------------------------------------------- the driver

// Enrich turns fingerprinted services into CVE, advisory and update findings.
// Services without a version, or apps that are not catalogued, are skipped:
// guessing at versions would produce findings nobody can act on.
func Enrich(
	ctx context.Context,
	services []model.Service,
	cfg *config.Config,
	cache Cache,
	progress Progress,
) []model.Finding {
	type group struct {
		app        AppInfo
		version    string
		serviceKey string
	}
	var groups []group
	seen := map[string]bool{}
	for _, svc := range services {
		info, ok := Lookup(svc.App)
		if !ok || svc.Version == "" {
			continue
		}
		key := info.Name + "|" + svc.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		groups = append(groups, group{app: info, version: svc.Version, serviceKey: svc.Key()})
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].app.Name != groups[j].app.Name {
			return groups[i].app.Name < groups[j].app.Name
		}
		return groups[i].version < groups[j].version
	})

	findings := []model.Finding{}
	deduped := map[string]bool{}

	for i, g := range groups {
		if ctx.Err() != nil {
			break
		}
		if progress != nil {
			progress(90, fmt.Sprintf("Vulnerabilities %d/%d: %s", i+1, len(groups), g.app.Name))
		}

		if cfg.Vulns.GitHub {
			if release, ok := LatestRelease(ctx, g.app, cfg, cache); ok && release.Version != "" &&
				isNewer(release.Version, g.version) {
				findings = append(findings, model.Finding{
					Kind:       "update",
					App:        g.app.Name,
					Ref:        fmt.Sprintf("%s->%s", g.version, release.Version),
					Title:      fmt.Sprintf("Update available: %s %s -> %s", g.app.Name, g.version, release.Version),
					Severity:   "info",
					ServiceKey: g.serviceKey,
					Installed:  g.version,
					Fixed:      release.Version,
					URL:        release.URL,
					Detail:     securityNotes(release.Body),
				})
			}
		}

		if cfg.Vulns.OSV {
			for _, adv := range OSVAdvisories(ctx, g.app, g.version, cfg, cache) {
				ref := adv.ID
				for _, alias := range adv.Aliases {
					if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
						ref = alias
						break
					}
				}
				if deduped[g.app.Name+"|"+ref] {
					continue
				}
				deduped[g.app.Name+"|"+ref] = true
				title := adv.Summary
				if title == "" {
					title = fmt.Sprintf("%s affects %s", ref, g.app.Name)
				}
				kind := "advisory"
				detail := ""
				if adv.Applies != nil && *adv.Applies {
					kind = "cve"
				} else if adv.Applies == nil {
					detail = "Applicability could not be established from OSV ranges; review."
				}
				findings = append(findings, model.Finding{
					Kind:       kind,
					App:        g.app.Name,
					Ref:        ref,
					Title:      title,
					Severity:   adv.Severity,
					ServiceKey: g.serviceKey,
					Installed:  g.version,
					Fixed:      adv.Fixed,
					URL:        adv.URL,
					Detail:     detail,
				})
			}
		}

		if cfg.Vulns.GitHub {
			for _, adv := range RepoAdvisories(ctx, g.app, g.version, cfg, cache) {
				if deduped[g.app.Name+"|"+adv.ID] {
					continue
				}
				deduped[g.app.Name+"|"+adv.ID] = true
				title := adv.Summary
				if title == "" {
					title = fmt.Sprintf("%s affects %s", adv.ID, g.app.Name)
				}
				kind := "advisory"
				if adv.Applies != nil && *adv.Applies {
					kind = "cve"
				}
				fixed := strings.TrimLeft(adv.Fixed, "<>=~^ ")
				findings = append(findings, model.Finding{
					Kind:       kind,
					App:        g.app.Name,
					Ref:        adv.ID,
					Title:      title,
					Severity:   adv.Severity,
					ServiceKey: g.serviceKey,
					Installed:  g.version,
					Fixed:      fixed,
					URL:        adv.URL,
					Detail:     adv.Detail,
				})
			}
		}
	}

	if progress != nil {
		progress(96, "Vulnerability checks complete")
	}
	return findings
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
