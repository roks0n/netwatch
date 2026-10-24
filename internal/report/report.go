// Package report renders a scan as Markdown or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/roks0n/netwatch/internal/model"
)

var severityOrder = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5,
}

var controlRE = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f]`)

func clean(v string) string { return controlRE.ReplaceAllString(v, "") }

func reachBadge(r model.Reach) string {
	switch r {
	case model.ReachPublic:
		return "**PUBLIC**"
	case model.ReachTailnet:
		return "tailnet"
	case model.ReachLAN:
		return "lan"
	default:
		return "?"
	}
}

func table(headers []string, rows [][]string) string {
	if len(rows) == 0 {
		return "_none_\n"
	}
	var b strings.Builder
	b.WriteString("| " + strings.Join(headers, " | ") + " |\n")
	b.WriteString("|" + strings.Repeat("---|", len(headers)) + "\n")
	for _, row := range rows {
		cells := make([]string, len(row))
		for i, cell := range row {
			cells[i] = strings.ReplaceAll(clean(cell), "|", "\\|")
		}
		b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// SortFindings orders findings the way a human triages them: worst first.
func SortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if severityOrder[strings.ToLower(a.Severity)] != severityOrder[strings.ToLower(b.Severity)] {
			return severityOrder[strings.ToLower(a.Severity)] < severityOrder[strings.ToLower(b.Severity)]
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.App < b.App
	})
}

// ToMarkdown renders the whole scan as a shareable report.
func ToMarkdown(result *model.ScanResult) string {
	findings := append([]model.Finding(nil), result.Findings...)
	SortFindings(findings)
	services := result.Services()
	public := result.PublicExposures()

	lines := []string{
		"# netwatch report",
		"",
		"- Generated: " + orFallback(result.Finished, result.Started),
		"- Scan started: " + result.Started,
		"- Public IP: " + orFallback(result.PublicIP, "unknown"),
		fmt.Sprintf("- Hosts: %d  |  Services: %d  |  Public exposures: %d  |  Findings: %d",
			len(result.Hosts), len(services), len(public), len(findings)),
		"",
		"## Public exposure",
		"",
		table([]string{"Target", "Kind", "App", "Verified", "Detail"},
			mapRows(public, func(e model.Exposure) []string {
				verified := "advisory"
				if e.Verified {
					verified = "yes"
				}
				return []string{e.Target, e.Kind, e.App, verified, e.Detail}
			})),
		"",
		"## Tailnet / private exposure",
		"",
	}

	var private []model.Exposure
	for _, e := range result.Exposures {
		if !e.Public {
			private = append(private, e)
		}
	}
	lines = append(lines,
		table([]string{"Target", "Kind", "Detail"},
			mapRows(private, func(e model.Exposure) []string {
				return []string{e.Target, e.Kind, e.Detail}
			})),
		"",
		"## Findings",
		"",
		"### Updates",
		"",
		table([]string{"App", "Installed", "Latest", "Detail"},
			mapRows(findings, func(f model.Finding) []string {
				return []string{f.App, f.Installed, f.Fixed, f.Title}
			}, func(f model.Finding) bool { return f.Kind == "update" })),
		"",
		"### Vulnerabilities / advisories",
		"",
		table([]string{"Severity", "Kind", "App", "Ref", "Installed", "Fixed", "Title"},
			mapRows(findings, func(f model.Finding) []string {
				return []string{f.Severity, f.Kind, f.App, f.Ref, f.Installed, f.Fixed, f.Title}
			}, func(f model.Finding) bool { return f.Kind != "update" })),
		"",
		"## Changes since previous scan",
		"",
	)

	diff := result.Diff
	if diff == nil {
		lines = append(lines, "_No comparison recorded for this scan._")
	} else if diff.Baseline {
		lines = append(lines, "_First scan: baseline recorded._")
	} else {
		lines = append(lines, "Compared with: "+orFallback(diff.PreviousStarted, "?"))
		lines = append(lines, "")
		lines = append(lines,
			fmt.Sprintf("- New services: %d", len(diff.NewServices)),
			fmt.Sprintf("- Disappeared services: %d", len(diff.GoneServices)),
			fmt.Sprintf("- New findings: %d", len(diff.NewFindings)),
			fmt.Sprintf("- Resolved findings: %d", len(diff.ResolvedFindings)),
			fmt.Sprintf("- Reach changes: %d", len(diff.ReachChanges)),
		)
		if len(diff.NewServices) > 0 {
			quoted := make([]string, len(diff.NewServices))
			for i, k := range diff.NewServices {
				quoted[i] = "`" + k + "`"
			}
			lines = append(lines, "", "New: "+strings.Join(quoted, ", "))
		}
		if len(diff.ReachChanges) > 0 {
			lines = append(lines, "", "Reach changes:")
			for _, ch := range diff.ReachChanges {
				lines = append(lines, fmt.Sprintf("- `%s`: %s -> %s", ch.Key, ch.From, ch.To))
			}
		}
	}

	sorted := append([]model.Service(nil), services...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].IP != sorted[j].IP {
			return sorted[i].IP < sorted[j].IP
		}
		return sorted[i].Port < sorted[j].Port
	})
	lines = append(lines, "", "## All services", "")
	lines = append(lines, table([]string{"Host", "Port", "App", "Version", "Reach", "Evidence"},
		mapRows(sorted, func(s model.Service) []string {
			evidence := strings.Join(s.Evidence, "; ")
			if len(evidence) > 120 {
				evidence = evidence[:120]
			}
			return []string{s.IP, fmt.Sprint(s.Port), s.App, s.Version, reachBadge(s.Reach), evidence}
		})))

	if len(result.Errors) > 0 {
		lines = append(lines, "", "## Errors", "")
		for _, e := range result.Errors {
			lines = append(lines, "- "+e)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// ToJSON renders the scan for scripts, including a flattened service list.
func ToJSON(result *model.ScanResult) ([]byte, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	payload["services"] = result.Services()

	var out strings.Builder
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(out.String(), "\n")), nil
}

// Write saves a report and returns the path written.
func Write(result *model.ScanResult, directory, format, path string) (string, error) {
	target := path
	if target == "" {
		stamp := time.Now().Format("20060102-150405")
		ext := "md"
		if format == "json" {
			ext = "json"
		}
		target = filepath.Join(directory, fmt.Sprintf("netwatch-%s.%s", stamp, ext))
	}
	if dir := filepath.Dir(target); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}

	var data []byte
	var err error
	if format == "json" || strings.HasSuffix(target, ".json") {
		data, err = ToJSON(result)
	} else {
		data = []byte(ToMarkdown(result))
	}
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return "", err
	}
	return target, nil
}

func orFallback(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// mapRows builds table rows, optionally filtering the source slice.
func mapRows[T any](items []T, row func(T) []string, keep ...func(T) bool) [][]string {
	out := [][]string{}
	for _, item := range items {
		skip := false
		for _, predicate := range keep {
			if !predicate(item) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, row(item))
		}
	}
	return out
}

// SortStrings is exported for the TUI's convenience.
func SortStrings(in []string) []string {
	out := append([]string(nil), in...)
	slices.Sort(out)
	return out
}
