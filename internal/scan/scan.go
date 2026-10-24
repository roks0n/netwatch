// Package scan runs the whole pipeline: discover, port scan, fingerprint,
// verify exposure, track CVEs, persist, diff.
package scan

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/roks0n/netwatch/internal/config"
	"github.com/roks0n/netwatch/internal/discovery"
	"github.com/roks0n/netwatch/internal/exposure"
	"github.com/roks0n/netwatch/internal/fingerprint"
	"github.com/roks0n/netwatch/internal/model"
	"github.com/roks0n/netwatch/internal/store"
	"github.com/roks0n/netwatch/internal/vulndb"
)

// Progress reports percent-complete and a human-readable stage.
type Progress func(pct int, msg string)

// Engine binds a configuration to a database.
type Engine struct {
	Cfg   *config.Config
	Store *store.Store
}

// New builds an engine. The store may be nil, in which case nothing persists.
func New(cfg *config.Config, st *store.Store) *Engine {
	return &Engine{Cfg: cfg, Store: st}
}

// Options are the per-run overrides the CLI and TUI expose.
type Options struct {
	Full       bool
	NoExternal bool
	NoVulns    bool
	NoSave     bool
}

// runStats recomputes the counters shown in the summary and stored in the DB.
func runStats(result *model.ScanResult, started time.Time) map[string]any {
	services := result.Services()
	counts := result.CountReach()
	return map[string]any{
		"hosts":      len(result.Hosts),
		"services":   len(services),
		"public":     counts[model.ReachPublic],
		"tailnet":    counts[model.ReachTailnet],
		"findings":   len(result.Findings),
		"exposures":  len(result.PublicExposures()),
		"duration_s": round(time.Since(started).Seconds(), 1),
	}
}

func round(v, step float64) float64 {
	// Keep one decimal without pulling in math for a single call site.
	scaled := v * step
	rounded := float64(int64(scaled + 0.5*sign(scaled)))
	return rounded / step
}

func sign(v float64) float64 {
	if v < 0 {
		return -1
	}
	return 1
}

// Scan runs one complete pass. A stage that fails is recorded in Errors and
// the partial result is still returned, because a half-scan is far more useful
// than nothing when a router stops answering.
func (e *Engine) Scan(ctx context.Context, opts Options, progress Progress) *model.ScanResult {
	started := time.Now()
	result := model.NewScanResult()
	result.Started = model.UTCNow()

	cfg := e.Cfg
	ports := cfg.ScanPorts()
	if opts.Full && !cfg.Network.FullScan {
		ports = make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
	}

	report := func(pct int, msg string) {
		if progress != nil {
			progress(clamp(pct, 0, 100), msg)
		}
	}
	finish := func() *model.ScanResult {
		result.Finished = model.UTCNow()
		result.Stats = runStats(result, started)
		if e.Store != nil && !opts.NoSave {
			if runID, err := e.Store.Save(result); err == nil {
				result.Stats["run_id"] = runID
			}
		}
		return result
	}

	report(1, "Detecting public IP")
	result.PublicIP = exposure.PublicIP(ctx)

	report(4, "Discovering hosts")
	hosts, err := discovery.DiscoverHosts(ctx, cfg, progressAdapter(report))
	if err != nil {
		result.Errors = append(result.Errors, "discovery: "+err.Error())
		return finish()
	}
	result.Hosts = hosts

	report(11, "Scanning ports")
	discovery.ScanPorts(ctx, &result.Hosts, ports, cfg.Network.Concurrency,
		cfg.ConnectTimeout(), 11, 45, progressAdapter(report))

	// Services behind Tailscale serve/funnel often bind to loopback only, so
	// they never appear in the LAN sweep but are exactly what we care about.
	if cfg.Exposure.Tailscale {
		tsPorts := exposure.TailscaleTargetPorts(ctx)
		if len(tsPorts) > 0 {
			var list []int
			for p := range tsPorts {
				list = append(list, p)
			}
			locals := []model.Host{{IP: "127.0.0.1", Hostname: "localhost", Services: []model.Service{}}}
			discovery.ScanPorts(ctx, &locals, list, cfg.Network.Concurrency,
				400*time.Millisecond, 56, 2, progressAdapter(report))
			if len(locals[0].Services) > 0 {
				result.Hosts = append(result.Hosts, locals[0])
			}
		}
	}

	report(58, "Resolving names")
	discovery.ReverseDNS(ctx, &result.Hosts)

	report(59, "Fingerprinting services")
	fingerprint.FingerprintAll(ctx, &result.Hosts, cfg, 59, 18, progressAdapter(report))

	report(77, "Checking exposure")
	var cache exposure.Cache
	if e.Store != nil {
		cache = e.Store
	}
	result.Exposures = exposure.Detect(ctx, cfg, &result.Hosts, cache, progressAdapter(report), result.PublicIP)

	if !opts.NoVulns {
		report(89, "Checking vulnerabilities and updates")
		var vulnCache vulndb.Cache
		if e.Store != nil {
			vulnCache = e.Store
		}
		result.Findings = vulndb.Enrich(ctx, result.Services(), cfg, vulnCache, progressAdapter(report))
	}

	if e.Store != nil {
		if _, err := e.Store.Diff(result); err != nil {
			result.Errors = append(result.Errors, "diff: "+err.Error())
		}
	}
	report(100, "Done")
	return finish()
}

func progressAdapter(report Progress) func(int, string) {
	return func(pct int, msg string) { report(pct, msg) }
}

// Latest reloads the last persisted scan.
func (e *Engine) Latest() (*model.ScanResult, error) {
	if e.Store == nil {
		return nil, errors.New("no database configured")
	}
	return e.Store.Latest()
}

// History lists recent runs.
func (e *Engine) History(limit int) ([]store.RunSummary, error) {
	if e.Store == nil {
		return nil, errors.New("no database configured")
	}
	return e.Store.History(limit)
}

// Describe is a one-line summary used by the CLI header.
func Describe(result *model.ScanResult) string {
	services := result.Services()
	counts := result.CountReach()
	return fmt.Sprintf("%d hosts, %d services, %d public, %d findings",
		len(result.Hosts), len(services), counts[model.ReachPublic], len(result.Findings))
}

// FormatSeconds renders a duration for the CLI.
func FormatSeconds(seconds float64) string {
	return strconv.FormatFloat(seconds, 'f', 1, 64) + "s"
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
