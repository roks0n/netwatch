// Package model holds the data structures shared by every stage of a scan.
package model

import (
	"fmt"
	"time"
)

// Reach describes how far a service is exposed.
type Reach string

const (
	ReachLAN     Reach = "lan"
	ReachTailnet Reach = "tailnet"
	ReachPublic  Reach = "public"
	ReachUnknown Reach = "unknown"
)

// UTCNow returns the timestamp format used throughout the database.
func UTCNow() string { return time.Now().UTC().Format(time.RFC3339) }

// Service is one open port on one host, identified as well as we can.
type Service struct {
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	Proto      string   `json:"proto"`
	App        string   `json:"app"`
	Version    string   `json:"version,omitempty"`
	Product    string   `json:"product,omitempty"`
	Reach      Reach    `json:"reach"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence"`
	Exposures  []string `json:"exposures"`
}

// NewService builds a TCP service with empty optional fields set.
func NewService(ip string, port int) Service {
	return Service{
		IP:         ip,
		Port:       port,
		Proto:      "tcp",
		App:        "unknown",
		Reach:      ReachLAN,
		Confidence: "low",
		Evidence:   []string{},
		Exposures:  []string{},
	}
}

// Key identifies the service across scans.
func (s Service) Key() string { return fmt.Sprintf("%s:%d/%s", s.IP, s.Port, s.Proto) }

// Label is the shortest human-readable name, e.g. "Jellyfin 12.2.0".
func (s Service) Label() string {
	if s.Version == "" {
		return s.App
	}
	return s.App + " " + s.Version
}

// Host is an address that answered discovery, with the services found on it.
type Host struct {
	IP       string    `json:"ip"`
	MAC      string    `json:"mac,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	Services []Service `json:"services"`
}

// Label prefers the resolved name over the bare address.
func (h Host) Label() string {
	if h.Hostname != "" {
		return h.Hostname
	}
	return h.IP
}

// Exposure is a single piece of evidence that something is reachable.
type Exposure struct {
	Kind     string `json:"kind"` // upnp | external | funnel | serve | shodan
	Target   string `json:"target"`
	Public   bool   `json:"public"`
	Verified bool   `json:"verified"`
	Detail   string `json:"detail"`
	App      string `json:"app,omitempty"`
}

// Finding is a CVE, advisory, or available update for a fingerprinted app.
type Finding struct {
	Kind       string `json:"kind"` // cve | advisory | update
	App        string `json:"app"`
	Ref        string `json:"ref"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	ServiceKey string `json:"service_key,omitempty"`
	Installed  string `json:"installed,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	URL        string `json:"url,omitempty"`
	Detail     string `json:"detail,omitempty"`
	FirstSeen  string `json:"first_seen,omitempty"`
}

// Identity identifies a finding across scans, for dedupe and diffing.
func (f Finding) Identity() string { return f.Kind + "|" + f.App + "|" + f.Ref }

// FindingRef is the lightweight form used in a diff.
type FindingRef struct {
	Kind string `json:"kind"`
	App  string `json:"app"`
	Ref  string `json:"ref"`
}

// ReachChange records a service whose exposure changed between scans.
type ReachChange struct {
	Key  string `json:"key"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Diff compares a scan with the run before it.
type Diff struct {
	Baseline         bool          `json:"baseline"`
	PreviousStarted  string        `json:"previous_started,omitempty"`
	NewServices      []string      `json:"new_services"`
	GoneServices     []string      `json:"gone_services"`
	NewFindings      []FindingRef  `json:"new_findings"`
	ResolvedFindings []FindingRef  `json:"resolved_findings"`
	ReachChanges     []ReachChange `json:"reach_changes"`
}

// ScanResult is the output of one complete pipeline run.
type ScanResult struct {
	Started   string         `json:"started"`
	Finished  string         `json:"finished,omitempty"`
	PublicIP  string         `json:"public_ip,omitempty"`
	Hosts     []Host         `json:"hosts"`
	Exposures []Exposure     `json:"exposures"`
	Findings  []Finding      `json:"findings"`
	Errors    []string       `json:"errors"`
	Stats     map[string]any `json:"stats"`
	Diff      *Diff          `json:"diff,omitempty"`
}

// NewScanResult returns a result with all collections initialised so that
// JSON output never contains nulls where a list is expected.
func NewScanResult() *ScanResult {
	return &ScanResult{
		Hosts:     []Host{},
		Exposures: []Exposure{},
		Findings:  []Finding{},
		Errors:    []string{},
		Stats:     map[string]any{},
	}
}

// Services flattens the host list into a single slice of services.
func (r *ScanResult) Services() []Service {
	out := make([]Service, 0, len(r.Hosts))
	for _, h := range r.Hosts {
		out = append(out, h.Services...)
	}
	return out
}

// PublicServices returns services confirmed reachable from outside.
func (r *ScanResult) PublicServices() []Service {
	var out []Service
	for _, s := range r.Services() {
		if s.Reach == ReachPublic {
			out = append(out, s)
		}
	}
	return out
}

// PublicExposures returns only the exposures that mean "reachable from the internet".
func (r *ScanResult) PublicExposures() []Exposure {
	var out []Exposure
	for _, e := range r.Exposures {
		if e.Public {
			out = append(out, e)
		}
	}
	return out
}

// ServiceByKey indexes services by their stable Key.
func (r *ScanResult) ServiceByKey() map[string]Service {
	out := map[string]Service{}
	for _, s := range r.Services() {
		out[s.Key()] = s
	}
	return out
}

// CountReach reports how many services sit at each reach level.
func (r *ScanResult) CountReach() map[Reach]int {
	counts := map[Reach]int{}
	for _, s := range r.Services() {
		counts[s.Reach]++
	}
	return counts
}
