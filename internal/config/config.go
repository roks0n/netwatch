// Package config loads and defaults every knob the scanner exposes.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultPorts covers the services a home NAS or media server realistically runs.
// Full scans (1-65535) stay opt-in because they are an order of magnitude slower.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995,
	2000, 2222, 2375, 2376, 3000, 3001, 3002, 3003, 3004, 32400,
	4000, 5000, 5055, 5056, 5060, 5269, 5357, 5432, 5480, 5601,
	5672, 5900, 6379, 6380, 6381, 6767, 7000, 7878, 8000, 8008,
	8009, 8069, 8080, 8081, 8082, 8090, 8096, 8123, 8200, 8240,
	8333, 8381, 8385, 8443, 8444, 8843, 8880, 8900, 8901, 8989,
	9000, 9001, 9090, 9091, 9100, 9443, 9696, 9735, 10000,
	18080, 27017, 50001, 51413, 57621, 61613,
}

// DefaultConfig is written by `netwatch init`. Every value shown already
// matches the built-in default, so the file is only needed to change
// something — the tool is fully functional with no config at all.
const DefaultConfig = `# netwatch configuration — entirely optional.
# Delete this file, or any section, to fall back to defaults.

[network]
cidr = "auto"          # detected from the default route
full_scan = false      # scan all 65535 TCP ports (slow)
concurrency = 300
connect_timeout = 0.7
http_timeout = 6.0
# ports = [22, 80, 443]  # override the built-in list

[exposure]
external_verify = true       # confirm forwards from outside your network
upnp = true                  # read the router's UPnP port-mapping table
tailscale = true             # inspect serve/funnel state and tailnet peers
shodan_internetdb = true     # free, no key: ports Shodan has already seen
max_verify_ports = 40
check_host_interval = 1.5
# Optional, and the single most valuable knob: any SSH host outside your
# network (e.g. a VPS in ~/.ssh/config). One parallel /dev/tcp probe runs
# there, so verification has no API limits. Without it netwatch falls back
# to check-host.net, which is rate-limited.
remote_probe_ssh = ""
remote_probe_timeout = 4
cache_hours = 1

[vulns]
osv = true
github = true
cache_hours = 6
github_token = ""            # optional, lifts GitHub API rate limits
include_distro_advisories = false

# Storage defaults to $XDG_DATA_HOME/netwatch (or ~/.local/share/netwatch).
# [storage]
# db = "/some/where/netwatch.db"
# reports = "/some/where/reports"

# Manual app/version overrides for services that hide their version,
# e.g. behind a login proxy. Key is "ip:port", value is "App Version".
[overrides]
# "192.0.2.10:8989" = "Sonarr 4.0.12"
`

// Network groups discovery and port-scanning settings.
type Network struct {
	CIDR           string  `toml:"cidr"`
	Ports          []int   `toml:"ports"`
	FullScan       bool    `toml:"full_scan"`
	Concurrency    int     `toml:"concurrency"`
	ConnectTimeout float64 `toml:"connect_timeout"`
	HTTPTimeout    float64 `toml:"http_timeout"`
}

// Exposure groups everything that answers "can the internet reach this?".
type Exposure struct {
	ExternalVerify     bool    `toml:"external_verify"`
	UPnP               bool    `toml:"upnp"`
	Tailscale          bool    `toml:"tailscale"`
	ShodanInternetDB   bool    `toml:"shodan_internetdb"`
	MaxVerifyPorts     int     `toml:"max_verify_ports"`
	CheckHostInterval  float64 `toml:"check_host_interval"`
	RemoteProbeSSH     string  `toml:"remote_probe_ssh"`
	RemoteProbeTimeout float64 `toml:"remote_probe_timeout"`
	CacheHours         float64 `toml:"cache_hours"`
}

// Vulns groups advisory and release-tracking settings.
type Vulns struct {
	OSV                     bool    `toml:"osv"`
	GitHub                  bool    `toml:"github"`
	CacheHours              float64 `toml:"cache_hours"`
	GitHubToken             string  `toml:"github_token"`
	IncludeDistroAdvisories bool    `toml:"include_distro_advisories"`
}

// Storage holds on-disk locations.
type Storage struct {
	DB      string `toml:"db"`
	Reports string `toml:"reports"`
}

// Config is the whole configuration file.
type Config struct {
	Network   Network           `toml:"network"`
	Exposure  Exposure          `toml:"exposure"`
	Vulns     Vulns             `toml:"vulns"`
	Storage   Storage           `toml:"storage"`
	Overrides map[string]string `toml:"overrides"`

	// Path records where this config was loaded from ("" when defaults).
	Path string `toml:"-"`
}

// Default returns the built-in configuration. Nothing here requires a
// config file: every field is a sane default for a home network, and the
// scanner adapts to what is actually present (Tailscale, UPnP, SSH probe).
func Default() *Config {
	data := dataDir()
	return &Config{
		Network: Network{
			CIDR:           "auto",
			Ports:          append([]int(nil), DefaultPorts...),
			FullScan:       false,
			Concurrency:    300,
			ConnectTimeout: 0.7,
			HTTPTimeout:    6.0,
		},
		Exposure: Exposure{
			ExternalVerify:     true,
			UPnP:               true,
			Tailscale:          true,
			ShodanInternetDB:   true,
			MaxVerifyPorts:     40,
			CheckHostInterval:  1.5,
			RemoteProbeSSH:     "",
			RemoteProbeTimeout: 4,
			CacheHours:         1,
		},
		Vulns: Vulns{
			OSV:        true,
			GitHub:     true,
			CacheHours: 6,
		},
		Storage: Storage{
			DB:      filepath.Join(data, "netwatch", "netwatch.db"),
			Reports: filepath.Join(data, "netwatch", "reports"),
		},
		Overrides: map[string]string{},
	}
}

// dataDir follows the XDG spec: $XDG_DATA_HOME, falling back to
// ~/.local/share. State lives there so no config is needed on a fresh box.
func dataDir() string {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return dir
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share")
	}
	return ".netwatch"
}

// Load reads a TOML file, falling back to ~/.config/netwatch/config.toml and
// ./netwatch.toml. Missing files are not an error: defaults win.
func Load(path string) (*Config, error) {
	cfg := Default()

	candidates := []string{}
	if path != "" {
		candidates = append(candidates, path)
	} else {
		if dir, err := os.UserConfigDir(); err == nil {
			candidates = append(candidates, filepath.Join(dir, "netwatch", "config.toml"))
		}
		// Plain ~/.config stays a candidate even when XDG_CONFIG_HOME points
		// elsewhere, so configs written by earlier versions keep loading.
		if home, err := os.UserHomeDir(); err == nil {
			candidates = append(candidates, filepath.Join(home, ".config", "netwatch", "config.toml"))
		}
		candidates = append(candidates, "netwatch.toml")
	}

	for _, candidate := range candidates {
		expanded := Expand(candidate)
		data, err := os.ReadFile(expanded)
		if err != nil {
			continue
		}
		md, err := toml.Decode(string(data), cfg)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", expanded, err)
		}
		cfg.Path = expanded
		for _, unknown := range md.Undecoded() {
			fmt.Fprintf(os.Stderr, "netwatch: warning: unknown config key %q in %s\n",
				unknown.String(), expanded)
		}
		break
	}

	if cfg.Vulns.GitHubToken == "" {
		cfg.Vulns.GitHubToken = os.Getenv("GITHUB_TOKEN")
	}
	if cfg.Network.Concurrency <= 0 {
		cfg.Network.Concurrency = 300
	}
	if len(cfg.Network.Ports) == 0 && !cfg.Network.FullScan {
		cfg.Network.Ports = append([]int(nil), DefaultPorts...)
	}
	if cfg.Overrides == nil {
		cfg.Overrides = map[string]string{}
	}
	return cfg, nil
}

// WriteDefault creates the config file unless one already exists. The file
// is optional — netwatch runs with zero config — this is just a convenience
// that drops in a commented template of every knob.
func WriteDefault(path string) (string, error) {
	if path == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(dir, "netwatch", "config.toml")
	}
	target := Expand(path)
	if _, err := os.Stat(target); err == nil {
		return target, nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(target, []byte(DefaultConfig), 0o644); err != nil {
		return "", err
	}
	return target, nil
}

// Expand turns a leading ~ into the user's home directory.
func Expand(p string) string {
	if p == "" {
		return p
	}
	if p == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return p
	}
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// DBPath is the expanded SQLite location.
func (c *Config) DBPath() string { return Expand(c.Storage.DB) }

// ReportDir is the expanded report directory.
func (c *Config) ReportDir() string { return Expand(c.Storage.Reports) }

// ScanPorts returns the TCP ports to probe.
func (c *Config) ScanPorts() []int {
	if c.Network.FullScan {
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports
	}
	ports := append([]int(nil), c.Network.Ports...)
	sort.Ints(ports)
	return ports
}

// ConnectTimeout is the TCP dial budget per port.
func (c *Config) ConnectTimeout() time.Duration {
	return time.Duration(c.Network.ConnectTimeout * float64(time.Second))
}

// HTTPTimeout is the budget for a single HTTP probe.
func (c *Config) HTTPTimeout() time.Duration {
	return time.Duration(c.Network.HTTPTimeout * float64(time.Second))
}

// CheckHostInterval is the delay between check-host.net submissions.
func (c *Config) CheckHostInterval() time.Duration {
	return time.Duration(c.Exposure.CheckHostInterval * float64(time.Second))
}

// RemoteProbeTimeout is the per-port budget on the external SSH probe.
func (c *Config) RemoteProbeTimeout() time.Duration {
	return time.Duration(c.Exposure.RemoteProbeTimeout * float64(time.Second))
}

// ExposureCacheTTL is how long external verification results are reused.
func (c *Config) ExposureCacheTTL() time.Duration {
	return time.Duration(c.Exposure.CacheHours * float64(time.Hour))
}

// VulnCacheTTL is how long advisory and release data is reused.
func (c *Config) VulnCacheTTL() time.Duration {
	return time.Duration(c.Vulns.CacheHours * float64(time.Hour))
}

// OverrideFor returns a manually configured app name and version.
func (c *Config) OverrideFor(ip string, port int) (app, version string) {
	raw, ok := c.Overrides[fmt.Sprintf("%s:%d", ip, port)]
	if !ok {
		return "", ""
	}
	name, rest, found := strings.Cut(strings.TrimSpace(raw), " ")
	if !found {
		return name, ""
	}
	return name, strings.TrimSpace(rest)
}

// ResolvedCIDR returns the local subnet, either configured or detected.
func (c *Config) ResolvedCIDR() (*net.IPNet, error) {
	if c.Network.CIDR != "" && c.Network.CIDR != "auto" {
		_, network, err := net.ParseCIDR(c.Network.CIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid [network] cidr %q: %w", c.Network.CIDR, err)
		}
		return network, nil
	}
	return detectCIDR()
}

// MaxCIDRSize guards against pointing the scanner at the whole internet.
const MaxCIDRSize = 1 << 12 // /20

// detectCIDR finds the address and prefix of the interface carrying the
// default route, falling back to the source address of a UDP "route to 1.1.1.1".
func detectCIDR() (*net.IPNet, error) {
	if network, err := detectCIDRFromIPRoute(); err == nil {
		return network, nil
	}

	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return nil, fmt.Errorf("no usable local network: %w", err)
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("unexpected local address %s", conn.LocalAddr())
	}
	return &net.IPNet{IP: local.IP.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}, nil
}

// LocalIP returns the address this host uses to reach the internet.
func LocalIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// IPPort joins an address and port for display and dialing.
func IPPort(ip string, port int) string { return net.JoinHostPort(ip, strconv.Itoa(port)) }
