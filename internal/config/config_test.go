package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadAppliesFileAndDefaults(t *testing.T) {
	path := writeFile(t, "config.toml", `
[network]
cidr = "10.0.0.0/24"
ports = [22, 80, 443]

[exposure]
tailscale = false
remote_probe_ssh = "znc"

[overrides]
"192.168.1.196:51413" = "Transmission 4.1.3"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Network.CIDR != "10.0.0.0/24" {
		t.Errorf("cidr = %q", cfg.Network.CIDR)
	}
	if cfg.Exposure.RemoteProbeSSH != "znc" {
		t.Errorf("probe = %q", cfg.Exposure.RemoteProbeSSH)
	}
	if got := cfg.ScanPorts(); len(got) != 3 || got[0] != 22 || got[2] != 443 {
		t.Errorf("ScanPorts = %v, want [22 80 443]", got)
	}
	if cfg.Network.Concurrency <= 0 {
		t.Errorf("concurrency default missing: %d", cfg.Network.Concurrency)
	}
	if cfg.Path != path {
		t.Errorf("Path = %q, want %q", cfg.Path, path)
	}
}

func TestLoadMissingFileFallsBackToDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatalf("missing file must not be an error: %v", err)
	}
	if got := cfg.ScanPorts(); len(got) != len(DefaultPorts) {
		t.Errorf("expected default port list, got %d ports", len(got))
	}
}

func TestLoadGitHubTokenFromEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "gh-test-token")
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Vulns.GitHubToken != "gh-test-token" {
		t.Errorf("GitHubToken = %q, want token from environment", cfg.Vulns.GitHubToken)
	}
}

func TestOverrideFor(t *testing.T) {
	cfg := Default()
	cfg.Overrides = map[string]string{
		"192.168.1.196:51413": "Transmission 4.1.3",
		"127.0.0.1:8781":      " pricedaddy ",
	}

	if app, version := cfg.OverrideFor("192.168.1.196", 51413); app != "Transmission" || version != "4.1.3" {
		t.Errorf("OverrideFor = %q,%q want Transmission,4.1.3", app, version)
	}
	if app, version := cfg.OverrideFor("127.0.0.1", 8781); app != "pricedaddy" || version != "" {
		t.Errorf("OverrideFor = %q,%q want pricedaddy,''", app, version)
	}
	if app, version := cfg.OverrideFor("10.0.0.1", 22); app != "" || version != "" {
		t.Errorf("unmatched override leaked: %q,%q", app, version)
	}
}

func TestScanPortsFullScan(t *testing.T) {
	cfg := Default()
	cfg.Network.FullScan = true
	if got := cfg.ScanPorts(); len(got) != 65535 || got[0] != 1 || got[65534] != 65535 {
		t.Errorf("full scan ports wrong: %d entries", len(got))
	}
}

func TestExpandTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	if got := Expand("~/x"); got != filepath.Join(home, "x") {
		t.Errorf("Expand(~/x) = %q", got)
	}
	if got := Expand("/abs/path"); got != "/abs/path" {
		t.Errorf("absolute path changed: %q", got)
	}
}
