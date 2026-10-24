# netwatch

A Go terminal app for answering three questions about a home network:

1. **What is actually reachable from the internet?**
2. **What is each open port running, and which version?**
3. **Which of those apps have CVEs or a newer release, and what changed since last time?**

It combines LAN discovery, app fingerprinting, router/Tailscale inspection, an external vantage point, OSV advisories, and GitHub releases into one scan history.

```
┌ netwatch ────────────────────────────────────────────────────────────┐
│ netwatch  exposure · vuln tracker   [1 exposures] 2 services  …      │
│ public IP 188.x.x.x  hosts 16  services 49  public 2  findings 0     │
├──────────────────────────────────────────────────────────────────────┤
│ Target                     Kind      Verified  App        Detail     │
│ http://127.0.0.1:8781      funnel    yes       pricedaddy Funnel: …  │
│ 188.x.x.x:51413            external  yes       Transmission TCP con…  │
├──────────────────────────────────────────────────────────────────────┤
│ q quit · s scan · S full scan · tab/←→ switch · e export md          │
│ Scan finished in 28s  (s rescan)                                     │
└──────────────────────────────────────────────────────────────────────┘
```

Five tabs — **exposures, services, findings, history, report** — with scan progress, a progress bar, and cancel via `esc`.

## Why an external vantage is required

A port being open on `192.168.1.x` says nothing about whether the router forwards it. A device can also be public through **Tailscale Funnel** without any router rule at all. netwatch therefore separates:

| Label | Meaning |
|---|---|
| `PUBLIC` | Confirmed from outside, or an UPnP/Funnel config explicitly exposes it |
| `tailnet` | Reachable through Tailscale, not the public internet |
| `lan` | Local network only |
| `?` | Not enough evidence |

Set `remote_probe_ssh` to any SSH host **outside your network** (a VPS) and netwatch runs a parallel `/dev/tcp` probe there in one SSH call. This is the reliable mode and the only way to see router forwards when UPnP is silent (e.g. UniFi).

Without it, netwatch falls back to [check-host.net](https://check-host.net), which is free but rate-limited, and marks unverified things honestly rather than guessing.

## Install

```bash
go build -o netwatch ./cmd/netwatch   # no CGO needed; SQLite is pure Go
./netwatch init                        # writes ~/.config/netwatch/config.toml
./netwatch                             # TUI
```

Requires Go 1.26+ (the `go` directive pulls the right toolchain automatically). On Linux it uses `ping` and `ip neigh`; no root is needed. `CGO_ENABLED=0` builds work — the SQLite driver is `modernc.org/sqlite`.

## Configure

```toml
[network]
cidr = "auto"
full_scan = false          # all 65535 TCP ports
concurrency = 300
connect_timeout = 0.7

[exposure]
external_verify = true
upnp = true
tailscale = true
shodan_internetdb = true
remote_probe_ssh = "znc"   # any SSH alias/host with internet access
max_verify_ports = 40

[vulns]
osv = true
github = true
github_token = ""          # optional; lifts GitHub rate limits
include_distro_advisories = false

[storage]
db = "~/.local/share/netwatch/netwatch.db"
reports = "~/.local/share/netwatch/reports"

[overrides]
# Apps behind an auth proxy hide their version. Supply it manually:
"192.168.1.196:8989" = "Sonarr 4.0.12"
```

The config file and database are shared with earlier versions, so history carries over.

## Commands

```bash
netwatch                     # TUI (default)
netwatch scan                # headless scan + summary
netwatch scan --json         # machine-readable
netwatch scan --full         # 1–65535 on every host (slow)
netwatch scan --no-external  # LAN/fingerprint only
netwatch scan --no-vulns     # skip OSV/GitHub checks
netwatch scan --fail-on-public    # exit 2 if anything is public
netwatch scan --fail-on-findings  # exit 3 if findings exist
netwatch report -o report.md
netwatch findings
netwatch init
netwatch catalog             # known apps and version sources
```

TUI keys: `tab`/`1–5` switch tabs, `s` scan, `S` full scan, `esc` cancel scan, `r` reload, `e`/`E` export Markdown/JSON, `d` prune history, `j`/`k` scroll, `q` quit.

For cron:

```bash
0 7 * * *  /usr/local/bin/netwatch scan --quiet --fail-on-findings
```

The database keeps every run, so reports always include a diff: new/closed services, new/resolved findings, and LAN→public reach changes.

## What gets checked

| Stage | Implementation |
|---|---|
| Hosts | Ping sweep, neighbour table, local prefix detection |
| Ports | Concurrent TCP connect scan (common ports by default) |
| Apps | HTTP title/headers, auth-redirect `app=` parameter, SSH/FTP banners, port catalogue |
| Versions | Jellyfin API, banners, `Server` headers; manual overrides |
| Exposure | UPnP IGD table, Tailscale `serve`/`funnel` config + peer DNS, Shodan InternetDB, external TCP probe |
| CVEs | [OSV](https://osv.dev) by upstream package/version |
| Updates | GitHub latest release + security keywords in release notes |

### Vulnerability data is deliberately conservative

Upstream-only OSV ecosystems are used (PyPI, npm, Go, crates.io, NuGet, …). Distro advisories (Debian/Ubuntu/Alpine/RHEL/SUSE) are ignored by default because a `9.6p1` SSH banner says nothing about which distro patch level is installed. Set `include_distro_advisories = true` if you want that noise.

Native apps that OSV has no upstream data for still get **update** findings from GitHub, with security-relevant release notes. That is usually the actionable signal: “4.1.3 → 4.1.4, hardened torrent-add RPC”.

## Layout

```
cmd/netwatch/        CLI entry point (subcommands, flags, exit codes)
internal/model/      shared data structures (Host, Service, Exposure, Finding, Diff)
internal/config/     TOML config, defaults, CIDR detection, overrides
internal/discovery/  ping sweep, neighbours, concurrent port scan, reverse DNS
internal/fingerprint/ probes and app/version signatures
internal/exposure/   UPnP, Tailscale, Shodan, SSH/check-host verification
internal/vulndb/     OSV + GitHub releases, semver comparison, app catalogue
internal/store/      SQLite history, diff, first_seen, TTL cache
internal/report/     Markdown / JSON rendering
internal/scan/       scan pipeline (Engine.Scan with progress callbacks)
internal/tui/        bubbletea dashboard (tabs, tables, viewport, progress)
```

All network operations are bounded by a `context.Context` and run concurrently. State lives in SQLite; caches are TTL-based so repeated scans are fast.

## Limitations

- Router forward tables are only visible if UPnP is enabled. UniFi Dream Routers do not answer SSDP in the default configuration; use `remote_probe_ssh`.
- Tailscale Funnel on *other* nodes can only be confirmed from outside; without a remote probe it is marked unverified.
- Apps behind Umbrel's auth proxy do not reveal versions. Use `[overrides]` or query the app's API from inside the container.
- check-host.net rate-limits aggressive scans. The tool caps itself at 20 ports and backs off on 429.
- This is an inventory and triage tool, not a pentest framework. It does not exploit anything.

## Tests

```bash
go test ./...
```
