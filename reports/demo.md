# netwatch report

- Generated: 2026-10-24T21:03:33+00:00
- Scan started: 2026-10-24T21:03:11+00:00
- Public IP: 188.230.154.243
- Hosts: 15  |  Services: 53  |  Public exposures: 2  |  Findings: 2

## Public exposure

| Target | Kind | App | Verified | Detail |
|---|---|---|---|---|
| http://127.0.0.1:8781 | funnel |  | yes | Funnel: https://framework.tailaaeff3.ts.net:443/ -> http://127.0.0.1:8781 |
| 188.230.154.243:51413 | external |  | yes | TCP connect confirmed via SSH probe on znc |


## Tailnet / private exposure

| Target | Kind | Detail |
|---|---|---|
| https://umbrel.tailaaeff3.ts.net | serve | public DNS 185.40.234.198; ingress not serving (remote probe HTTP 0) |


## Findings

### Updates

| App | Installed | Latest | Detail |
|---|---|---|---|
| Jellyfin | 12.2.0 | 12.3 | Update available: Jellyfin 12.2.0 -> 12.3 |
| Transmission | 4.1.3 | 4.1.4 | Update available: Transmission 4.1.3 -> 4.1.4 |


### Vulnerabilities / advisories

_none_


## Changes since previous scan

Compared with: 2026-10-24T21:01:54+00:00

- New services: 0
- Disappeared services: 0
- New findings: 2
- Resolved findings: 0
- Reach changes: 0

## All services

| Host | Port | App | Version | Reach | Evidence |
|---|---|---|---|---|---|
| 127.0.0.1 | 8781 | pricedaddy |  | **PUBLIC** | HTTP 404 (http); manual override |
| 192.168.1.1 | 53 | unknown |  | lan |  |
| 192.168.1.1 | 80 | nginx |  | lan | server: nginx; HTTP 301 (http); title: 301 Moved Permanently |
| 192.168.1.1 | 443 | nginx |  | lan | server: nginx; HTTP 200 (https); title: UniFi OS |
| 192.168.1.1 | 8080 | HTTP app |  | lan | HTTP 400 (http); title: HTTP Status 400 – Bad Request |
| 192.168.1.1 | 8082 | unknown |  | lan | HTTP 404 (https) |
| 192.168.1.1 | 8381 | unknown |  | lan |  |
| 192.168.1.1 | 8443 | unknown |  | lan | HTTP 404 (https) |
| 192.168.1.1 | 8444 | nginx |  | lan | server: nginx; HTTP 400 (http); title: 400 The plain HTTP request was sent to HTTPS port |
| 192.168.1.1 | 8843 | unknown |  | lan | HTTP 400 (https); title: HTTP Status 400 – Bad Request |
| 192.168.1.1 | 8880 | unknown |  | lan | HTTP 400 (http); title: HTTP Status 400 – Bad Request |
| 192.168.1.1 | 8900 | unknown |  | lan | HTTP 400 (http) |
| 192.168.1.1 | 8901 | unknown |  | lan | HTTP 404 (http) |
| 192.168.1.1 | 9443 | unknown |  | lan | HTTP 404 (https) |
| 192.168.1.146 | 22 | OpenSSH | 9.6p1 | lan | banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20 |
| 192.168.1.146 | 8000 | Uvicorn |  | lan | server: uvicorn; HTTP 404 (http) |
| 192.168.1.16 | 5000 | AirTunes | 870.14.1 | lan | server: AirTunes/870.14.1; HTTP 403 (http) |
| 192.168.1.16 | 7000 | AirTunes | 870.14.1 | lan | server: AirTunes/870.14.1; HTTP 403 (http) |
| 192.168.1.16 | 57621 | unknown |  | lan |  |
| 192.168.1.165 | 22 | dropbear | 2025.89 | lan | banner: SSH-2.0-dropbear_2025.89 |
| 192.168.1.165 | 8080 | HTTP app |  | lan | HTTP 404 (https) |
| 192.168.1.165 | 8381 | unknown |  | lan |  |
| 192.168.1.196 | 22 | OpenSSH | 10.0p2 | lan | banner: SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4 |
| 192.168.1.196 | 80 | Umbrel |  | lan | HTTP 200 (http); title: Umbrel |
| 192.168.1.196 | 139 | unknown |  | lan |  |
| 192.168.1.196 | 443 | Umbrel |  | lan | HTTP 200 (https); title: Umbrel |
| 192.168.1.196 | 445 | unknown |  | lan |  |
| 192.168.1.196 | 2000 | Umbrel |  | lan | HTTP 200 (http); title: Umbrel |
| 192.168.1.196 | 5056 | Jellyseerr |  | lan | HTTP 302 (http); redirect app=jellyseerr |
| 192.168.1.196 | 6767 | Bazarr |  | lan | HTTP 302 (http); redirect app=bazarr |
| 192.168.1.196 | 7878 | Radarr |  | lan | HTTP 302 (http); redirect app=radarr |
| 192.168.1.196 | 8096 | Jellyfin | 12.2.0 | lan | server: Kestrel; HTTP 302 (http); api version: 12.2.0 |
| 192.168.1.196 | 8240 | Tailscale |  | lan | HTTP 200 (http); title: Tailscale |
| 192.168.1.196 | 8385 | Uptime Kuma |  | lan | HTTP 302 (http) |
| 192.168.1.196 | 8989 | Sonarr |  | lan | HTTP 302 (http); redirect app=sonarr |
| 192.168.1.196 | 9091 | Transmission |  | lan | HTTP 302 (http); redirect app=transmission |
| 192.168.1.196 | 9696 | Prowlarr |  | lan | HTTP 302 (http); redirect app=prowlarr |
| 192.168.1.196 | 51413 | Transmission | 4.1.3 | **PUBLIC** | manual override |
| 192.168.1.42 | 80 | HP |  | lan | server: HP HTTP Server; HP Smart Tank 580-590 series - 1F3Y2A; Serial Number: CN4638C3NS; Built:Fri Jul 24, 2026 01:58:2 |
| 192.168.1.42 | 443 | HP |  | lan | server: HP HTTP Server; HP Smart Tank 580-590 series - 1F3Y2A; Serial Number: CN4638C3NS; Built:Fri Jul 24, 2026 01:58:2 |
| 192.168.1.42 | 8080 | HP |  | lan | server: HP HTTP Server; HP Smart Tank 580-590 series - 1F3Y2A; Serial Number: CN4638C3NS; Built:Fri Jul 24, 2026 01:58:2 |
| 192.168.1.5 | 21 | unknown |  | lan |  |
| 192.168.1.5 | 22 | OpenSSH |  | lan |  |
| 192.168.1.5 | 23 | unknown |  | lan |  |
| 192.168.1.5 | 25 | unknown |  | lan |  |
| 192.168.1.5 | 53 | unknown |  | lan |  |
| 192.168.1.5 | 80 | HTTP |  | lan |  |
| 192.168.1.5 | 110 | unknown |  | lan |  |
| 192.168.1.5 | 445 | unknown |  | lan |  |
| 192.168.1.5 | 2222 | unknown |  | lan |  |
| 192.168.1.5 | 8000 | HTTP app |  | lan |  |
| 192.168.1.89 | 5480 | PostgreSQL |  | lan |  |
| 192.168.1.89 | 6381 | Valkey |  | lan |  |

