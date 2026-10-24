// Package fingerprint identifies what is behind an open port.
package fingerprint

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/roks0n/netwatch/internal/config"
	"github.com/roks0n/netwatch/internal/model"
)

// Progress reports percent-complete and a human-readable stage.
type Progress func(pct int, msg string)

// nonHTTP are ports whose wire protocol is not HTTP(S); probing them wastes time.
var nonHTTP = map[int]bool{
	21: true, 22: true, 23: true, 25: true, 53: true, 110: true, 139: true,
	143: true, 445: true, 587: true, 993: true, 995: true, 3702: true,
	5432: true, 5480: true, 6379: true, 6380: true, 6381: true, 8333: true,
	9735: true, 50001: true, 51413: true, 57621: true, 61613: true, 9100: true,
}

var tlsFirst = map[int]bool{443: true, 8443: true, 8843: true, 9443: true}

// bannerPorts are probed with a plain read to catch a cleartext greeting.
var bannerPorts = map[int]bool{21: true, 22: true, 25: true, 110: true, 143: true}

// portApp is the fallback guess when banners and titles say nothing.
var portApp = map[int]string{
	22: "OpenSSH", 80: "HTTP", 443: "HTTPS", 2000: "Umbrel app proxy",
	2375: "Docker API", 2376: "Docker API", 3000: "Grafana", 3001: "Uptime Kuma",
	5055: "Jellyseerr", 5056: "Jellyseerr", 5432: "PostgreSQL", 5480: "PostgreSQL",
	6379: "Redis", 6381: "Valkey", 6767: "Bazarr", 7878: "Radarr", 8000: "HTTP app",
	8080: "HTTP app", 8096: "Jellyfin", 8123: "Home Assistant", 8240: "Tailscale",
	8385: "Uptime Kuma", 8989: "Sonarr", 9000: "Portainer", 9091: "Transmission",
	9696: "Prowlarr", 32400: "Plex", 51413: "Transmission peer",
}

type signature struct {
	app     string
	needles []string
}

// signatures match a page <title> (lowercased) to a canonical app name.
var signatures = []signature{
	{"Jellyfin", []string{"jellyfin"}},
	{"Sonarr", []string{"sonarr"}},
	{"Radarr", []string{"radarr"}},
	{"Prowlarr", []string{"prowlarr"}},
	{"Bazarr", []string{"bazarr"}},
	{"Jellyseerr", []string{"jellyseerr", "overseerr"}},
	{"Transmission", []string{"transmission"}},
	{"Uptime Kuma", []string{"uptime kuma", "uptime-kuma"}},
	{"Home Assistant", []string{"home assistant"}},
	{"Grafana", []string{"grafana"}},
	{"Portainer", []string{"portainer"}},
	{"Plex", []string{"plex"}},
	{"AdGuard Home", []string{"adguard"}},
	{"Umbrel", []string{"umbrel"}},
	{"UniFi OS", []string{"unifi"}},
	{"Tailscale", []string{"tailscale"}},
	{"OpenSSH", []string{"openssh"}},
	{"nginx", []string{"nginx"}},
	{"Apache", []string{"apache"}},
	{"FastAPI", []string{"fastapi"}},
	{"uvicorn", []string{"uvicorn"}},
}

var aliases = map[string]string{
	"jellyseerr": "Jellyseerr", "overseerr": "Jellyseerr", "jellyfin": "Jellyfin",
	"sonarr": "Sonarr", "radarr": "Radarr", "prowlarr": "Prowlarr", "bazarr": "Bazarr",
	"transmission": "Transmission", "tailscale": "Tailscale", "umbrel": "Umbrel",
	"uptime-kuma": "Uptime Kuma", "uptime kuma": "Uptime Kuma", "openssh": "OpenSSH",
	"nginx": "nginx", "apache": "Apache", "unifi": "UniFi OS",
}

var (
	versionRE       = regexp.MustCompile(`(?i)["']?(?:version|appVersion|serverVersion)["']?\s*[:=]\s*["']([0-9][0-9A-Za-z.\-+]{1,30})["']`)
	titleRE         = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	serverVersionRE = regexp.MustCompile(`([A-Za-z][\w.\-]*)/([0-9][\w.\-+]*)`)
	sshRE           = regexp.MustCompile(`SSH-[\d.]+-(\S+?)(?:_([\w.\-+]+))?(?:\s|$)`)
	controlRE       = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f]`)
	whitespaceRE    = regexp.MustCompile(`\s+`)
)

// Probe is what one HTTP request taught us about a port.
type Probe struct {
	Status   int
	Scheme   string
	Server   string
	Title    string
	Location string
	Body     string
}

func cleanText(s string) string {
	return strings.TrimSpace(controlRE.ReplaceAllString(s, ""))
}

func extractTitle(html string) string {
	m := titleRE.FindStringSubmatch(html)
	if m == nil {
		return ""
	}
	return truncate(cleanText(whitespaceRE.ReplaceAllString(m[1], " ")), 120)
}

// isErrorTitle rejects generic error pages so they never become an app name.
func isErrorTitle(title string) bool {
	low := strings.ToLower(strings.TrimSpace(title))
	for _, prefix := range []string{
		"http status", "error", "400", "401", "403", "404", "405", "500", "501",
		"502", "503", "504", "bad request", "unauthorized", "forbidden", "not found",
	} {
		if strings.HasPrefix(low, prefix) {
			return true
		}
	}
	return false
}

func serverVersion(server string) (product, version string) {
	if server == "" {
		return "", ""
	}
	if m := serverVersionRE.FindStringSubmatch(server); m != nil {
		return m[1], m[2]
	}
	return strings.Fields(server)[0], ""
}

func canonical(name string) string {
	if mapped, ok := aliases[strings.ToLower(name)]; ok {
		return mapped
	}
	if name == "" {
		return name
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

func matchSignature(title string) string {
	low := strings.ToLower(title)
	for _, sig := range signatures {
		for _, needle := range sig.needles {
			if strings.Contains(low, needle) {
				return sig.app
			}
		}
	}
	return ""
}

func redirectApp(location string) string {
	if location == "" {
		return ""
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return parsed.Query().Get("app")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func banner(ctx context.Context, ip string, port int, timeout time.Duration) string {
	dialer := net.Dialer{Timeout: timeout}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialer.DialContext(cctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	line, _, _ := strings.Cut(string(buf[:n]), "\n")
	return cleanText(line)
}

func httpProbe(ctx context.Context, client *http.Client, ip string, port int, scheme string) (*Probe, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		scheme+"://"+net.JoinHostPort(ip, strconv.Itoa(port))+"/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 40000)
	body, _ := io.ReadAll(limited)
	return &Probe{
		Status:   resp.StatusCode,
		Scheme:   scheme,
		Server:   resp.Header.Get("Server"),
		Title:    extractTitle(string(body)),
		Location: resp.Header.Get("Location"),
		Body:     string(body),
	}, nil
}

func jellyfinVersion(ctx context.Context, client *http.Client, ip string, port int, scheme string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		scheme+"://"+net.JoinHostPort(ip, strconv.Itoa(port))+"/System/Info/Public", nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var info struct {
		Version string `json:"Version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&info); err != nil {
		return ""
	}
	return info.Version
}

// Service fills in app, version, confidence and evidence for one open port.
func Service(ctx context.Context, svc *model.Service, cfg *config.Config, client *http.Client) {
	ip, port := svc.IP, svc.Port
	svc.Evidence = []string{}
	add := func(format string, args ...any) {
		svc.Evidence = append(svc.Evidence, strings.TrimSpace(fmt.Sprintf(format, args...)))
	}

	if bannerPorts[port] {
		if text := banner(ctx, ip, port, cfg.ConnectTimeout()+1500*time.Millisecond); text != "" {
			add("banner: %s", truncate(text, 100))
			if m := sshRE.FindStringSubmatch(text); m != nil {
				if strings.Contains(strings.ToLower(m[1]), "openssh") {
					svc.App = "OpenSSH"
				} else {
					svc.App = m[1]
				}
				svc.Version = m[2]
				svc.Product = svc.App
				svc.Confidence = "high"
			}
		}
	}

	var probe *Probe
	if !nonHTTP[port] {
		schemes := []string{"http", "https"}
		if tlsFirst[port] {
			schemes = []string{"https", "http"}
		}
		for _, scheme := range schemes {
			cctx, cancel := context.WithTimeout(ctx, cfg.HTTPTimeout())
			p, err := httpProbe(cctx, client, ip, port, scheme)
			cancel()
			if err == nil {
				probe = p
				break
			}
		}
	}

	if probe != nil {
		if probe.Server != "" {
			add("server: %s", probe.Server)
		}
		add("HTTP %d (%s)", probe.Status, probe.Scheme)
		if probe.Title != "" {
			add("title: %s", probe.Title)
		}
	}

	switch {
	// 1. An Umbrel-style auth redirect names the app outright.
	case probe != nil && redirectApp(probe.Location) != "":
		app := redirectApp(probe.Location)
		svc.App = canonical(app)
		svc.Confidence = "high"
		add("redirect app=%s", app)

	// 2. The page title matches a known product.
	case probe != nil && matchSignature(probe.Title) != "":
		svc.App = matchSignature(probe.Title)
		svc.Confidence = "high"

	// 3. Fall back to the port catalogue, then the Server header.
	case svc.App == "" || svc.App == "unknown":
		guess := portApp[port]
		product, _ := serverVersion(probeServer(probe))
		switch {
		case (guess == "HTTP" || guess == "HTTPS" || guess == "HTTP app") && product != "":
			svc.App = canonical(product)
			svc.Confidence = "medium"
		case guess != "":
			svc.App = guess
			svc.Confidence = "medium"
		case probe != nil && probe.Title != "" && !isErrorTitle(probe.Title):
			svc.App = truncate(probe.Title, 60)
			svc.Confidence = "low"
		}
	}

	if probe != nil {
		product, version := serverVersion(probe.Server)
		if product != "" && (svc.App == "" || svc.App == "unknown") {
			svc.App = canonical(product)
			svc.Confidence = "low"
		}
		generic := svc.App == "unknown" || svc.App == "HTTP" || svc.App == "HTTPS" ||
			svc.App == "nginx" || svc.App == "Apache" || svc.App == "uvicorn"
		if version != "" && svc.Version == "" &&
			(generic || strings.EqualFold(product, svc.App)) {
			svc.Version = version
		}
		if svc.Version == "" && probe.Body != "" {
			if m := versionRE.FindStringSubmatch(probe.Body); m != nil {
				svc.Version = m[1]
			}
		}
		if svc.App == "Jellyfin" || port == 8096 {
			scheme := probe.Scheme
			if scheme == "" {
				scheme = "http"
			}
			cctx, cancel := context.WithTimeout(ctx, cfg.HTTPTimeout())
			v := jellyfinVersion(cctx, client, ip, port, scheme)
			cancel()
			if v != "" {
				svc.Version = v
				add("api version: %s", v)
			}
		}
	}

	// A manual override always wins: some apps hide their version behind a proxy.
	if app, version := cfg.OverrideFor(ip, port); app != "" {
		svc.App, svc.Version = app, version
		svc.Confidence = "override"
		add("manual override")
	}

	svc.Product = svc.App
	if svc.App == "" {
		svc.App = "unknown"
	}
}

func probeServer(p *Probe) string {
	if p == nil {
		return ""
	}
	return p.Server
}

// FingerprintAll identifies every service on every host, concurrently.
func FingerprintAll(
	ctx context.Context,
	hosts *[]model.Host,
	cfg *config.Config,
	base, span int,
	progress Progress,
) {
	if hosts == nil {
		return
	}
	client := &http.Client{
		Timeout: cfg.HTTPTimeout(),
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConnsPerHost: 4,
			DisableKeepAlives:   false,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var services []*model.Service
	for i := range *hosts {
		for j := range (*hosts)[i].Services {
			services = append(services, &(*hosts)[i].Services[j])
		}
	}

	total := len(services)
	sem := make(chan struct{}, 24)
	var wg sync.WaitGroup
	var done int
	var mu sync.Mutex
	for _, svc := range services {
		wg.Add(1)
		sem <- struct{}{}
		go func(s *model.Service) {
			defer wg.Done()
			defer func() { <-sem }()
			Service(ctx, s, cfg, client)
			mu.Lock()
			done++
			current := done
			mu.Unlock()
			if progress != nil && current%5 == 0 {
				progress(base+span*current/max(1, total), "Fingerprint "+strconv.Itoa(current)+"/"+strconv.Itoa(total))
			}
		}(svc)
	}
	wg.Wait()
	if progress != nil {
		progress(base+span, "Fingerprinting complete")
	}
}
