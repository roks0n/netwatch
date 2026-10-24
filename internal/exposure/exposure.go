// Package exposure answers "can the internet reach this?" for every service.
//
// Nothing here is guessed into the "public" bucket: a port is only labelled
// public when something outside the network actually connected to it, or when
// the router's own UPnP table says it is forwarded.
package exposure

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/roks0n/netwatch/internal/config"
	"github.com/roks0n/netwatch/internal/model"
)

// Progress reports percent-complete and a human-readable stage.
type Progress func(pct int, msg string)

// Cache lets expensive external lookups survive between scans. Store implements it.
type Cache interface {
	CacheGet(key string, ttl time.Duration) (json.RawMessage, bool)
	CacheSet(key string, value any)
}

var publicIPURLs = []string{
	"https://ifconfig.me/ip",
	"https://api.ipify.org",
	"https://icanhazip.com",
}

var tailnet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// tlsSkipVerify is used only for liveness probes against self-signed services.
var tlsSkipVerify = tls.Config{InsecureSkipVerify: true}

func newClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// PublicIP asks a few echo services for this network's egress address.
func PublicIP(ctx context.Context) string {
	client := newClient(8 * time.Second)
	for _, endpoint := range publicIPURLs {
		cctx, cancel := context.WithTimeout(ctx, 9*time.Second)
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "netwatch/0.1")
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		cancel()

		ip := strings.TrimSpace(strings.SplitN(strings.TrimSpace(string(body)), "\n", 2)[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// ------------------------------------------------------------------ UPnP / SSDP

// PortMapping is one entry of the router's port-forwarding table.
type PortMapping struct {
	ExternalPort   int    `json:"external_port"`
	InternalPort   int    `json:"internal_port"`
	Protocol       string `json:"protocol"`
	InternalClient string `json:"internal_client"`
	Description    string `json:"description"`
	Enabled        bool   `json:"enabled"`
}

// Key is the stable identity of a mapping across scans.
func (m PortMapping) Key() string {
	return fmt.Sprintf("%d/%s->%s:%d", m.ExternalPort, m.Protocol, m.InternalClient, m.InternalPort)
}

var locationRE = regexp.MustCompile(`(?i)LOCATION:\s*(\S+)`)

// ssdpLocations multicasts an SSDP M-SEARCH for an IGD and collects LOCATIONs.
func ssdpLocations(timeout time.Duration) []string {
	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"

	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	targets := []string{"239.255.255.250", "192.168.1.1"}
	for _, target := range targets {
		_, _ = conn.WriteTo([]byte(msg), &net.UDPAddr{IP: net.ParseIP(target), Port: 1900})
	}

	var locations []string
	buf := make([]byte, 65507)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		if m := locationRE.FindSubmatch(buf[:n]); m != nil {
			loc := string(m[1])
			if !slices.Contains(locations, loc) {
				locations = append(locations, loc)
			}
		}
	}
	return locations
}

// xmlNode is a namespace-agnostic element, so vendor XML dialects still parse.
type xmlNode struct {
	Name     string
	Text     string
	Children []*xmlNode
}

func parseXML(data string) (*xmlNode, error) {
	dec := xml.NewDecoder(strings.NewReader(data))
	dec.Strict = false
	root := &xmlNode{Name: "root"}
	stack := []*xmlNode{root}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if len(stack) == 1 {
				return root, nil
			}
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			node := &xmlNode{Name: t.Name.Local}
			parent := stack[len(stack)-1]
			parent.Children = append(parent.Children, node)
			stack = append(stack, node)
		case xml.CharData:
			parent := stack[len(stack)-1]
			parent.Text += string(t)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return root, nil
}

func (n *xmlNode) find(name string) *xmlNode {
	for _, c := range n.Children {
		if strings.EqualFold(c.Name, name) {
			return c
		}
	}
	return nil
}

// findDeep walks the tree looking for the first element with this local name.
func (n *xmlNode) findDeep(name string) *xmlNode {
	for _, c := range n.Children {
		if strings.EqualFold(c.Name, name) {
			return c
		}
		if got := c.findDeep(name); got != nil {
			return got
		}
	}
	return nil
}

func (n *xmlNode) text(name string) string {
	if c := n.find(name); c != nil {
		return strings.TrimSpace(c.Text)
	}
	return ""
}

func (n *xmlNode) textDeep(name string) string {
	if c := n.findDeep(name); c != nil {
		return strings.TrimSpace(c.Text)
	}
	return ""
}

// firstWANService returns the serviceType and absolute controlURL of the
// WANIPConnection (or WANPPPConnection) service in a device description.
func firstWANService(body, base string) (svcType, controlURL string) {
	root, err := parseXML(body)
	if err != nil {
		return "", ""
	}
	for _, device := range root.findDeepSlice("serviceList") {
		for _, svc := range device.Children {
			if !strings.EqualFold(svc.Name, "service") {
				continue
			}
			st := svc.text("serviceType")
			cu := svc.text("controlURL")
			if st != "" && cu != "" &&
				(strings.Contains(st, "WANIPConnection") || strings.Contains(st, "WANPPPConnection")) {
				return st, joinURL(base, cu)
			}
		}
	}
	// Some routers nest services without a serviceList wrapper.
	var walk func(*xmlNode) bool
	walk = func(n *xmlNode) bool {
		if strings.EqualFold(n.Name, "service") {
			st := n.text("serviceType")
			cu := n.text("controlURL")
			if st != "" && cu != "" &&
				(strings.Contains(st, "WANIPConnection") || strings.Contains(st, "WANPPPConnection")) {
				svcType, controlURL = st, joinURL(base, cu)
				return true
			}
		}
		for _, c := range n.Children {
			if walk(c) {
				return true
			}
		}
		return false
	}
	walk(root)
	return svcType, controlURL
}

func (n *xmlNode) findDeepSlice(name string) []*xmlNode {
	var out []*xmlNode
	var walk func(*xmlNode)
	walk = func(cur *xmlNode) {
		if strings.EqualFold(cur.Name, name) {
			out = append(out, cur)
		}
		for _, c := range cur.Children {
			walk(c)
		}
	}
	walk(n)
	return out
}

func joinURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}

func soap(ctx context.Context, controlURL, svcType, action, args string) string {
	envelope := `<?xml version="1.0"?>` +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body><u:` + action + ` xmlns:u="` + svcType + `">` + args +
		`</u:` + action + `></s:Body></s:Envelope>`

	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, controlURL, strings.NewReader(envelope))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+svcType+`#`+action+`"`)

	resp, err := newClient(6 * time.Second).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(body)
}

// UPnPMappings reads the router's port-forwarding table over SSDP + SOAP.
func UPnPMappings(ctx context.Context) []PortMapping {
	var mappings []PortMapping
	client := newClient(6 * time.Second)

	for _, location := range ssdpLocations(3 * time.Second) {
		cctx, cancel := context.WithTimeout(ctx, 7*time.Second)
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, location, nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		cancel()

		svcType, control := firstWANService(string(body), location)
		if control == "" {
			continue
		}
		_ = soap(ctx, control, svcType, "GetExternalIPAddress", "")

		for idx := 0; idx < 64; idx++ {
			out := soap(ctx, control, svcType, "GetGenericPortMappingEntry",
				"<NewPortMappingIndex>"+strconv.Itoa(idx)+"</NewPortMappingIndex>")
			if out == "" {
				break
			}
			node, err := parseXML(out)
			if err != nil {
				break
			}
			ext := node.textDeep("NewExternalPort")
			if ext == "" {
				break
			}
			port, err := strconv.Atoi(ext)
			if err != nil {
				break
			}
			internal, _ := strconv.Atoi(node.textDeep("NewInternalPort"))
			proto := strings.ToUpper(orDefault(node.textDeep("NewProtocol"), "TCP"))
			mappings = append(mappings, PortMapping{
				ExternalPort:   port,
				InternalPort:   internal,
				Protocol:       proto,
				InternalClient: node.textDeep("NewInternalClient"),
				Description:    node.textDeep("NewPortMappingDescription"),
				Enabled:        orDefault(node.textDeep("NewEnabled"), "1") == "1",
			})
		}
	}
	return mappings
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// ------------------------------------------------------------------- Tailscale

type serveStatus struct {
	Web map[string]struct {
		Handlers map[string]struct {
			Proxy string `json:"Proxy"`
			Text  string `json:"Text"`
		} `json:"Handlers"`
	} `json:"Web"`
	AllowFunnel map[string]bool `json:"AllowFunnel"`
}

type tsStatus struct {
	Self struct {
		DNSName  string `json:"DNSName"`
		HostName string `json:"HostName"`
	} `json:"Self"`
	Peer map[string]struct {
		DNSName  string `json:"DNSName"`
		HostName string `json:"HostName"`
	} `json:"Peer"`
}

func runJSON(ctx context.Context, args ...string) ([]byte, bool) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if len(args) == 0 {
		return nil, false
	}
	out, err := exec.CommandContext(cctx, args[0], args[1:]...).Output()
	if err != nil {
		return nil, false
	}
	return out, true
}

func serveState(ctx context.Context) (*serveStatus, bool) {
	out, ok := runJSON(ctx, "tailscale", "serve", "status", "--json")
	if !ok {
		return nil, false
	}
	var s serveStatus
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, false
	}
	return &s, true
}

// TailscaleTargetPorts lists ports that local serve/funnel handlers proxy to,
// so the scanner fingerprints them even when nothing else points at them.
func TailscaleTargetPorts(ctx context.Context) map[int]bool {
	ports := map[int]bool{}
	s, ok := serveState(ctx)
	if !ok {
		return ports
	}
	for _, web := range s.Web {
		for _, h := range web.Handlers {
			if p := targetPort(h.Proxy); p > 0 {
				ports[p] = true
			}
		}
	}
	return ports
}

// isPublicAddr rejects loopback, RFC1918 and tailnet addresses.
func isPublicAddr(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	return !addr.IsPrivate() && !addr.IsLoopback() && !tailnet.Contains(addr)
}

// resolveA asks Cloudflare's DNS-over-HTTPS for a name's A records.
func resolveA(ctx context.Context, client *http.Client, name string) []string {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	endpoint := "https://cloudflare-dns.com/dns-query?name=" + url.QueryEscape(name) + "&type=A"
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var payload struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return nil
	}
	var addrs []string
	for _, a := range payload.Answer {
		if a.Type == 1 {
			addrs = append(addrs, a.Data)
		}
	}
	return addrs
}

// RemoteOpenPorts probes ports from an SSH host you control outside the network.
// One SSH round trip, parallel /dev/tcp probes on the far side.
func RemoteOpenPorts(ctx context.Context, sshHost, ip string, ports []int, timeout time.Duration) (map[int]bool, bool) {
	if len(ports) == 0 {
		return map[int]bool{}, true
	}
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(p)
	}
	script := "for p in " + strings.Join(strs, " ") + "; do " +
		"(timeout " + strconv.Itoa(int(timeout.Seconds())) +
		` bash -c "</dev/tcp/` + ip + `/$p" 2>/dev/null && echo $p) & ` +
		"done; wait"

	cctx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", sshHost, script)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, false
	}
	open := map[int]bool{}
	for _, field := range strings.Fields(string(out)) {
		if p, err := strconv.Atoi(field); err == nil {
			open[p] = true
		}
	}
	result := make(map[int]bool, len(ports))
	for _, p := range ports {
		result[p] = open[p]
	}
	return result, true
}

// RemoteHTTPStatus fetches https://name/ from the external probe host.
func RemoteHTTPStatus(ctx context.Context, sshHost, name string, timeout time.Duration) (int, bool) {
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 10
	}
	script := "curl -k -s -o /dev/null -w '%{http_code}' --max-time " + strconv.Itoa(secs) +
		" 'https://" + name + "/' 2>/dev/null || true"

	cctx, cancel := context.WithTimeout(ctx, timeout+15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", sshHost, script)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return 0, false
	}
	text := strings.TrimSpace(string(out))
	code, err := strconv.Atoi(text)
	if err != nil {
		return 0, false
	}
	return code, true
}

// CheckHostHTTP asks check-host.net to fetch https://name/ from outside.
// The free tier is rate limited, so this is only the fallback vantage.
func CheckHostHTTP(ctx context.Context, name string) (public bool, verified bool) {
	client := newClient(20 * time.Second)
	get := func(endpoint string, params url.Values) (map[string]json.RawMessage, bool) {
		u := endpoint
		if len(params) > 0 {
			u += "?" + params.Encode()
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, false
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, false
		}
		return payload, true
	}

	payload, ok := get("https://check-host.net/check-http", url.Values{
		"host":      {"https://" + name + "/"},
		"max_nodes": {"2"},
	})
	if !ok {
		return false, false
	}
	var rid string
	if raw, found := payload["request_id"]; found {
		_ = json.Unmarshal(raw, &rid)
	}
	if rid == "" {
		return false, false
	}

	for attempt := 0; attempt < 5; attempt++ {
		select {
		case <-ctx.Done():
			return false, false
		case <-time.After(4 * time.Second):
		}
		data, ok := get("https://check-host.net/check-result/"+rid, nil)
		if !ok || len(data) == 0 {
			continue
		}
		pending := false
		for _, raw := range data {
			if string(raw) == "null" {
				pending = true
			}
		}
		if pending {
			continue
		}
		for _, raw := range data {
			var node []json.RawMessage
			if err := json.Unmarshal(raw, &node); err != nil || len(node) == 0 {
				continue
			}
			var first []any
			if err := json.Unmarshal(node[0], &first); err != nil || len(first) == 0 {
				continue
			}
			if code, ok := first[0].(float64); ok && int(code) > 0 {
				return true, true
			}
		}
		return false, true
	}
	return false, false
}

// TailscaleExposures reports every serve/funnel handler on this tailnet, and
// verifies from outside whether a peer's ts.net name is really being served.
func TailscaleExposures(ctx context.Context, cfg *config.Config) []model.Exposure {
	statusRaw, ok := runJSON(ctx, "tailscale", "status", "--json")
	if !ok {
		return nil
	}
	var status tsStatus
	if err := json.Unmarshal(statusRaw, &status); err != nil {
		return nil
	}

	out := []model.Exposure{}
	serve, _ := serveState(ctx)
	if serve != nil {
		keys := make([]string, 0, len(serve.Web))
		for key := range serve.Web {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			web := serve.Web[key]
			paths := make([]string, 0, len(web.Handlers))
			for path := range web.Handlers {
				paths = append(paths, path)
			}
			sort.Strings(paths)
			for _, path := range paths {
				h := web.Handlers[path]
				target := h.Proxy
				if target == "" {
					target = h.Text
				}
				if target == "" {
					target = "?"
				}
				public := serve.AllowFunnel[key]
				kind := "serve"
				if public {
					kind = "funnel"
				}
				out = append(out, model.Exposure{
					Kind:     kind,
					Target:   target,
					Public:   public,
					Verified: true,
					Detail:   fmt.Sprintf("%s: https://%s%s -> %s", capitalized(kind), key, path, target),
				})
			}
		}
	}

	selfName := strings.TrimSuffix(status.Self.DNSName, ".")
	type peer struct{ hostName string }
	peers := map[string]peer{}
	for _, p := range status.Peer {
		// funnel-ingress-node peers have no DNS name and are not machines.
		if name := strings.TrimSuffix(p.DNSName, "."); name != "" {
			peers[name] = peer{hostName: p.HostName}
		}
	}
	if len(peers) == 0 {
		return out
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tlsSkipVerify},
	}
	names := make([]string, 0, len(peers))
	for name := range peers {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if name == selfName || !strings.HasSuffix(name, ".ts.net") {
			continue
		}
		addrs := resolveA(ctx, client, name)
		var publicAddr string
		for _, a := range addrs {
			if isPublicAddr(a) {
				publicAddr = a
				break
			}
		}
		if publicAddr == "" {
			continue
		}
		// Public DNS goes stale after Funnel is turned off, so confirm the
		// ingress really answers. With no outside vantage, stay honest.
		var (
			public, verified bool
			how              = "no external vantage configured"
		)
		if cfg.Exposure.RemoteProbeSSH != "" {
			if code, ok := RemoteHTTPStatus(ctx, cfg.Exposure.RemoteProbeSSH, name, cfg.RemoteProbeTimeout()); ok {
				public, verified = code > 0, true
				how = fmt.Sprintf("remote probe HTTP %d", code)
			}
		} else if cfg.Exposure.ExternalVerify {
			public, verified = CheckHostHTTP(ctx, name)
			how = "check-host.net"
		}
		served := "ingress not serving"
		if public {
			served = "funnel served"
		}
		kind := "serve"
		if public {
			kind = "funnel"
		}
		out = append(out, model.Exposure{
			Kind:     kind,
			Target:   "https://" + name,
			Public:   public,
			Verified: verified,
			Detail:   fmt.Sprintf("public DNS %s; %s (%s)", publicAddr, served, how),
			App:      peers[name].hostName,
		})
	}
	return out
}

func capitalized(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ------------------------------------------------------------ Shodan InternetDB

// ShodanPorts returns the ports Shodan has already seen on a public address.
// Free, keyless, and a useful cross-check on what the router claims.
func ShodanPorts(ctx context.Context, ip string) []int {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet,
		"https://internetdb.shodan.io/"+ip, nil)
	if err != nil {
		return nil
	}
	resp, err := newClient(8 * time.Second).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var payload struct {
		Ports []int `json:"ports"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return nil
	}
	out := make([]int, 0, len(payload.Ports))
	for _, p := range payload.Ports {
		if p > 0 && p <= 65535 {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// appPortsFirst orders candidates so the interesting services are verified
// before the boring infrastructure ports, in case we run out of budget.
func appPortsFirst(ports []int) []int {
	preferred := []int{
		51413, 32400, 8096, 8989, 9696, 7878, 6767, 5055, 5056, 9091,
		8240, 8385, 3000, 3001, 8000, 8080, 8443, 2000, 9000, 8123,
	}
	rank := func(p int) int {
		if i := slices.Index(preferred, p); i >= 0 {
			return i
		}
		return len(preferred)
	}
	out := append([]int(nil), ports...)
	sort.SliceStable(out, func(i, j int) bool {
		if rank(out[i]) != rank(out[j]) {
			return rank(out[i]) < rank(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// ---------------------------------------------------------------------- verify

const (
	statePublic  = "public"
	stateClosed  = "closed"
	stateUnknown = "unknown"
)

// VerifyPublicPorts returns port -> public|closed|unknown using an outside vantage.
func VerifyPublicPorts(
	ctx context.Context,
	ip string,
	ports []int,
	cfg *config.Config,
	cache Cache,
	progress Progress,
) map[int]string {
	results := map[int]string{}
	var todo []int
	for _, p := range ports {
		key := fmt.Sprintf("ext:%s:%d", ip, p)
		if cache != nil {
			if raw, ok := cache.CacheGet(key, cfg.ExposureCacheTTL()); ok {
				var state string
				if json.Unmarshal(raw, &state) == nil && state != "" {
					results[p] = state
					continue
				}
			}
		}
		todo = append(todo, p)
	}

	todo = appPortsFirst(todo)
	if len(todo) == 0 {
		return results
	}

	// Preferred: one SSH call to a host you control outside the network.
	if cfg.Exposure.RemoteProbeSSH != "" {
		probe := todo
		if len(probe) > 100 {
			probe = probe[:100]
		}
		remote, ok := RemoteOpenPorts(ctx, cfg.Exposure.RemoteProbeSSH, ip, probe, cfg.RemoteProbeTimeout())
		if ok {
			for port, isOpen := range remote {
				state := stateClosed
				if isOpen {
					state = statePublic
				}
				results[port] = state
				if cache != nil {
					cache.CacheSet(fmt.Sprintf("ext:%s:%d", ip, port), state)
				}
			}
			if progress != nil {
				progress(86, fmt.Sprintf("Verified %d ports from %s", len(remote), cfg.Exposure.RemoteProbeSSH))
			}
			return results
		}
		if progress != nil {
			progress(83, "Remote probe failed; falling back to check-host.net")
		}
	}

	limit := cfg.Exposure.MaxVerifyPorts
	if limit > 20 {
		limit = 20
	}
	if len(todo) > limit {
		todo = todo[:limit]
	}

	client := newClient(20 * time.Second)
	get := func(endpoint string, params url.Values) (map[string]json.RawMessage, bool) {
		u := endpoint
		if len(params) > 0 {
			u += "?" + params.Encode()
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, false
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, false
		}
		return payload, resp.StatusCode != http.StatusTooManyRequests
	}

	pending := map[string]int{}
	for i, port := range todo {
		payload, ok := get("https://check-host.net/check-tcp", url.Values{
			"host":      {fmt.Sprintf("%s:%d", ip, port)},
			"max_nodes": {"2"},
		})
		if !ok {
			break
		}
		var rid string
		if raw, found := payload["request_id"]; found {
			_ = json.Unmarshal(raw, &rid)
		}
		if rid != "" {
			pending[rid] = port
		}
		if progress != nil {
			progress(84, fmt.Sprintf("External verify %d/%d", i+1, len(todo)))
		}
		select {
		case <-ctx.Done():
			return results
		case <-time.After(cfg.CheckHostInterval()):
		}
	}

	for attempt := 0; attempt < 6 && len(pending) > 0; attempt++ {
		select {
		case <-ctx.Done():
			return results
		case <-time.After(5 * time.Second):
		}
		still := map[string]int{}
		for rid, port := range pending {
			data, ok := get("https://check-host.net/check-result/"+rid, nil)
			if !ok || len(data) == 0 {
				still[rid] = port
				continue
			}
			waiting := false
			for _, raw := range data {
				if string(raw) == "null" {
					waiting = true
				}
			}
			if waiting {
				still[rid] = port
				continue
			}
			open := false
			for _, raw := range data {
				var node []json.RawMessage
				if err := json.Unmarshal(raw, &node); err != nil || len(node) == 0 {
					continue
				}
				var item map[string]any
				if err := json.Unmarshal(node[0], &item); err == nil {
					if _, found := item["address"]; found {
						open = true
					}
				}
			}
			state := stateClosed
			if open {
				state = statePublic
			}
			results[port] = state
			if cache != nil {
				cache.CacheSet(fmt.Sprintf("ext:%s:%d", ip, port), state)
			}
		}
		pending = still
	}

	for _, port := range pending {
		if _, seen := results[port]; !seen {
			results[port] = stateUnknown
		}
	}
	return results
}

// -------------------------------------------------------------------- assemble

// targetPort pulls a port out of "http://127.0.0.1:8781", "8781" or ":8781".
func targetPort(target string) int {
	if target == "" {
		return 0
	}
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return 0
		}
		if u.Port() != "" {
			p, _ := strconv.Atoi(u.Port())
			return p
		}
		switch u.Scheme {
		case "https":
			return 443
		case "http":
			return 80
		}
		return 0
	}
	if p, err := strconv.Atoi(target); err == nil {
		return p
	}
	if _, rest, found := strings.Cut(target, ":"); found {
		if p, err := strconv.Atoi(rest); err == nil {
			return p
		}
	}
	return 0
}

// Detect gathers UPnP, Tailscale, Shodan and external-verification evidence,
// and pushes each service's Reach up to match what it found. Pass an empty
// publicIP to have it discovered here; the engine already knows it.
func Detect(
	ctx context.Context,
	cfg *config.Config,
	hosts *[]model.Host,
	cache Cache,
	progress Progress,
	publicIP string,
) []model.Exposure {
	if hosts == nil {
		return []model.Exposure{}
	}
	var services []*model.Service
	for i := range *hosts {
		for j := range (*hosts)[i].Services {
			services = append(services, &(*hosts)[i].Services[j])
		}
	}

	exposures := []model.Exposure{}
	if publicIP == "" {
		publicIP = PublicIP(ctx)
	}

	// 1. The router's own forwarding table.
	if cfg.Exposure.UPnP {
		for _, m := range UPnPMappings(ctx) {
			exposures = append(exposures, model.Exposure{
				Kind:   "upnp",
				Target: fmt.Sprintf("%s:%d/%s", orDefault(publicIP, "?"), m.ExternalPort, m.Protocol),
				Public: m.Enabled,
				Detail: strings.TrimSpace(fmt.Sprintf("UPnP %s %d -> %s:%d %s",
					m.Protocol, m.ExternalPort, m.InternalClient, m.InternalPort, m.Description)),
			})
			for _, svc := range services {
				if svc.IP == m.InternalClient && svc.Port == m.InternalPort {
					svc.Reach = model.ReachPublic
					svc.Exposures = append(svc.Exposures,
						fmt.Sprintf("UPnP %d->%d", m.ExternalPort, m.InternalPort))
				}
			}
		}
	}

	// 2. Tailscale serve/funnel, including handlers pointed at localhost.
	if cfg.Exposure.Tailscale {
		ts := TailscaleExposures(ctx, cfg)
		exposures = append(exposures, ts...)
		me := config.LocalIP()
		for _, e := range ts {
			port := targetPort(e.Target)
			if port == 0 {
				continue
			}
			for _, svc := range services {
				if svc.Port != port || (svc.IP != me && svc.IP != "127.0.0.1") {
					continue
				}
				if e.Public {
					svc.Reach = model.ReachPublic
				} else if svc.Reach != model.ReachPublic {
					svc.Reach = model.ReachTailnet
				}
				svc.Exposures = append(svc.Exposures, e.Detail)
			}
		}
	}

	// 3. What Shodan has already seen on the egress address.
	var shodanPorts []int
	if cfg.Exposure.ShodanInternetDB && publicIP != "" {
		shodanPorts = ShodanPorts(ctx, publicIP)
		for _, p := range shodanPorts {
			exposures = append(exposures, model.Exposure{
				Kind:   "shodan",
				Target: fmt.Sprintf("%s:%d", publicIP, p),
				Public: true,
				Detail: "Port observed by Shodan InternetDB",
			})
		}
	}

	// 4. Actually connect from outside and see what answers.
	if cfg.Exposure.ExternalVerify && publicIP != "" {
		seen := map[int]bool{}
		var candidates []int
		for _, svc := range services {
			if !seen[svc.Port] {
				seen[svc.Port] = true
				candidates = append(candidates, svc.Port)
			}
		}
		for _, p := range shodanPorts {
			if !seen[p] {
				seen[p] = true
				candidates = append(candidates, p)
			}
		}
		sort.Ints(candidates)
		if progress != nil {
			progress(82, fmt.Sprintf("Verifying %d ports externally", len(candidates)))
		}
		verified := VerifyPublicPorts(ctx, publicIP, candidates, cfg, cache, progress)

		var ports []int
		for port := range verified {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		for _, port := range ports {
			if verified[port] != statePublic {
				continue
			}
			detail := "TCP connect confirmed from external check-host nodes"
			if cfg.Exposure.RemoteProbeSSH != "" {
				detail = "TCP connect confirmed via SSH probe on " + cfg.Exposure.RemoteProbeSSH
			}
			exposures = append(exposures, model.Exposure{
				Kind:     "external",
				Target:   fmt.Sprintf("%s:%d", publicIP, port),
				Public:   true,
				Verified: true,
				Detail:   detail,
			})
			var matching []*model.Service
			for _, svc := range services {
				if svc.Port == port {
					matching = append(matching, svc)
				}
			}
			// Only blame one service when the forward is unambiguous.
			if len(matching) == 1 {
				matching[0].Reach = model.ReachPublic
				matching[0].Exposures = append(matching[0].Exposures,
					fmt.Sprintf("verified external :%d", port))
			} else {
				for _, svc := range matching {
					svc.Exposures = append(svc.Exposures,
						fmt.Sprintf("external :%d (target ambiguous)", port))
				}
			}
		}
	}

	if progress != nil {
		progress(88, "Exposure checks complete")
	}
	return exposures
}
