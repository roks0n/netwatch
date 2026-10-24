// Package discovery finds live hosts and open TCP ports on the local network.
package discovery

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/roks0n/netwatch/internal/config"
	"github.com/roks0n/netwatch/internal/model"
)

// Progress reports percent-complete and a human-readable stage.
type Progress func(pct int, msg string)

var neighEntry = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+.*?lladdr\s+([0-9a-f:]{17})`)
var neighBare = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+`)

// PingSweep fills the neighbour table so that hosts which ignore TCP probes
// still show up. Failures are expected and ignored.
func PingSweep(ctx context.Context, cidr *net.IPNet, concurrency int) {
	if concurrency <= 0 {
		concurrency = 64
	}
	var base []string
	switch runtime.GOOS {
	case "linux":
		base = []string{"ping", "-c", "1", "-W", "1", "-n"}
	case "darwin":
		base = []string{"ping", "-c", "1", "-W", "1000", "-n"}
	default:
		return
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, ip := range HostAddrs(cidr) {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
			defer cancel()
			_ = exec.CommandContext(cctx, base[0], append(base[1:], addr)...).Run()
		}(ip.String())
	}
	wg.Wait()
}

// ReadNeighbours returns ip -> MAC for entries the kernel considers reachable.
func ReadNeighbours() map[string]string {
	out := map[string]string{}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var out2 []byte
	var err error
	if runtime.GOOS == "linux" {
		out2, err = exec.CommandContext(ctx, "ip", "neigh", "show").Output()
	} else {
		out2, err = exec.CommandContext(ctx, "arp", "-an").Output()
	}
	if err != nil {
		return out
	}

	for _, line := range strings.Split(string(out2), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "FAILED") || strings.Contains(line, "INCOMPLETE") {
			continue
		}
		if m := neighEntry.FindStringSubmatch(line); m != nil {
			out[m[1]] = m[2]
			continue
		}
		if m := neighBare.FindStringSubmatch(line); m != nil {
			if _, seen := out[m[1]]; !seen {
				out[m[1]] = ""
			}
		}
	}
	return out
}

// HostAddrs lists usable addresses in a network, excluding the network and
// broadcast addresses for ordinary prefixes.
func HostAddrs(n *net.IPNet) []net.IP {
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return nil
	}
	start := ipToUint(n.IP)
	count := uint32(1) << (32 - ones)
	var addrs []net.IP
	switch {
	case ones >= 31:
		for i := uint32(0); i < count; i++ {
			addrs = append(addrs, uintToIP(start+i))
		}
	default:
		for i := uint32(1); i < count-1; i++ {
			addrs = append(addrs, uintToIP(start+i))
		}
	}
	return addrs
}

func ipToUint(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

func uintToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
}

// DiscoverHosts pings the subnet and returns the hosts the kernel saw.
func DiscoverHosts(ctx context.Context, cfg *config.Config, progress Progress) ([]model.Host, error) {
	cidr, err := cfg.ResolvedCIDR()
	if err != nil {
		return nil, err
	}
	if size := len(HostAddrs(cidr)); size > config.MaxCIDRSize {
		return nil, fmt.Errorf("cidr %s has %d addresses; the limit is %d. Set a smaller [network] cidr",
			cidr.String(), size, config.MaxCIDRSize)
	}
	if progress != nil {
		progress(2, "Ping sweep "+cidr.String())
	}
	PingSweep(ctx, cidr, 64)

	neighbours := ReadNeighbours()
	inNetwork := func(ip string) bool {
		addr := net.ParseIP(ip)
		return addr != nil && cidr.Contains(addr)
	}

	hosts := make([]model.Host, 0, len(neighbours))
	for ip, mac := range neighbours {
		if !inNetwork(ip) {
			continue
		}
		hosts = append(hosts, model.Host{IP: ip, MAC: mac, Services: []model.Service{}})
	}
	if me := config.LocalIP(); me != "" && inNetwork(me) {
		known := false
		for _, h := range hosts {
			if h.IP == me {
				known = true
				break
			}
		}
		if !known {
			hosts = append(hosts, model.Host{IP: me, Services: []model.Service{}})
		}
	}

	sort.Slice(hosts, func(i, j int) bool {
		return ipToUint(net.ParseIP(hosts[i].IP)) < ipToUint(net.ParseIP(hosts[j].IP))
	})
	if progress != nil {
		progress(10, strconv.Itoa(len(hosts))+" live hosts")
	}
	return hosts, nil
}

// ScanPorts TCP-connects every port to every host, concurrently, and appends
// what answered. Progress is mapped onto [base, base+span].
func ScanPorts(
	ctx context.Context,
	hosts *[]model.Host,
	ports []int,
	concurrency int,
	timeout time.Duration,
	base, span int,
	progress Progress,
) {
	if hosts == nil || len(*hosts) == 0 || len(ports) == 0 {
		return
	}
	if concurrency <= 0 {
		concurrency = 300
	}

	type job struct {
		hostIdx int
		port    int
	}
	jobs := make(chan job, 1024)
	total := len(*hosts) * len(ports)
	var done int64
	var mu sync.Mutex
	dialer := net.Dialer{Timeout: timeout}

	worker := func() {
		for j := range jobs {
			if ctx.Err() != nil {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, timeout)
			conn, err := dialer.DialContext(cctx, "tcp", net.JoinHostPort((*hosts)[j.hostIdx].IP, strconv.Itoa(j.port)))
			cancel()
			if err == nil {
				_ = conn.Close()
				mu.Lock()
				(*hosts)[j.hostIdx].Services = append((*hosts)[j.hostIdx].Services,
					model.NewService((*hosts)[j.hostIdx].IP, j.port))
				mu.Unlock()
			}
			if n := atomic.AddInt64(&done, 1); progress != nil && total > 0 && n%int64(max(1, total/20)) == 0 {
				progress(base+span*int(n)/total, "Port scan "+strconv.FormatInt(n, 10)+"/"+strconv.Itoa(total))
			}
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); worker() }()
	}

feed:
	for h := range *hosts {
		for _, p := range ports {
			if ctx.Err() != nil {
				break feed
			}
			jobs <- job{hostIdx: h, port: p}
		}
	}
	close(jobs)
	wg.Wait()

	for i := range *hosts {
		sort.Slice((*hosts)[i].Services, func(a, b int) bool {
			return (*hosts)[i].Services[a].Port < (*hosts)[i].Services[b].Port
		})
	}
	if progress != nil {
		progress(base+span, "Port scan complete")
	}
}

// ReverseDNS fills in hostnames where a PTR record exists.
func ReverseDNS(ctx context.Context, hosts *[]model.Host) {
	if hosts == nil {
		return
	}
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for i := range *hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(cctx, (*hosts)[idx].IP)
			if err != nil || len(names) == 0 {
				return
			}
			name := strings.TrimSuffix(names[0], ".")
			if name == "" || strings.ReplaceAll(name, ".", "-") == strings.ReplaceAll((*hosts)[idx].IP, ".", "-") {
				return
			}
			(*hosts)[idx].Hostname = name
		}(i)
	}
	wg.Wait()
}
