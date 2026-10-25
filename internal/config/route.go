package config

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var (
	routeDev = regexp.MustCompile(`\bdev\s+(\S+)`)
	routeSrc = regexp.MustCompile(`\bsrc\s+(\d+\.\d+\.\d+\.\d+)`)
	addrInet = regexp.MustCompile(`inet\s+(\d+\.\d+\.\d+\.\d+/\d+)`)
	routeVia = regexp.MustCompile(`\bvia\s+(\d+\.\d+\.\d+\.\d+)`)
	routeGw  = regexp.MustCompile(`\bgateway:\s*(\d+\.\d+\.\d+\.\d+)`)
)

// DefaultGateway returns the kernel's default-route gateway, or nil when
// there is none (directly connected) or the OS is unsupported. Detection is
// runtime so nothing about the network needs to be configured.
func DefaultGateway() net.IP {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var out []byte
	var err error
	if runtime.GOOS == "linux" {
		out, err = exec.CommandContext(ctx, "ip", "-4", "route", "get", "1.1.1.1").Output()
	} else {
		out, err = exec.CommandContext(ctx, "route", "-n", "get", "default").Output()
	}
	if err != nil {
		return nil
	}
	return parseGateway(string(out))
}

// parseGateway extracts the gateway from `ip route get` (Linux) or
// `route -n get` (macOS) output. Routes without a gateway return nil.
func parseGateway(out string) net.IP {
	for _, re := range []*regexp.Regexp{routeVia, routeGw} {
		if m := re.FindStringSubmatch(out); m != nil {
			return net.ParseIP(m[1])
		}
	}
	return nil
}

// detectCIDRFromIPRoute asks the kernel for the default route, then reads that
// interface's prefix. This beats scanning every interface, which on a machine
// with Tailscale and Docker would pick a tunnel address.
func detectCIDRFromIPRoute() (*net.IPNet, error) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("no route inspection on %s", runtime.GOOS)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return nil, err
	}
	route := string(out)
	dev, src := routeDev.FindStringSubmatch(route), routeSrc.FindStringSubmatch(route)
	if dev == nil || src == nil {
		return nil, fmt.Errorf("unexpected route output: %q", strings.TrimSpace(route))
	}

	out, err = exec.CommandContext(ctx, "ip", "-4", "addr", "show", "dev", dev[1]).Output()
	if err != nil {
		return nil, err
	}
	found := addrInet.FindStringSubmatch(string(out))
	if found == nil {
		return nil, fmt.Errorf("no inet address on %s", dev[1])
	}
	_, network, err := net.ParseCIDR(found[1])
	if err != nil {
		return nil, err
	}
	return network, nil
}
