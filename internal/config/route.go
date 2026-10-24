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
)

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
