package auth

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// DefaultGatewayIP returns this process's IPv4 default gateway, as seen in
// its own routing table (/proc/net/route on Linux). In containerized
// deployments (Docker, Kubernetes) this is typically the bridge/overlay
// network gateway that a host-level reverse proxy or load balancer
// connects through -- which is why it's trusted by default for
// X-Forwarded-* headers (DECLARATIVEAUTH_NETWORK_TRUST_DEFAULT_GATEWAY),
// without requiring an operator to hunt down and hardcode a Docker-assigned
// address that can differ per host/restart.
func DefaultGatewayIP() (net.IP, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("reading routing table: %w", err)
	}
	defer f.Close()
	return parseDefaultGateway(f)
}

// parseDefaultGateway reads /proc/net/route's format (a header line, then
// one line per route: Iface Destination Gateway Flags ... with Destination
// and Gateway as little-endian hex-encoded IPv4 addresses) and returns the
// gateway of the route whose destination is 0.0.0.0, i.e. the default route.
func parseDefaultGateway(r io.Reader) (net.IP, error) {
	scanner := bufio.NewScanner(r)
	scanner.Scan() // header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[1] != "00000000" { // Destination column: only the default route
			continue
		}
		gw, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(gw))
		if ip.Equal(net.IPv4zero) {
			continue // default route with no gateway (directly connected) -- not useful here
		}
		return ip, nil
	}
	return nil, fmt.Errorf("no default route found")
}
