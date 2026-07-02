package auth

import (
	"strings"
	"testing"
)

func TestParseDefaultGateway(t *testing.T) {
	// Real /proc/net/route excerpt for a host whose default gateway is
	// 192.168.1.1 via eth0, plus a non-default (directly connected) route
	// that must be ignored.
	const sample = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	0	00000000	0	0	0
eth0	0011A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`
	ip, err := parseDefaultGateway(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("parseDefaultGateway: %v", err)
	}
	if got, want := ip.String(), "192.168.1.1"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestParseDefaultGateway_DockerBridge(t *testing.T) {
	// Typical docker0 bridge gateway, 172.17.0.1.
	const sample = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	010011AC	0003	0	0	0	00000000	0	0	0
`
	ip, err := parseDefaultGateway(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("parseDefaultGateway: %v", err)
	}
	if got, want := ip.String(), "172.17.0.1"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestParseDefaultGateway_NoDefaultRoute(t *testing.T) {
	const sample = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	0011A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`
	if _, err := parseDefaultGateway(strings.NewReader(sample)); err == nil {
		t.Fatal("expected error when no default route is present")
	}
}
