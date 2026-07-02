package auth

import (
	"net"
	"net/http"
	"strings"
)

// TrustedProxies determines which CIDRs are allowed to supply forwarded
// client IP/scheme information via X-Forwarded-For / X-Forwarded-Proto.
// Empty by default: forwarded headers are ignored entirely and the raw TCP
// peer address is used, so this is opt-in and never silently trusts a
// spoofable header.
type TrustedProxies struct {
	nets []*net.IPNet
}

// NewTrustedProxies parses a list of CIDR strings.
func NewTrustedProxies(cidrs []string) (*TrustedProxies, error) {
	tp := &TrustedProxies{}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		tp.nets = append(tp.nets, n)
	}
	return tp, nil
}

func (tp *TrustedProxies) contains(ip net.IP) bool {
	for _, n := range tp.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP resolves the real client IP for an HTTP request: the raw TCP peer
// address, or — only if that peer is in TrustedProxies — the rightmost
// non-trusted hop in X-Forwarded-For.
func (tp *TrustedProxies) ClientIP(r *http.Request) net.IP {
	peerIP := peerIPOf(r.RemoteAddr)
	if peerIP == nil || tp == nil || !tp.contains(peerIP) {
		return peerIP
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peerIP
	}
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			continue
		}
		if !tp.contains(ip) {
			return ip
		}
	}
	return peerIP
}

// IsForwardedHTTPS reports whether the effective client-facing scheme is
// HTTPS, trusting X-Forwarded-Proto only when the immediate peer is a
// trusted proxy (Section 9b reverse-proxy-TLS-termination mode).
func (tp *TrustedProxies) IsForwardedHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peerIP := peerIPOf(r.RemoteAddr)
	if peerIP == nil || tp == nil || !tp.contains(peerIP) {
		return false
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func peerIPOf(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}
