package auth

import (
	"net/http"
	"testing"
)

func TestClientIP_UntrustedPeerIgnoresHeader(t *testing.T) {
	tp, _ := NewTrustedProxies(nil)
	r := &http.Request{RemoteAddr: "203.0.113.5:1234", Header: http.Header{}}
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	got := tp.ClientIP(r)
	if got.String() != "203.0.113.5" {
		t.Fatalf("expected raw peer IP, got %v", got)
	}
}

func TestClientIP_TrustedPeerHonorsRightmostNonTrustedHop(t *testing.T) {
	tp, _ := NewTrustedProxies([]string{"10.0.0.0/8"})
	r := &http.Request{RemoteAddr: "10.0.0.5:1234", Header: http.Header{}}
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.2")
	got := tp.ClientIP(r)
	if got.String() != "198.51.100.7" {
		t.Fatalf("expected real client IP 198.51.100.7, got %v", got)
	}
}

func TestClientIP_MalformedHeaderFallsBackToPeer(t *testing.T) {
	tp, _ := NewTrustedProxies([]string{"10.0.0.0/8"})
	r := &http.Request{RemoteAddr: "10.0.0.5:1234", Header: http.Header{}}
	r.Header.Set("X-Forwarded-For", "not-an-ip, also-not-an-ip")
	got := tp.ClientIP(r)
	if got.String() != "10.0.0.5" {
		t.Fatalf("expected fallback to peer IP, got %v", got)
	}
}

func TestIsForwardedHTTPS_OnlyTrustedPeer(t *testing.T) {
	tp, _ := NewTrustedProxies([]string{"10.0.0.0/8"})

	untrusted := &http.Request{RemoteAddr: "203.0.113.5:1234", Header: http.Header{}}
	untrusted.Header.Set("X-Forwarded-Proto", "https")
	if tp.IsForwardedHTTPS(untrusted) {
		t.Fatal("expected untrusted peer's X-Forwarded-Proto to be ignored")
	}

	trusted := &http.Request{RemoteAddr: "10.0.0.5:1234", Header: http.Header{}}
	trusted.Header.Set("X-Forwarded-Proto", "https")
	if !tp.IsForwardedHTTPS(trusted) {
		t.Fatal("expected trusted peer's X-Forwarded-Proto to be honored")
	}
}
