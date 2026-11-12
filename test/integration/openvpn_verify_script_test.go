//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"declarativeauth/internal/config"
)

// TestOpenVPNVerifyScript_EndToEnd runs the real verify.sh and the entrypoint's
// curl-config block, as deployed by the sysadmin repo's VPN manifest, against a
// real server. It only runs when OPENVPN_SCRIPT_DIR points at a directory with
// the ConfigMap's verify.sh and entrypoint.sh extracted, and sh/curl/jq exist.
func TestOpenVPNVerifyScript_EndToEnd(t *testing.T) {
	dir := os.Getenv("OPENVPN_SCRIPT_DIR")
	if dir == "" {
		t.Skip("OPENVPN_SCRIPT_DIR not set")
	}
	for _, bin := range []string{"sh", "curl", "jq", "base64"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	verifySh, err := os.ReadFile(filepath.Join(dir, "verify.sh"))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := os.ReadFile(filepath.Join(dir, "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, work)
	runtime := filepath.Join(work, "runtime")
	if err := os.MkdirAll(runtime, 0o755); err != nil {
		t.Fatal(err)
	}

	env := startTOTPServerWith(t, func(cfg *config.ServerConfig) {
		cfg.Verify.TLS = config.TLSListenerConfig{CertFile: certPath, KeyFile: keyPath}
	})
	const callerPW = `p"a\ss:w'ord$x` // exercises curl-config quoting
	seedPassword(t, env.pool, "svc", callerPW)
	for _, u := range []string{"secure", "plain", "outsider"} {
		seedPassword(t, env.pool, u, "Passw0rd!x")
	}
	secret := env.enroll(t, "secure")

	// The entrypoint's curl-config block, verbatim, with paths redirected.
	start := strings.Index(string(entry), "esc() {")
	end := strings.Index(string(entry), "chmod 640 /etc/openvpn/runtime/verify.curlrc")
	if start < 0 || end < 0 {
		t.Fatal("could not find the curl-config block in entrypoint.sh")
	}
	block := string(entry)[start : end+len("chmod 640 /etc/openvpn/runtime/verify.curlrc")]
	// chown to nogroup needs root and that group; irrelevant to what is tested here.
	block = strings.ReplaceAll(block, "chown root:nogroup /etc/openvpn/runtime/verify.curlrc", ":")
	block = strings.ReplaceAll(block, "/etc/openvpn/tls/ca.crt", certPath)
	block = strings.ReplaceAll(block, "/etc/openvpn/runtime", runtime)
	setup := exec.Command("sh", "-c", block)
	setup.Env = append(os.Environ(),
		"VERIFY_URL=https://127.0.0.1:"+portOf(env.verifyAddr)+"/v1/verify",
		"VERIFY_USER=svc", "VERIFY_PASSWORD="+callerPW)
	if out, err := setup.CombinedOutput(); err != nil {
		t.Fatalf("curl-config block failed: %v\n%s", err, out)
	}

	scriptPath := filepath.Join(work, "verify.sh")
	patched := strings.ReplaceAll(string(verifySh), "/etc/openvpn/runtime", runtime)
	if err := os.WriteFile(scriptPath, []byte(patched), 0o755); err != nil {
		t.Fatal(err)
	}

	scrv1 := func(pw, code string) string {
		e := base64.StdEncoding.EncodeToString
		return "SCRV1:" + e([]byte(pw)) + ":" + e([]byte(code))
	}
	run := func(user, password string) bool {
		t.Helper()
		// OpenVPN's auth-user-pass-verify via-file: $1 = file with the username on
		// line 1 and the password on line 2 (and nothing in the environment).
		credFile := filepath.Join(work, "creds")
		if err := os.WriteFile(credFile, []byte(user+"\n"+password+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", scriptPath, credFile)
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
		t.Logf("%s -> err=%v %s", user, err, strings.TrimSpace(string(out)))
		return err == nil
	}

	if !run("plain", "Passw0rd!x") {
		t.Error("plain user, plain password: want accept")
	}
	if !run("plain", scrv1("Passw0rd!x", "")) {
		t.Error("plain user, empty static-challenge answer: want accept")
	}
	if run("plain", "wrong") {
		t.Error("wrong password accepted")
	}
	if run("outsider", "Passw0rd!x") {
		t.Error("user outside vpn-users accepted")
	}
	if run("secure", "Passw0rd!x") {
		t.Error("MFA user without code accepted (old client)")
	}
	if run("secure", scrv1("Passw0rd!x", "000000")) {
		t.Error("MFA user with wrong code accepted")
	}
	if !run("secure", scrv1("Passw0rd!x", " "+currentCode(secret)+" ")) {
		t.Error("MFA user with valid code: want accept")
	}
	if run("secure", scrv1("Passw0rd!x", currentCode(secret))) {
		t.Error("replayed code accepted")
	}
	if run("secure", "SCRV1:!!!:!!!") {
		t.Error("malformed SCRV1 accepted")
	}
	if run("", "x") {
		t.Error("empty username accepted")
	}
	// Whitespace and backslashes in a password must survive the file round trip.
	seedPassword(t, env.pool, "plain", ` Pa\ss  w0rd `)
	if !run("plain", ` Pa\ss  w0rd `) {
		t.Error("password with spaces and backslash did not round-trip")
	}
}

func portOf(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

func writeSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "verify-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
