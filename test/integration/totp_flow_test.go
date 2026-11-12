//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"testing"
	"time"

	"declarativeauth/internal/config"
	"declarativeauth/internal/metrics"
	"declarativeauth/internal/server"
	"declarativeauth/internal/store"
	"declarativeauth/internal/totp"

	"github.com/jackc/pgx/v5/pgxpool"
)

type totpEnv struct {
	issuer     string
	verifyAddr string
	pool       *pgxpool.Pool
	totp       *store.TOTPStore
}

// startTOTPServer runs the full server with TOTP enabled and the verify API
// listening, against the "totp" identity fixture.
func startTOTPServer(t *testing.T) *totpEnv { return startTOTPServerWith(t, nil) }

// startTOTPServerWith is startTOTPServer with a hook to adjust the config.
func startTOTPServerWith(t *testing.T, mutate func(*config.ServerConfig)) *totpEnv {
	t.Helper()
	pool := setupPool(t)
	if _, err := pool.Exec(context.Background(), "DELETE FROM user_totp"); err != nil {
		t.Fatalf("cleaning user_totp: %v", err)
	}
	oidcAddr, ldapAddr, verifyAddr := freePort(t), freePort(t), freePort(t)
	key := bytes.Repeat([]byte{0x42}, 32)

	cfg := &config.ServerConfig{
		Database: config.DatabaseConfig{DSN: testDSN(t), MaxConns: 5},
		LDAP:     config.LDAPConfig{ListenAddr: ldapAddr, BaseDN: "dc=example,dc=com"},
		OIDC: config.OIDCConfig{
			Issuer: "http://" + oidcAddr, ListenAddr: oidcAddr, SigningAlg: "ES256",
			KeyRotationInterval: config.Duration(720 * time.Hour),
			KeyOverlap:          config.Duration(24 * time.Hour),
			RefreshTokenTTL:     config.Duration(720 * time.Hour),
		},
		SMTP: config.SMTPConfig{Host: "mailcatcher", Port: 1025, From: "DeclarativeAuth <test@example.com>"},
		RateLimit: config.RateLimitConfig{
			Threshold: 5, BackoffBase: config.Duration(time.Second),
			BackoffMax: config.Duration(15 * time.Minute), Window: config.Duration(24 * time.Hour),
		},
		AdminUI: config.AdminUIConfig{AdminGroup: "admins"},
		TOTP:    config.TOTPConfig{EncryptionKey: key, Issuer: "Test"},
		Verify:  config.VerifyConfig{SecureListenAddr: verifyAddr, CallerGroup: "credential-verifiers"},
	}
	if mutate != nil {
		mutate(cfg)
	}
	holder := &config.SnapshotHolder{}
	snap, err := config.LoadIdentity(fixturePath("totp"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	holder.Set(snap)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Run(ctx, cfg, holder, pool, testLogger(), metrics.New()) }()
	waitForTCP(t, oidcAddr, 10*time.Second)
	waitForTCP(t, verifyAddr, 10*time.Second)

	cipher, err := totp.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return &totpEnv{
		issuer: "http://" + oidcAddr, verifyAddr: verifyAddr, pool: pool,
		totp: &store.TOTPStore{Pool: pool, Cipher: cipher},
	}
}

// enroll gives username a confirmed authenticator secret directly.
func (e *totpEnv) enroll(t *testing.T, username string) []byte {
	t.Helper()
	ctx := context.Background()
	secret, err := e.totp.BeginEnrollment(ctx, username)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.totp.ConfirmEnrollment(ctx, username, totp.Code(secret, totp.Step(time.Now())), time.Now()); err != nil {
		t.Fatal(err)
	}
	e.resetReplay(t, username)
	return secret
}

// resetReplay forgets the last accepted step so a test can reuse "now".
func (e *totpEnv) resetReplay(t *testing.T, username string) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `UPDATE user_totp SET last_step = 0 WHERE username = $1`, username); err != nil {
		t.Fatal(err)
	}
}

func currentCode(secret []byte) string { return totp.Code(secret, totp.Step(time.Now())) }

type browser struct {
	t      *testing.T
	issuer string
	client *http.Client
	jar    *cookiejar.Jar
}

func newBrowser(t *testing.T, issuer string) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, issuer: issuer, jar: jar, client: &http.Client{Jar: jar}}
}

func (b *browser) csrf() string {
	u, _ := url.Parse(b.issuer)
	return csrfFrom(b.jar, u)
}

func (b *browser) has(name string) bool {
	u, _ := url.Parse(b.issuer)
	return hasCookie(b.jar, u, name)
}

func (b *browser) get(path string) (*http.Response, string) {
	b.t.Helper()
	resp, err := b.client.Get(b.issuer + path)
	if err != nil {
		b.t.Fatalf("GET %s: %v", path, err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	resp.Body.Close()
	return resp, buf.String()
}

func (b *browser) post(path string, v url.Values) (*http.Response, string) {
	b.t.Helper()
	v.Set("csrf_token", b.csrf())
	resp, err := b.client.PostForm(b.issuer+path, v)
	if err != nil {
		b.t.Fatalf("POST %s: %v", path, err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	resp.Body.Close()
	return resp, buf.String()
}

func (b *browser) password(user, pw string) *http.Response {
	b.get("/login")
	resp, _ := b.post("/login", url.Values{"username": {user}, "password": {pw}})
	return resp
}

var secretRe = regexp.MustCompile(`<code>([A-Z2-7]+)</code>`)

func secretFromPage(t *testing.T, body string) []byte {
	t.Helper()
	m := secretRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no secret on enrolment page:\n%s", body)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

// A user subject to MFA with no authenticator app must enrol one during
// sign-in, only after the emailed-code step, and gets no session before.
func TestTOTPFlow_ForcedEnrolmentDuringSignIn(t *testing.T) {
	api := mailcatcherAPI(t)
	clearMailcatcher(t, api)
	env := startTOTPServer(t)
	seedPassword(t, env.pool, "secure", "CorrectHorse123!")

	b := newBrowser(t, env.issuer)
	if resp := b.password("secure", "CorrectHorse123!"); resp.Request.URL.Path != "/login/mfa" {
		t.Fatalf("expected /login/mfa, got %s", resp.Request.URL.Path)
	}

	// Having only passed the password step, the enrolment page must be unreachable:
	// otherwise a stolen password could enrol the attacker's own app and bypass email MFA.
	resp, _ := b.get("/login/mfa/enroll")
	if resp.Request.URL.Path != "/login" {
		t.Fatalf("enrolment reachable without passing MFA: landed on %s", resp.Request.URL.Path)
	}
	if b.has("da_session") {
		t.Fatal("session issued before MFA")
	}

	// Redo the password step (the failed probe cleared the pending cookie).
	b = newBrowser(t, env.issuer)
	b.password("secure", "CorrectHorse123!")
	code := waitForMFACode(t, api, "secure@example.com")
	resp, body := b.post("/login/mfa", url.Values{"code": {code}})
	if resp.Request.URL.Path != "/login/mfa/enroll" {
		t.Fatalf("expected forced enrolment after email code, got %s", resp.Request.URL.Path)
	}
	if b.has("da_session") {
		t.Fatal("session issued before enrolment finished")
	}
	secret := secretFromPage(t, body)

	// Wrong code: still no session, still on the page.
	resp, _ = b.post("/login/mfa/enroll", url.Values{"code": {"000000"}})
	if b.has("da_session") || resp.Request.URL.Path != "/login/mfa/enroll" {
		t.Fatalf("wrong enrolment code accepted (path %s)", resp.Request.URL.Path)
	}

	resp, _ = b.post("/login/mfa/enroll", url.Values{"code": {currentCode(secret)}})
	if resp.Request.URL.Path != "/" || !b.has("da_session") {
		t.Fatalf("expected signed in at / after enrolment, got %s (session=%v)", resp.Request.URL.Path, b.has("da_session"))
	}
	enrolled, err := env.totp.IsEnrolled(context.Background(), "secure")
	if err != nil || !enrolled {
		t.Fatalf("enrolled=%v err=%v", enrolled, err)
	}
}

// Once enrolled, the authenticator app is the default (nothing emailed), the
// user can switch to an emailed code, and a wrong code never signs in.
func TestTOTPFlow_ChooseAppOrEmail(t *testing.T) {
	api := mailcatcherAPI(t)
	env := startTOTPServer(t)
	seedPassword(t, env.pool, "secure", "CorrectHorse123!")
	secret := env.enroll(t, "secure")

	t.Run("authenticator app is the default and sends no email", func(t *testing.T) {
		clearMailcatcher(t, api)
		b := newBrowser(t, env.issuer)
		resp := b.password("secure", "CorrectHorse123!")
		if resp.Request.URL.Path != "/login/mfa" {
			t.Fatalf("expected /login/mfa, got %s", resp.Request.URL.Path)
		}
		_, page := b.get("/login/mfa")
		if !regexp.MustCompile(`authenticator app`).MatchString(page) || !regexp.MustCompile(`Email me a code instead`).MatchString(page) {
			t.Fatalf("expected app prompt with email alternative:\n%s", page)
		}
		if r, _ := http.Get(api + "/messages"); r != nil {
			var msgs []mcMessage
			_ = json.NewDecoder(r.Body).Decode(&msgs)
			r.Body.Close()
			if len(msgs) != 0 {
				t.Fatalf("email sent although the authenticator app is the default: %d messages", len(msgs))
			}
		}
		if resp, _ := b.post("/login/mfa", url.Values{"code": {"000000"}}); b.has("da_session") {
			t.Fatalf("wrong code signed in (path %s)", resp.Request.URL.Path)
		}
		resp, _ = b.post("/login/mfa", url.Values{"code": {currentCode(secret)}})
		if resp.Request.URL.Path != "/" || !b.has("da_session") {
			t.Fatalf("authenticator code did not sign in: %s", resp.Request.URL.Path)
		}
	})

	t.Run("email code works on request", func(t *testing.T) {
		env.resetReplay(t, "secure")
		clearMailcatcher(t, api)
		b := newBrowser(t, env.issuer)
		b.password("secure", "CorrectHorse123!")
		b.get("/login/mfa")
		b.post("/login/mfa/resend", url.Values{})
		code := waitForMFACode(t, api, "secure@example.com")
		resp, _ := b.post("/login/mfa", url.Values{"code": {code}})
		if resp.Request.URL.Path != "/" || !b.has("da_session") {
			t.Fatalf("emailed code did not sign in: %s", resp.Request.URL.Path)
		}
	})

	t.Run("an authenticator code cannot be replayed", func(t *testing.T) {
		env.resetReplay(t, "secure")
		code := currentCode(secret)
		first := newBrowser(t, env.issuer)
		first.password("secure", "CorrectHorse123!")
		first.post("/login/mfa", url.Values{"code": {code}})
		if !first.has("da_session") {
			t.Fatal("first use rejected")
		}
		second := newBrowser(t, env.issuer)
		second.password("secure", "CorrectHorse123!")
		second.post("/login/mfa", url.Values{"code": {code}})
		if second.has("da_session") {
			t.Fatal("replayed code signed in")
		}
	})

	t.Run("five wrong codes kill the challenge", func(t *testing.T) {
		env.resetReplay(t, "secure")
		b := newBrowser(t, env.issuer)
		b.password("secure", "CorrectHorse123!")
		for i := 0; i < 5; i++ {
			b.post("/login/mfa", url.Values{"code": {"000000"}})
		}
		b.post("/login/mfa", url.Values{"code": {currentCode(secret)}})
		if b.has("da_session") {
			t.Fatal("valid code accepted after the attempt budget was exhausted")
		}
	})
}

type verifyReply struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
}

func (e *totpEnv) verify(t *testing.T, caller, callerPW string, body map[string]string) (int, verifyReply) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, "https://"+e.verifyAddr+"/v1/verify", bytes.NewReader(raw))
	req.SetBasicAuth(caller, callerPW)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("verify call: %v", err)
	}
	defer resp.Body.Close()
	var out verifyReply
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestTOTPFlow_VerifyAPI(t *testing.T) {
	env := startTOTPServer(t)
	for _, u := range []string{"svc", "secure", "plain", "outsider"} {
		seedPassword(t, env.pool, u, "Passw0rd!x")
	}
	secret := env.enroll(t, "secure")

	check := func(name string, status int, reason string, caller string, body map[string]string) {
		t.Helper()
		got, reply := env.verify(t, caller, "Passw0rd!x", body)
		if got != status || reply.Reason != reason {
			t.Errorf("%s: got %d %q, want %d %q", name, got, reply.Reason, status, reason)
		}
	}

	check("plain user, password only", 200, "", "svc", map[string]string{"username": "plain", "password": "Passw0rd!x", "group": "vpn-users"})
	check("MFA user without code", 401, "mfa_code_missing", "svc", map[string]string{"username": "secure", "password": "Passw0rd!x", "group": "vpn-users"})
	check("MFA user, wrong code", 401, "bad_totp", "svc", map[string]string{"username": "secure", "password": "Passw0rd!x", "code": "000000"})
	check("MFA user, right code but wrong password", 401, "bad_password", "svc", map[string]string{"username": "secure", "password": "nope", "code": currentCode(secret)})
	check("MFA user, password and code", 200, "", "svc", map[string]string{"username": "secure", "password": "Passw0rd!x", "code": currentCode(secret), "group": "vpn-users"})
	check("same code replayed", 401, "bad_totp", "svc", map[string]string{"username": "secure", "password": "Passw0rd!x", "code": currentCode(secret)})
	check("not in the requested group", 403, "not_in_group", "svc", map[string]string{"username": "outsider", "password": "Passw0rd!x", "group": "vpn-users"})
	check("caller not a verifier", 403, "caller_not_allowed", "plain", map[string]string{"username": "plain", "password": "Passw0rd!x"})
}

// Guessing codes with a known password is bounded by the normal lockout,
// which a successful password check alone must not reset.
func TestTOTPFlow_VerifyAPILockoutOnCodeGuessing(t *testing.T) {
	env := startTOTPServer(t)
	seedPassword(t, env.pool, "svc", "Passw0rd!x")
	seedPassword(t, env.pool, "locky", "Passw0rd!x")
	secret := env.enroll(t, "locky")

	for i := 0; i < 6; i++ {
		env.verify(t, "svc", "Passw0rd!x", map[string]string{"username": "locky", "password": "Passw0rd!x", "code": "000000"})
	}
	status, reply := env.verify(t, "svc", "Passw0rd!x", map[string]string{"username": "locky", "password": "Passw0rd!x", "code": currentCode(secret)})
	if status != 401 || reply.Reason != "locked_out" {
		t.Fatalf("expected locked_out after repeated bad codes, got %d %q", status, reply.Reason)
	}
}

func TestTOTPStore_StagesAndSealing(t *testing.T) {
	env := startTOTPServer(t)
	ctx := context.Background()
	ch := &store.EmailChallengeStore{Pool: env.pool}

	// An enrol-stage challenge must never satisfy the login verify step.
	if err := ch.Create(ctx, "enr", "secure", "h", "/", store.ChallengeStageEnroll, false, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.Verify(ctx, "enr", "h"); err == nil {
		t.Fatal("enroll-stage challenge accepted by Verify")
	}
	got, err := ch.Peek(ctx, "enr")
	if err != nil || got.Stage != store.ChallengeStageEnroll {
		t.Fatalf("peek: %v %v", got, err)
	}

	// A secret copied onto another user's row must not decrypt.
	secret := env.enroll(t, "secure")
	var sealed []byte
	if err := env.pool.QueryRow(ctx, `SELECT secret_enc FROM user_totp WHERE username='secure'`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("secret stored in clear")
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO user_totp (username, secret_enc) VALUES ('plain', $1)`, sealed); err != nil {
		t.Fatal(err)
	}
	if ok, err := env.totp.Verify(ctx, "plain", currentCode(secret)); ok || err == nil {
		t.Fatalf("sealed secret opened under another username: ok=%v err=%v", ok, err)
	}
}
