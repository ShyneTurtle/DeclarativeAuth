# DeclarativeAuth

A lightweight authentication server where **who exists is a file, not a
database row**. You declare users, groups (with recursive group
inheritance), and OIDC clients in hot-reloaded YAML files; DeclarativeAuth 
exposes that identity through both an LDAP server and an OIDC provider, so any
downstream system can authenticate against it. Postgres is used for dynamic
data: password hashes, sessions, password-reset tokens, audit history, and
brute-force lockouts. The process configuration is done through env variables.

```
              users.yaml / groups.yaml   (declarative, hot-reloaded, "who exists")
                        |
                        v
                 DeclarativeAuth  <----->  Postgres  (password hashes, sessions, logs)
                   /    |     \
                  /     |      \
              LDAP    OIDC    web login/reset page
             server  provider  (+ small admin UI)
```

## Why this exists

Managing users using a UI is nice & pretty, until you need to do something with that data.

Config file can be versioned, edited, generated, shared however you like - it's just files, not database records.

This is a lightweight & secure alternative to hard to heavy (authentik), hard to maintain (kanidm) or basic (lldap) auth systems.

## Features

- **Declarative identity**: YAML, hot-reloaded, with recursive group
  inheritance (diamond-safe, cycle-detected).
- **Single static binary**, ~27MB container image, a few MB of RSS at idle.
- **Passkey (WebAuthn) support**
- **Username or email, interchangeably**, both resolve to the same account.
- **OIDC provider**: authorization code + PKCE, refresh token rotation with
  reuse detection, `client_credentials` for service clients, token
  introspection/revocation (RFC 7662/7009), RP-Initiated Logout, CORS on the
  public-client endpoints, and Postgres-backed signing keys (ES256 or RS256)
  that rotate automatically and work across replicas
- **LDAP v3 server** (simple bind + search) with fully flattened
  `memberOf`, so LDAP-only clients don't need to understand nested groups.
- **Insecure-configuration guards**: the browser refuses to submit any password 
  field at all when the page wasn't loaded over a secure connection. 
  The server logs an explicit warning at startup for insecure configurations.
- **SMTP-based password reset & MFA**: configurable minimum length & strength
  policy, group & per-user enforceable MFA (users can still opt in even when
  not enforced, but they can't opt out if they are).
- **Persisted brute-force backoff**, shared across LDAP and OIDC/web login,
  opt-in (disabled by default -- a hard lockout is itself a DoS lever; see
  `DECLARATIVEAUTH_RATE_LIMIT_THRESHOLD` in `examples/.env.example`).
- **Environment-variable configuration**
- **Hardened password storage**: Argon2id.
- **Reverse-proxy aware**: correct client IP/scheme handling for rate
  limiting and audit logs when deployed behind a load balancer.
- **Observability**: Prometheus metrics, structured JSON logs, `/healthz` and `/readyz`.
- **Admin UI** (gated by a group setting): send test emails, view the 
  group-inheritance graph, and optionally edit/save the declarative files from the browser
  (can be disabled, single-instance deployments only (might change in the future)).

## Demo: Try it out

```sh
docker compose -f deploy/demo/docker-compose.yaml up -d --build
```

This spins up DeclarativeAuth, Postgres and a
[mailcatcher](https://mailcatcher.me/) (so you can see password-reset
emails without a real SMTP server) using the example identity in
[`examples/identity/`](examples/identity/), no persistence, unsecure listeners,
nothing to configure. See [`deploy/demo/`](deploy/demo/):

| What | Where |
|---|---|
| Home page (name/email, passkeys) | http://localhost:8080/ |
| Login page | http://localhost:8080/login |
| Password reset | http://localhost:8080/reset |
| Admin UI | http://localhost:8080/admin |
| Caught emails (mailcatcher) | http://localhost:1080 |
| Prometheus metrics | http://localhost:9090/metrics |
| LDAP | `ldap://localhost:1389` |

The example identity declares users but no passwords.
You can either use the forgot password form, or set one via CLI:

```sh
docker compose -f deploy/demo/docker-compose.yaml exec declarativeauth \
  /declarativeauth admin set-password \
  -username jsmith -password Secret123!
```

Then log in at http://localhost:8080/login with `jsmith` / `Secret123!`,
or query LDAP directly:

```sh
ldapsearch -x -H ldap://localhost:1389 \
  -D uid=jsmith,ou=users,dc=example,dc=com -w Secret123! \
  -b ou=users,dc=example,dc=com "(memberOf=cn=engineering,ou=groups,dc=example,dc=com)" uid memberOf
```

Ready to run this for real (on a NAS, a home server, whatever) instead of
just poking at it? [`deploy/compose/`](deploy/compose/) is a homelab-ready
single-instance stack instead: persistent Postgres, TLS on by default:

```sh
docker compose -f deploy/compose/docker-compose.yaml up -d
```

## Configuring your own deployment

Two separate kinds of input, deliberately different in shape:

1. **Identity**: users, groups, and OIDC clients: declarative YAML,
   hot-reloaded. Every `.yaml`/`.yml` file under
   `DECLARATIVEAUTH_IDENTITY_PATH` is read and used for identity if it
   contains the right config header, if not it is ignored (allows having
   other config files in the folder without problems). A file that declares a
   recognized header is validated strictly, so a typo in one is a real
   error, not something silently dropped. See
   [`examples/identity/`](examples/identity/) for a worked example of each
   kind. Zero declared groups is fine as long as no user references one;
   zero declared users isn't an error either, but logs a startup/reload
   warning, since nobody can log in until at least one exists. OIDC clients
   are optional too, but there is no dynamic client registration, 
   `oidc-clients.yaml` is the only way to register one, and an absent file
   just means none are registered; the discovery documents at
   `/.well-known/openid-configuration` and `/.well-known/jwks.json` are
   always served regardless, so client libraries can still auto-discover
   this issuer. A user's credential is normally set out-of-band (CLI or
   self-service reset, both write to Postgres) -- but a user can instead
   declare `passwordHash` (an inline Argon2id hash) or `passwordHashFile`
   (the same hash, read from a file -- typically a mounted Docker or
   Kubernetes secret) directly in the identity YAML. This is for accounts
   that are themselves config-managed, e.g. an LDAP service/bind account:
   it eliminates the need for an init container that runs
   `admin set-password` on every startup, and it hot-reloads (including
   secret rotation) the same as everything else here. Once set, Postgres is
   bypassed entirely for that user, so both the self-service reset flow and
   `admin set-password` refuse to touch the account. Generate the hash with
   `declarativeauth admin hash-password`. See `svc-example` in
   [`examples/identity/users.yaml`](examples/identity/users.yaml) and
   [`deploy/kubernetes/secret-ldap-passwords.yaml`](deploy/kubernetes/secret-ldap-passwords.yaml)
   for both flavors worked out. A user or group can also declare
   `customAttribute`: arbitrary out-of-schema LDAP attributes (eg. a phone
   number). A group can additionally declare `userCustomAttribute`/
   `directUserCustomAttribute` to push a custom attribute onto every member's
   own entry instead of the group's. See 
   [`examples/identity/users.yaml`](examples/identity/users.yaml) and
   [`examples/identity/groups.yaml`](examples/identity/groups.yaml) for the
   value-shape rules and a worked example of all three. Two sources
   declaring the same attribute key for the same user gives a warning as the 
   attribute is dropped for that user to avoid unpredictable behavior.
2. **Server config** -- *how the process runs*: listeners, database DSN,
   SMTP, rate limiting, TLS, admin UI. Entirely `DECLARATIVEAUTH_*`
   environment variables, set once at process start. See
   [`.env.example`](.env.example) at the repo root for every variable,
   its default, and whether it's required.

Secrets (DB password, SMTP password) are just the value of their own
environment variable (`DECLARATIVEAUTH_DATABASE_DSN` with the password
embedded, `DECLARATIVEAUTH_SMTP_PASSWORD`) -- however you inject
environment variables into the process (`docker run --env-file`, a
Kubernetes Secret, a systemd `EnvironmentFile=`) is however you manage
these secrets; DeclarativeAuth has no config-templating layer of its own
to route around.

For a from-scratch production layout (Kubernetes + CloudNativePG), see
[`deploy/kubernetes/`](deploy/kubernetes/) -- `configmap-env.yaml` /
`secret-example.yaml` for the non-secret/secret environment variables
(consumed via `envFrom`), `configmap-identity.yaml` for the same identity
example, mounted as a volume so it can hot-reload, and
`secret-ldap-passwords.yaml` for a worked `passwordHashFile` example --
mounted as a subdirectory of that same identity volume, so it hot-reloads
too.

## CLI

```
declarativeauth serve             # run the server (default long-running process)
declarativeauth migrate           # apply Postgres migrations and exit
declarativeauth validate-config   # validate users.yaml/groups.yaml/oidc-clients.yaml without starting anything
declarativeauth admin set-password    # seed/reset a password directly (bootstrap/testing)
declarativeauth admin hash-password   # print an Argon2id hash for a password, for passwordHash/passwordHashFile
```

`validate-config` reuses the exact same parse+validate code path the
running server uses (so results never diverge), and prints a summary:

```
$ declarativeauth validate-config -identity-path examples/identity
config valid: 5 groups, 4 users (1 disabled), 2 oidc clients
```

Use it in CI or a pre-commit hook against your real identity files, before
they ever reach a running server.

There is also an admin-only HTTP endpoint, `POST /admin/send-setup-link`
(gated the same way as the rest of `/admin`), that emails a newly-declared
user a first-password-setup link -- it reuses the identical token/email
flow as a normal password reset, so there's no separate "admin sets a raw
password" code path.

## Repository layout

```
cmd/declarativeauth   entrypoint + CLI subcommands
internal/             application code (see "Architecture" below)
examples/identity/    a worked users.yaml/groups.yaml/oidc-clients.yaml example (diamond group inheritance)
deploy/
  docker/             production Dockerfile
  compose/            homelab-ready single-instance docker-compose stack (persistent, TLS on)
  demo/               throwaway docker-compose stack for click-through testing (mailcatcher, no TLS)
  dev/                the Go toolchain dev container used to build/test the code itself
  kubernetes/         Deployment/Service/ConfigMap/Secret/Certificate/CNPG-Cluster examples
examples/.env.example every DECLARATIVEAUTH_* environment variable, with defaults/docs
test/integration/     integration tests (real Postgres, real SMTP, real LDAP client)
```

## Architecture

```
cmd/declarativeauth   entrypoint + CLI subcommands
internal/config       declarative identity YAML loading/validation/hot-reload, env-var server config
internal/identity     domain model + group-inheritance resolver (cycle detection, flattening)
internal/store        Postgres access layer (credentials, sessions, reset tokens, audit, lockouts, passkeys, email-MFA)
internal/auth         password hashing, Authenticate(), MFAPolicy, brute-force backoff, client IP
internal/ldapserver   minimal LDAPv3 server (Bind + Search only)
internal/oidcserver   authorization-code+PKCE OIDC provider
internal/web          login page, password reset flow, passkey (WebAuthn) flow, email-MFA flow, session cookie, CSRF
internal/admin        gated admin UI (SMTP test, group graph, config editor)
internal/mail         SMTP client + email templates
internal/tls          certificate loading + hot rotation + self-signed dev fallback
internal/metrics      Prometheus metric definitions
internal/logging      log/slog setup
internal/server       process composition: wires every listener together
```

The key architectural seam: **LDAP bind and OIDC/web login both call the
exact same `internal/auth.Authenticate`**, and both read group membership
from the exact same `identity.Snapshot.FlattenedMemberOf`. That's what
guarantees LDAP and OIDC present an identical view of identity.

## TLS

LDAP and OIDC/web each have two *independent* listener addresses -- a
plaintext one and a TLS-terminating ("secure") one -- and either, both, or
neither can be active, entirely based on whether its address variable is
set: `DECLARATIVEAUTH_LDAP_LISTEN_ADDR` / `DECLARATIVEAUTH_LDAP_SECURE_LISTEN_ADDR`,
and `DECLARATIVEAUTH_OIDC_LISTEN_ADDR` / `DECLARATIVEAUTH_OIDC_SECURE_LISTEN_ADDR`.
There's no separate "TLS enabled" flag to keep in sync -- setting the secure
address *is* what turns TLS on for that listener, and running both at once
(e.g. a plaintext port for in-cluster traffic alongside a public TLS port)
is a supported, ordinary configuration.

- **Self-terminated**: set `..._SECURE_LISTEN_ADDR` and provide a cert/key
  pair (either per-listener, e.g. `DECLARATIVEAUTH_OIDC_TLS_CERT_FILE`, or
  once via the shared `DECLARATIVEAUTH_TLS_CERT_FILE`/`_KEY_FILE`). Certs
  are hot-reloaded from disk on change -- no restart needed to roll a
  renewed cert. If no cert/key is configured at all while the secure
  address is set, an ephemeral self-signed certificate is generated instead
  (a warning is logged; don't rely on this outside local dev).
- **StartTLS**: independent of the above, the LDAP listener
  (`DECLARATIVEAUTH_LDAP_LISTEN_ADDR`) offers the StartTLS extended
  operation (RFC 4511 §4.14), resolving a cert/key pair the same way the
  secure listener does (self-signed fallback included).
- **Reverse-proxy terminated**: set the `..._LISTEN_ADDR` bind address/port
  (for LDAP, also allow unsecure plaintext connections with 
  `DECLARATIVEAUTH_LDAP_REQUIRE_TLS=false`), and put a TLS-terminating
  proxy/load balancer in front. Its address needs to be trusted for 
  `X-Forwarded-For` / `X-Forwarded-Proto` headers to be honored (rate limiting,
  audit logs, and detecting that the original request was HTTPS) -- by default
  DeclarativeAuth already trusts its own default gateway
  (`DECLARATIVEAUTH_NETWORK_TRUST_DEFAULT_GATEWAY`, true by default), which
  covers the common case of a reverse proxy on the Docker host or in a
  sidecar reaching the container through its bridge gateway. Add explicit
  CIDRs to `DECLARATIVEAUTH_NETWORK_TRUSTED_PROXIES` for anything beyond
  that (e.g. a load balancer reachable on a different address).

Since "reverse-proxy terminated" is indistinguishable, from the
configuration alone, from someone simply forgetting to set up TLS at all,
the server logs an explicit `WARN` at startup for OIDC/web whenever its
plaintext address is set, and for LDAP whenever `DECLARATIVEAUTH_LDAP_REQUIRE_TLS`
is set to `false`, among other risky settings, see "Insecure-configuration
guards" below -- so it's never silently the case. There's no way to
suppress these short of actually fixing the setting;
they're informational, not
fatal.

## Insecure-configuration guards

Two independent layers, since neither can catch everything alone:

- **Startup warnings** (`internal/server/insecure_warnings.go`): logged
  once per `declarativeauth serve` startup for anything that could
  silently expose credentials -- TLS-disabled listeners,
  `DECLARATIVEAUTH_LDAP_ALLOW_ANONYMOUS_BIND=true`, a password policy
  weaker than the documented defaults, or the config editor enabled
  without OIDC TLS (which would expose both the admin session cookie and
  the identity files it can rewrite). These are `WARN` logs, not startup
  failures -- some of them (e.g. TLS-disabled behind a reverse proxy) are
  entirely legitimate, so the server can't know for certain something's
  wrong, only flag what's worth double-checking.
- **Client-side guard** (`internal/web/static/secure-guard.js`, loaded on
  every login/reset/admin page): refuses to submit any form containing a
  password field unless `window.isSecureContext` is true -- the browser's
  own definition of "safe to send secrets" (true for HTTPS, and also true
  for `http://localhost` so local dev without TLS still works). This is a
  last-resort net for the non-adversarial case -- a stale bookmark, a
  misconfigured proxy, a typo'd link landing someone on plain HTTP -- not a
  substitute for actually running TLS; a network attacker who controls the
  connection can also tamper with the JavaScript itself.

## Samba integration

A Samba file server can use DeclarativeAuth as its account backend
(`passdb backend = ldapsam:ldap://...`) via LDAP, so file share ACLs come
from the same declarative users/groups everything else does. This is
opt-in and off by default -- set `DECLARATIVEAUTH_LDAP_SAMBA_READERS_GROUP`
to a group name, plus `DECLARATIVEAUTH_LDAP_SAMBA_DOMAIN_SID` (generate once
with `net getlocalsid` on the Samba host, then never change it) and
`DECLARATIVEAUTH_LDAP_SAMBA_DOMAIN_NAME` (Samba's `workgroup`). See
`examples/.env.example`.

Three things worth understanding before turning this on:

- **A second, weaker credential is involved.** NTLM (what SMB actually
  speaks on the wire) requires the server to hold an NT hash -- MD4 of the
  password, unsalted -- not a check against Argon2id. DeclarativeAuth
  computes and stores this alongside the Argon2id hash, but it's real 
  password-equivalent material if leaked, unlike Argon2id.
- **Read access to it is gated, not just present.** Only an LDAP bind
  authenticated as a member of `DECLARATIVEAUTH_LDAP_SAMBA_READERS_GROUP`
  can access `sambaNTPassword`, `sambaSID`, `sambaAcctFlags`, or any of the
  `posixAccount`/`posixGroup`/`sambaGroupMapping` attributes below.
- **Primary group resolution needs NSS, not just LDAP.** Every user is
  rendered with `sambaPrimaryGroupSID` pointing at the domain's well-known
  "Domain Users" group (RID 513), but Samba's `ldapsam` backend does not
  actually read that attribute to resolve a user's primary group -- verified
  against Samba's own source (`source3/passdb/lookup_sid.c`,
  `get_primary_group_sid()`): it always calls `getpwnam(3)` on the Samba
  host and maps the result's `pw_gid` to a SID, falling back to "Domain
  Users" only if no Unix account can be found *at all* -- in which case
  `pdbedit`/`smbd` report the primary group as `(NULL SID)` rather than
  falling back gracefully. To fix that, every user and group here is also
  rendered with `posixAccount`/`posixGroup` (`uidNumber`/`gidNumber`,
  `homeDirectory`, `loginShell`, `memberUid`), so the Samba host's own NSS
  resolves `jsmith` and its groups correctly once something is configured to
  read them from this same LDAP server -- `nss_ldap`/`libnss-ldapd`/`sssd`
  in `nsswitch.conf`, or `winbindd` with `ldapsam:trusted = yes`. Without
  that NSS wiring, the primary group SID (and any group's SID) stays
  unresolvable to real Samba tooling even though LDAP is serving it.
  Declarative groups get their own `sambaSID`/`sambaGroupMapping` entry too
  (RID assigned and persisted on first use, same as a user's), so they're
  usable in a Windows ACL once NSS resolves them -- confirmed against a real
  `pdbedit -L -v` and `net groupmap list` run in this repo's devcontainer,
  not just this project's own LDAP client tests.

Known limitation: A declaratively-hashed account
(`passwordHash`/`passwordHashFile`) can never get an NT hash, so such accounts
(typically service accounts) won't be able to authenticate to Samba shares.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for local dev setup (a WSL/Docker dev
container is used since this was built without a local Go toolchain),
running tests, and adding migrations.
