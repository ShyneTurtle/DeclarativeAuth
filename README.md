# DeclarativeAuth

A lightweight authentication server where **who exists is a file, not a
database row**. You declare users and groups (with recursive group
inheritance) in two YAML files; DeclarativeAuth hot-reloads them and
exposes that identity through both an LDAP server and an OIDC provider +
hosted login page, so any downstream system can authenticate against it.
Postgres is only used for what YAML can't express: password hashes,
sessions, password-reset tokens, audit history, and brute-force lockouts.
Everything else -- how the process itself runs -- is configured through
environment variables.

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

- **Declarative identity** -- `users.yaml` / `groups.yaml`, hot-reloaded,
  with recursive group inheritance (diamond-safe, cycle-detected).
- **Single static binary**, ~27MB container image, a few MB of RSS at idle.
- **Passkey (WebAuthn) support**
- **Username or email, interchangeably**, both resolve to the same account.
- **OIDC provider**, authorization code + PKCE
- **LDAP v3 server** (simple bind + search) with fully flattened
  `memberOf`, so LDAP-only clients don't need to understand nested groups.
- **Insecure-configuration guards**: the browser refuses to submit any password 
  field at all when the page wasn't loaded over a secure connection. 
  The server logs an explicit warning at startup for insecure configurations.
- **SMTP-based password reset & MFA**: configurable minimum length & strength
  policy, group & per-user enforceable MFA (users can still opt in even when
  not enforced, but they can't opt out if they are).
- **Persisted brute-force backoff**, shared across LDAP and OIDC/web login.
- **Environment-variable configuration**
- **Hardened password storage**: Argon2id with an HMAC-SHA256 pepper layer.
- **Reverse-proxy aware**: correct client IP/scheme handling for rate
  limiting and audit logs when deployed behind a load balancer.
- **Observability**: Prometheus metrics, structured JSON logs, `/healthz` and `/readyz`.
- **Admin UI** (gated by a group setting): send test emails, view the 
  group-inheritance graph, and optionally edit/save the declarative files from the browser
  (can be disabled, single-instance deployments only (might change in the future)).

## Try it out

This spins up DeclarativeAuth plus Postgres and a
[mailcatcher](https://mailcatcher.me/) (so you can see password-reset
emails without a real SMTP server) using the example identity in
[`examples/identity/`](examples/identity/):

```sh
cp deploy/compose/.env.example deploy/compose/.env
docker compose -f deploy/compose/docker-compose.yaml up -d --build
```

| What | Where |
|---|---|
| Login page | http://localhost:8080/login |
| Home page (name/email, admin link, passkeys) | http://localhost:8080/ |
| Password reset | http://localhost:8080/reset |
| Caught emails (mailcatcher) | http://localhost:1080 |
| Admin UI | http://localhost:8080/admin |
| Prometheus metrics | http://localhost:9090/metrics |
| LDAP | `ldap://localhost:1389` |

The example identity declares users but no passwords (passwords never
live in YAML). Set one:

```sh
docker compose -f deploy/compose/docker-compose.yaml exec declarativeauth \
  /declarativeauth admin set-password \
  -dsn "postgres://declarativeauth:declarativeauth@postgres:5432/declarativeauth?sslmode=disable" \
  -username jsmith -password Secret123!
```

(this reads the pepper from `DECLARATIVEAUTH_PASSWORD_PEPPER`, already set
via `deploy/compose/.env`)

Then log in at http://localhost:8080/login with `jsmith` / `Secret123!`,
or query LDAP directly:

```sh
ldapsearch -x -H ldap://localhost:1389 \
  -D uid=jsmith,ou=users,dc=example,dc=com -w Secret123! \
  -b ou=users,dc=example,dc=com "(memberOf=cn=engineering,ou=groups,dc=example,dc=com)" uid memberOf
```

`jsmith` isn't declared as a member of `engineering` directly (see
[`examples/identity/groups.yaml`](examples/identity/groups.yaml)) -- this
search only returns a result because `engineering` is a transitive
grandparent via `oncall` -> `backend-team` -> `engineering`, and
DeclarativeAuth flattens that automatically.

## Configuring your own deployment

Two separate kinds of input, deliberately different in shape:

1. **Identity** (`users.yaml` + `groups.yaml`) -- *who exists*, declarative
   YAML, hot-reloaded. See [`examples/identity/`](examples/identity/):
   every field is commented inline, and the example groups form a
   deliberate "diamond" to demonstrate inheritance. Point the server at
   your own copy via `DECLARATIVEAUTH_IDENTITY_PATH`; edits are
   hot-reloaded, no restart needed.
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
to route around. The Argon2id password pepper is handled even more
strictly: it's not a configurable-name field at all, always read from a
single fixed environment variable, `DECLARATIVEAUTH_PASSWORD_PEPPER`, so
there's exactly one place to look for how it's wired up, in any deployment.

For a from-scratch production layout (Kubernetes + CloudNativePG), see
[`deploy/kubernetes/`](deploy/kubernetes/) -- `configmap-env.yaml` /
`secret-example.yaml` for the non-secret/secret environment variables
(consumed via `envFrom`), and `configmap-identity.yaml` for the same
identity example, mounted as a volume so it can hot-reload.

## CLI

```
declarativeauth serve             # run the server (default long-running process)
declarativeauth migrate           # apply Postgres migrations and exit
declarativeauth validate-config   # validate users.yaml/groups.yaml without starting anything
declarativeauth admin set-password    # seed/reset a password directly (bootstrap/testing)
```

`validate-config` reuses the exact same parse+validate code path the
running server uses (so results never diverge), and prints a summary:

```
$ declarativeauth validate-config -identity-path examples/identity
config valid: 5 groups, 3 users (1 disabled)
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
examples/identity/    a worked users.yaml/groups.yaml example (diamond group inheritance)
deploy/
  docker/             production Dockerfile
  compose/            docker-compose quickstart stack + the Go toolchain dev container
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

Two supported modes, chosen independently per listener
(`DECLARATIVEAUTH_LDAP_TLS_ENABLED` / `DECLARATIVEAUTH_OIDC_TLS_ENABLED`):

- **Self-terminated**: set `..._TLS_ENABLED=true` and provide a cert/key
  pair (either per-listener, e.g. `DECLARATIVEAUTH_OIDC_TLS_CERT_FILE`, or
  once via the shared `DECLARATIVEAUTH_TLS_CERT_FILE`/`_KEY_FILE`). Certs
  are hot-reloaded from disk on change -- no restart needed to roll a
  renewed cert. If no cert/key is configured at all while
  `..._TLS_ENABLED=true`, an ephemeral self-signed certificate is
  generated instead (a warning is logged; don't rely on this outside local
  dev).
- **Reverse-proxy terminated**: leave `..._TLS_ENABLED=false` (the
  default) and put a TLS-terminating proxy/load balancer in front. Its
  address needs to be trusted for `X-Forwarded-For` / `X-Forwarded-Proto`
  headers to be honored (rate limiting, audit logs, and detecting that the
  original request was HTTPS) -- by default DeclarativeAuth already trusts
  its own default gateway (`DECLARATIVEAUTH_NETWORK_TRUST_DEFAULT_GATEWAY`,
  true by default), which covers the common case of a reverse proxy on the
  Docker host or in a sidecar reaching the container through its bridge
  gateway. Add explicit CIDRs to `DECLARATIVEAUTH_NETWORK_TRUSTED_PROXIES`
  for anything beyond that (e.g. a load balancer reachable on a different
  address), or set `DECLARATIVEAUTH_NETWORK_TRUST_DEFAULT_GATEWAY=false` if
  nothing should be trusted implicitly.

Since "reverse-proxy terminated" is indistinguishable, from the
configuration alone, from someone simply forgetting to set up TLS at all,
the server logs an explicit `WARN` at startup whenever a listener has
TLS disabled (among other risky settings -- see "Insecure-configuration
guards" below) so it's never silently the case. There's no way to suppress
these short of actually fixing the setting; they're informational, not
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

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for local dev setup (a WSL/Docker dev
container is used since this was built without a local Go toolchain),
running tests, and adding migrations.
