# DeclarativeAuth

A lightweight authentication server where **who exists is a file, not a
database row**. You declare users and groups (with recursive group
inheritance) in two YAML files; DeclarativeAuth hot-reloads them and
exposes that identity through both an LDAP server and an OIDC provider +
hosted login page, so any downstream system can authenticate against it.
Postgres is only used for what YAML can't express: password hashes,
sessions, password-reset tokens, audit history, and brute-force lockouts.

```
              users.yaml / groups.yaml   (declarative, hot-reloaded, "who exists")
                        |
                        v
                 DeclarativeAuth  <----->  Postgres  ("what only a database can hold":
                   /    |     \                       password hashes, sessions, audit log)
                  /     |      \
              LDAP    OIDC    web login/reset page
             server  provider  (+ small admin UI)
```

## Why this exists

If your users and their group memberships are already checked into a repo
somewhere (e.g. next to your Kubernetes manifests, or in an internal
"who's on the team" YAML file), DeclarativeAuth lets that file *be* the
source of truth for authentication, instead of syncing it into a separate
identity database that inevitably drifts out of sync.

## Features

- **Declarative identity** -- `users.yaml` / `groups.yaml`, hot-reloaded,
  with recursive group inheritance (diamond-safe, cycle-detected).
- **Username or email, interchangeably**, on LDAP bind, OIDC/web login, and
  the "forgot password" form alike -- all resolve to the same account, so
  brute-force lockout state is shared regardless of which one is used.
- **Insecure-configuration guards**: the server logs an explicit warning at
  startup for anything that could silently expose credentials (TLS-disabled
  listeners, anonymous LDAP bind, a weak password policy, the config editor
  running without TLS); the browser refuses to submit any password field at
  all when the page wasn't loaded over a secure connection.
- **LDAP v3 server** (simple bind + search) with fully flattened
  `memberOf`, so LDAP-only clients don't need to understand nested groups.
- **OIDC provider** (authorization code + PKCE) and a small hosted login page.
- **SMTP-based password reset** / first-password-setup flow, with password
  confirmation and a live strength indicator, backed by a configurable
  minimum length/strength policy (`passwordPolicy` in `declarativeauth.yaml`).
- **Hardened password storage**: Argon2id with an HMAC-SHA256 pepper layer.
- **Persisted brute-force backoff**, shared across LDAP and OIDC/web login.
- **Reverse-proxy aware**: correct client IP/scheme handling for rate
  limiting and audit logs when deployed behind a load balancer.
- **Observability**: Prometheus metrics, structured JSON logs, `/healthz` and `/readyz`.
- **Small admin UI** (separately gated by group membership): send a test
  email, view the group-inheritance graph, and optionally edit/save the
  declarative files from the browser (single-instance deployments only).
- **Single static binary**, ~27MB container image, a few MB of RSS at idle.

## Try it out

This spins up DeclarativeAuth plus Postgres and a
[mailcatcher](https://mailcatcher.me/) (so you can see password-reset
emails without a real SMTP server) using the example identity in
[`configs/example/`](configs/example/):

```sh
docker compose up -d --build
```

| What | Where |
|---|---|
| Login page | http://localhost:8080/login |
| Password reset | http://localhost:8080/reset |
| Caught emails (mailcatcher) | http://localhost:1080 |
| Admin UI | http://localhost:8080/admin |
| Prometheus metrics | http://localhost:9090/metrics |
| LDAP | `ldap://localhost:1389` |

The example identity declares users but no passwords (passwords never
live in YAML). Set one:

```sh
docker compose exec declarativeauth /declarativeauth admin set-password \
  -dsn "postgres://declarativeauth:declarativeauth@postgres:5432/declarativeauth?sslmode=disable" \
  -username jsmith -password Secret123!
```

(this reads the pepper from `DECLARATIVEAUTH_PASSWORD_PEPPER`, already set
in the container's environment by `docker-compose.yaml`)

Then log in at http://localhost:8080/login with `jsmith` / `Secret123!`,
or query LDAP directly:

```sh
ldapsearch -x -H ldap://localhost:1389 \
  -D uid=jsmith,ou=users,dc=example,dc=com -w Secret123! \
  -b ou=users,dc=example,dc=com "(memberOf=cn=engineering,ou=groups,dc=example,dc=com)" uid memberOf
```

`jsmith` isn't declared as a member of `engineering` directly (see
[`configs/example/groups.yaml`](configs/example/groups.yaml)) -- this
search only returns a result because `engineering` is a transitive
grandparent via `oncall` -> `backend-team` -> `engineering`, and
DeclarativeAuth flattens that automatically.

## Configuring your own deployment

Two separate kinds of config, both YAML, serving different purposes:

1. **Identity** (`users.yaml` + `groups.yaml`) -- *who exists*. See
   [`configs/example/users.yaml`](configs/example/users.yaml) and
   [`configs/example/groups.yaml`](configs/example/groups.yaml): every
   field is commented inline, and the example groups form a deliberate
   "diamond" to demonstrate inheritance. Point the server at your own copy
   via `config.identityPath` (below); edits are hot-reloaded, no restart
   needed.
2. **Server config** (`declarativeauth.yaml`) -- *how the server runs*:
   listeners, database DSN, SMTP, rate limiting, TLS, admin UI. See
   [`configs/example/declarativeauth.yaml`](configs/example/declarativeauth.yaml)
   for every field, its default, and whether it's required.

Secrets (DB password, SMTP password) are never written into either file
directly -- `declarativeauth.yaml` references them by environment
variable, either via `${VAR}` interpolation (e.g. in the database DSN) or
via an explicit `...Env` field naming the variable to read (e.g.
`smtp.passwordEnv`). The Argon2id password pepper is handled even more
strictly: it's not a config field at all, always read from a single fixed
environment variable, `DECLARATIVEAUTH_PASSWORD_PEPPER` -- there's no
`...Env` field for it, so there's exactly one place to look for how it's
wired up, in any deployment.

For a from-scratch production layout (Kubernetes + CloudNativePG), see
[`deploy/k8s/`](deploy/k8s/) -- in particular
[`deploy/k8s/configmap-identity.yaml`](deploy/k8s/configmap-identity.yaml)
for what a stricter, TLS-everywhere config looks like next to the same
identity example.

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
$ declarativeauth validate-config -identity-path configs/example
config valid: 5 groups, 3 users (1 disabled)
```

Use it in CI or a pre-commit hook against your real identity files, before
they ever reach a running server.

There is also an admin-only HTTP endpoint, `POST /admin/send-setup-link`
(gated the same way as the rest of `/admin`), that emails a newly-declared
user a first-password-setup link -- it reuses the identical token/email
flow as a normal password reset, so there's no separate "admin sets a raw
password" code path.

## Architecture

```
cmd/declarativeauth   entrypoint + CLI subcommands
internal/config       declarative YAML loading, validation, hot-reload, diff logging
internal/identity     domain model + group-inheritance resolver (cycle detection, flattening)
internal/store        Postgres access layer (credentials, sessions, reset tokens, audit, lockouts)
internal/auth         password hashing, Authenticate(), brute-force backoff, client IP
internal/ldapserver   minimal LDAPv3 server (Bind + Search only)
internal/oidcserver   authorization-code+PKCE OIDC provider
internal/web          login page, password reset flow, session cookie, CSRF
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

Two supported modes, chosen independently per listener (`ldap.tls.enabled`
/ `oidc.tls.enabled` in `declarativeauth.yaml`):

- **Self-terminated**: set `enabled: true` and provide a cert/key pair
  (either per-listener, or once in the shared top-level `tls:` block).
  Certs are hot-reloaded from disk on change -- no restart needed to roll
  a renewed cert. If no cert/key is configured at all while `enabled:
  true`, an ephemeral self-signed certificate is generated instead (a
  warning is logged; don't rely on this outside local dev).
- **Reverse-proxy terminated**: set `enabled: false` and put a
  TLS-terminating proxy/load balancer in front. Its address needs to be
  trusted for `X-Forwarded-For` / `X-Forwarded-Proto` headers to be honored
  (rate limiting, audit logs, and detecting that the original request was
  HTTPS) -- by default DeclarativeAuth already trusts its own default
  gateway (`network.trustDefaultGateway`, true by default), which covers
  the common case of a reverse proxy on the Docker host or in a sidecar
  reaching the container through its bridge gateway. Add explicit CIDRs to
  `network.trustedProxies` for anything beyond that (e.g. a load balancer
  reachable on a different address), or set `trustDefaultGateway: false`
  if nothing should be trusted implicitly.

Since "reverse-proxy terminated" is indistinguishable, from the config
alone, from someone simply forgetting to set up TLS at all, the server logs
an explicit `WARN` at startup whenever a listener has `tls.enabled: false`
(among other risky settings -- see "Insecure-configuration guards" below)
so it's never silently the case. There's no way to suppress these short of
actually fixing the setting; they're informational, not fatal.

## Insecure-configuration guards

Two independent layers, since neither can catch everything alone:

- **Startup warnings** (`internal/server/insecure_warnings.go`): logged
  once per `declarativeauth serve` startup for anything that could
  silently expose credentials -- TLS-disabled listeners, `ldap.allowAnonymousBind: true`,
  a `passwordPolicy` weaker than the documented defaults, or the config
  editor enabled without OIDC TLS (which would expose both the admin
  session cookie and the identity files it can rewrite). These are `WARN`
  logs, not startup failures -- some of them (e.g. TLS-disabled behind a
  reverse proxy) are entirely legitimate, so the server can't know for
  certain something's wrong, only flag what's worth double-checking.
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

## Deferred extensions

Not implemented yet, but the schema/architecture anticipates them:

- Authenticator-app TOTP MFA with recovery codes (`mfa_totp_secrets` /
  `mfa_recovery_codes` tables already exist, unused).
- Passkey/WebAuthn support on the OIDC login page.
