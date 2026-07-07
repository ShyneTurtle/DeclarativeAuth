# DeclarativeAuth project

The goal of this project is to make a declarative, easy-to-use, performant, lightweight, authentication system.

## Requirements
- The system shall support postgres and Cloud-native postgres to allow for clusterized deployment in docker & kubernetes.
- The system shall be declarative (file-based) for the groups and users.
- The groups shall support inheritance, where a user can be member of a group "A", and in turn becomes a member of all the groups the group "A" is part of, recursively.
- The system shall be performant and lightweight: It should consume less than 100MB of memory and low CPU, while allowing logins in less than 1 second.
- The system shall support LDAP authentication, flattening the groups inheritance so other systems's filters can easily get the inherited groups of a user without modification.
- The system shall support SMTP to send MFA authentication & password reset mails.
- The system shall support a small webpage allowing users to log in and/or reset their password with their email.
- The system shall feature detailed, leveled logs and prometheus metrics.
- The system shall be standalone besides the database, not relying on any other system.
- The system shall use hardened password hashing (Argon2id).
- The system shall apply a configurable brute-force login backoff (persisted, not just in-memory) shared across LDAP bind and OIDC/web login attempts.
- The system shall provide a CLI subcommand to validate declarative users/groups config files without starting the server, reporting the resulting user and group counts on success.
- The system shall log a summary of what changed (users/groups added, removed, modified) on every successful declarative config hot-reload.
- The system shall correctly attribute client IP addresses for rate limiting and audit logging when deployed behind a trusted reverse proxy or load balancer.
- The system shall provide a small, separately-gated admin web page for operators to: send a test email to verify SMTP configuration, visualize the group inheritance graph, and (optionally, single-instance deployments only) edit and save the declarative users/groups YAML files directly with live validation.
- The system shall support terminating its own TLS for HTTPS/LDAPS, or operating behind a reverse proxy/load balancer that terminates TLS on its behalf, forwarding plaintext to a trusted internal listener.
- The system shall be built following software development best practices: unit and integration testing, CI/CD, and well-documented, well-organized code.
- The system shall allow declaring a user's first name and (last) name, and derive the LDAP/OIDC display name from them when no explicit display name is set.
- The password-setting page shall require confirming the new password and shall show a live password-strength indicator; the minimum acceptable password length and strength shall be configurable.
- The system shall allow logging in with either a user's username or their declared email address, interchangeably, on both LDAP bind and OIDC/web login, sharing the same brute-force lockout state either way.
- The "forgot password" form shall accept either a username or an email address, interchangeably, resolving both to the same account as login does.
- The system shall warn operators about insecure configuration choices (e.g. TLS-disabled listeners, anonymous LDAP bind, a weak password policy) at startup, and the browser shall refuse to submit a password over a connection that isn't a secure context.
- The password-strength estimate shall resist trivial patterns such as a short sequence or a short unit repeated many times, not just raw length and character-class diversity.
- The system shall support passkeys for OIDC
- The system shall support email-based two-factor authentication: after a successful password login, a one-time code is emailed to the user's declared address and must be entered before a session is issued. It shall be enforceable declaratively (per-group via a "require MFA" flag, inherited the same way other group properties flatten, or per-user via an individual override field), and independently self-enabled by any user from their profile page even when not declaratively required.
