# KARIDNS-WEBADMIN(8) — KariDNS WebAdmin API

## NAME

**karidns-webadmin** — the HTTP API of a KariDNS database (PostgreSQL or SQLite3): logins, users, groups and grants, and the zones the database holds, under `/api/v1/`

## SYNOPSIS

```text
karidns-webadmin [-c <config>]
karidns-webadmin [-c <config>] --check
karidns-webadmin [-c <config>] --create-admin <name> [--bootstrap-conninfo-file <file>]
karidns-webadmin --version | -h | --help
```

## DESCRIPTION

`karidns-webadmin` (0.6.0, items D and E) is a Node.js service that lets authenticated principals look at, and change, the zones of a PowerDNS 5.1 database that [`karidns(8)`](karidns.md) serves through [`karidns-dbloader(8)`](karidns-dbloader.md). It is the one place that knows **who may do what**: users and groups, three kinds of grant (global master, domain master, subdomain master) and the record policies they carry. A browser front end (item F) and automation (API tokens) are clients of the same API.

**What this version has.** Authentication (password, TOTP, sessions, API tokens, CSRF protection, lockout, rate limits); users, groups, nested groups, record policies and grants with the no-escalation rule; the list of datasets and zones a principal may see, zone information, the RRsets of a zone (paged), the export of a zone as a zone file, the audit log, the status of the servers, `/health` and `/version`; and the **write side**: change sets (`PATCH .../rrsets`, with a dry run, preconditions and the permission check of the whole diff), zone creation, update and deletion, the import of a zone text, the reload ("update") button, the zone metadata the API may write, DNSSEC (the DS records of a signed zone, key requests for the signer) and the hourly sweep of expired sessions; and the **history of a zone** (item E): the versions every change set leaves, the diff of two versions or of a version and the zone, the rollback to a version (a change set of its own), the marker for changes made outside the versions, and **zone templates** (global masters write them, everyone reads them; a zone is made from one, or one is applied to a zone).

Zone data is read by the service itself (SQL, one page at a time) and exported and written by [`karidns-zone`](karidns-zone.md); the other programs it runs are `karicheck` (a version check) and, on SQLite3, `karictl` (the reload, with a restricted control key). It never talks to a DNS server in any other way.

It is an ordinary process (no Capsicum): it runs as its own user, `karidns-webadmin`. Every request is hostile input: the validators refuse what they do not know, every SQL value is a bound parameter, a name that reaches a program's argument list was checked first, and no shell is involved.

### Two databases, two models

| | PostgreSQL | SQLite3 |
|---|---|---|
| connection | the role `karidns_api` ([`db/karidns_api_role.pgsql.sql`](karidns-dbloader.md)), through a pool | the zone file with the auth file attached as `auth` (one connection) |
| who checks | the API, **and** row level security: every statement runs with `karidns.principal` set, and the policies check each row again | **the API only**. SQLite3 has no roles: whoever can write the files can do anything. This is the weaker model of the release plan (4.17); the files are the credential (below) |
| the first administrator | `--create-admin` needs the connection of the table owner (`--bootstrap-conninfo-file`): the API role cannot make the first user | `--create-admin` writes the auth file |
| zone export | as the check role (it reads a whole zone) | the same file |

If row level security refuses a statement that the API had allowed, that is a bug in the API: the answer is 500, the log says `row level security refused what the API allowed (a bug)` with the request id. The tests look for that line.

## OPTIONS

`-c`, `--config FILE`
: The configuration file (default `/usr/local/etc/karidns/karidns-webadmin.conf`).

`--check`
: Reads the configuration, checks the files and their modes, the versions and JSON schema numbers of `karidns-zone` and `karicheck`, and the database (schema version 3, every table the API uses), then exits: 0 = fine, 1 = a problem (one line each on standard error).

`--create-admin NAME`
: Makes a user NAME with a `global_master` grant and the record policy `all-types` (every record type `karidns-zone` accepts in a change file; the DNSSEC types are never in a policy), with a random password that is printed **once**. No default account exists. Run it once, as the service user. If `require-totp` is `global` or `all`, the first login has to enrol a TOTP device (below).

`--bootstrap-conninfo-file FILE`
: PostgreSQL only, with `--create-admin`: the connection of a role that row level security does not bind (the owner of the tables). The file has the rules of every connection file (below).

`-v`, `--version`, `-h`, `--help`
: Print the version, or the usage.

Signals: `SIGTERM` and `SIGINT` finish the requests that are running and stop. `SIGHUP` reads the configuration again: the rates, the session times, `require-totp`, `public-origin`, `trusted-proxy` and `scrypt-ln` change; the database, the datasets and the listen address do not (restart for those).

## SETUP

The packages, the roles, the first administrator, TLS and the day-to-day operation are described step by step in the **[service manual](karidns-webadmin.md)**; this is the short form.


PostgreSQL (the owner of the tables does all of this once):

```text
psql -f db/karidns_ext.pgsql.sql karidns                                     # schema version 3 (the auth schema too)
psql -v role=karidns_api -v schema=public -f db/karidns_api_role.pgsql.sql karidns
psql -v role=karidns_check -v schema=public -f db/karidns_check_role.pgsql.sql karidns
printf 'host=/var/run/postgresql dbname=karidns user=karidns_api\n' > /usr/local/etc/karidns/api.conninfo       # 0600, owner karidns-webadmin
printf 'host=/var/run/postgresql dbname=karidns user=karidns_check\n' > /usr/local/etc/karidns/check.conninfo   # likewise
karidns-webadmin --create-admin admin --bootstrap-conninfo-file /usr/local/etc/karidns/owner.conninfo
karidns-webadmin --check
```

SQLite3: apply `db/karidns_ext.sqlite3.sql` and `db/karidns_audit.sqlite3.sql` to the zone file, create the auth file (`sqlite3 /var/db/karidns/auth.sqlite3 < db/karidns_auth.sqlite3.sql`, owned by `karidns-webadmin`, **mode 0600**: it holds the password hashes, and `--check` refuses a wider mode), then `--create-admin` and `--check`. The loader must not be able to read the auth file. The zone file needs to be readable and writable by the API user (SQLite3 opens it read-write even to read: WAL mode).

The server listens on `127.0.0.1` or a UNIX socket (mode 0660). TLS is the job of a reverse proxy in front (relayd, nginx): set `trusted-proxy` to its address (`local` for a UNIX socket) so that the rate limits and the log see the real client, `public-origin` to the https origin a browser uses, and let the proxy forward `/api/` only. A non-loopback `listen` needs `tls-cert` and `tls-key` (TLS 1.2 or newer); the configuration check refuses plain HTTP anywhere but on loopback.

**Reloading with SQLite3.** A SQLite3 database has no reload requests, so the API asks the server over the control channel, with a key that can do **nothing but `reload-zone`** (it may reload one named zone and read the status; a full-power key must never sit in the web tier):

```text
# karidns.conf
key "webadmin" { algorithm hmac-sha256; secret "..."; };            # a secret of your own: karictl tsig-keygen
control-channel { socket "/var/run/karidns/control.sock"; keys { "webadmin" read-only yes allow-commands { reload-zone; }; }; ... };
# /usr/local/etc/karidns/webadmin-karictl.conf (owner karidns-webadmin, mode 0600); karictl-config points here
socket "/var/run/karidns/control.sock";
key "karictl" { algorithm hmac-sha256; secret "..."; };            # the same secret
```

The control socket must be reachable by the service user, so the API runs on the host of the DNS server (it must anyway: the SQLite3 file is local). PostgreSQL needs none of this: the reload is a row in `karidns_reload_requests`.

Back up the auth file (SQLite3) or the `karidns_auth` schema (PostgreSQL) with the zone data, and keep the **TOTP key file** with it: without that key the TOTP secrets in the database cannot be read and every TOTP user must enrol again.

## CONFIGURATION FILE

Lines are `key = value`; `#` starts a comment; a value may be in double quotes; sections `[dataset <name>]` come last. Durations are a number with an optional unit `s m h d w` (a bare number is seconds). An unknown key, a key set twice or a value that does not fit is an error that names the line. A sample is in `karidns-webadmin.conf.sample`.

| Key | Default | Meaning |
|---|---|---|
| `listen` | (required) | `host:port`, `[ipv6]:port` or the absolute path of a UNIX socket. Plain HTTP only on loopback or a socket |
| `tls-cert`, `tls-key` | | built-in TLS (both or neither; TLS 1.2 or newer). `tls-key` is checked like a connection file: the service user's, mode 0600 or 0400 |
| `public-origin` | (required) | the origin a browser sees, `https://dns.example.test` (`http://` only for localhost). Unsafe requests with a cookie must carry exactly this `Origin` |
| `trusted-proxy` | | comma separated addresses of proxies; only from them is `X-Forwarded-For` believed (the first address from the right that is not a proxy is the client). `local` names the peer of a UNIX socket, which has no address |
| `database` | (required) | `pg` or `sqlite3` |
| `api-conninfo-file`, `check-conninfo-file` | | PostgreSQL: the connection files of the API role and of the check role (both required) |
| `sqlite-file`, `auth-file` | | SQLite3: the zone file and the auth file (both required) |
| `karidns-zone`, `karicheck`, `karictl` | `/usr/local/bin/...` | the programs |
| `karictl-config` | | SQLite3: the `karictl` configuration (mode 0600, owned by the service user) of a **restricted control key**, `read-only yes` with `allow-commands { reload-zone; }` in the control channel of `karidns.conf` ([`karidns(8)`](karidns.md), "Restricted control keys"): the API reloads one named zone with it, nothing else. Without it a SQLite3 deployment cannot reload from the API |
| `workers` | min(4, CPUs) | the pool of tool runs (`karidns-zone`, `karictl`): at most this many at a time, 64 more may wait, then 503 |
| `reload-after-change` | no | the default of `reload` in a change set, an import and a zone deletion. SQLite3 needs `karictl-config` for it |
| `require-totp` | `global` | who must use TOTP: `global` (every global master), `all`, `none` |
| `session-idle`, `session-max` | `30m`, `12h` | idle time and absolute life of a session |
| `totp-key-file` | `/var/db/karidns-webadmin/totp.key` | the AES key of the TOTP secrets (64 hex digits, mode 0600), made at the first start |
| `rate-login` | 5 | login attempts a minute, per address and per user name |
| `rate-api`, `rate-write` | 20, 2 | requests a second (burst twice that) per principal, and writes a second |
| `scrypt-ln` | 17 | the cost of a new password hash (2^n; 14 to 20; about 128 MiB at 17) |
| `ui` | yes | serve the files of the web interface under `/` and `/ui/` (below, "THE WEB INTERFACE"); `no` serves only `/api/v1/` |
| `ui-dir` | `webadmin/ui` of the installation | the directory of the files of the web interface (absolute); read once at the start. Not with `ui = no` |
| `log` | `stderr` | `stderr` or a syslog facility (through `logger(1)`) |
| `[dataset NAME]` `schema`, `views` | | PostgreSQL: a dataset is a schema of zone tables (default one dataset `main` in `public`); SQLite3 has the one dataset `main` |

Connection files (`api-conninfo-file`, `check-conninfo-file`, `--bootstrap-conninfo-file`) must be regular files owned by the user the service runs as, mode 0600 or 0400; the keywords `host`, `port`, `dbname`, `user`, `password`, `sslmode`, `connect_timeout` and `application_name` are understood, any other is an error.

## AUTHENTICATION

A request carries **either** a session cookie (a browser) **or** `Authorization: Bearer kdt_<id>_<secret>` (automation), never both (400). Without one: 401, except `/health` and `/auth/login`.

**Passwords** are scrypt hashes (`$scrypt$ln=17,r=8,p=1$...`, `node:crypto`; no package); `$argon2id$` hashes made elsewhere are verified where Node has argon2 (24.7 or newer) and its OpenSSL has the algorithm (OpenSSL 3.2 or newer: not FreeBSD 14, whose base OpenSSL is 3.0); elsewhere such a hash never matches. A password has at least 12 characters and does not contain the user name. Hashing runs two at a time (about 128 MiB each); more than 64 waiting is a 503.

**Login** (`POST /auth/login {user, password, totp}`) answers the same 401 `invalid-credentials` for an unknown user, a wrong password, a disabled user, a group, a locked account and a wrong code, and does the same amount of work for each. Ten failures in a row lock the account for 15 minutes, twice as long for every further failure, a day at most; a success resets the count. The session cookie is `karidns_session` (256 random bits; the database holds only their SHA-256), `HttpOnly; SameSite=Strict; Path=/api/` and `Secure` when `public-origin` is https. The answer carries the CSRF token.

**Sessions** end after `session-idle` without a request, after `session-max`, on logout (`POST /auth/logout`, `{"all": true}` ends the other sessions too), when the user is disabled or deleted, and when the password is reset by an administrator. A session is replaced by a new one (new id) at the login and when TOTP is confirmed.

**CSRF.** An unsafe request (POST, PUT, PATCH, DELETE) with a cookie needs the header `X-KariDNS-CSRF: <token>` (from the login answer or `GET /auth/me`) **and** `Origin: <public-origin>`; otherwise 403 `csrf`. The body must be `application/json`. Bearer tokens are not ambient and need neither.

**TOTP** (RFC 6238, SHA-1, 6 digits, 30 s, one step either way). `POST /auth/totp {"action":"enroll"}` returns the secret (base32) and an `otpauth://` URI; `{"action":"confirm","code":"123456"}` switches it on and replaces the session; `{"action":"disable","password":...,"code":...}` switches it off where `require-totp` allows. With `require-totp = global` (the default) a global master's first login gets a session that can only call `/auth/*` until it has enrolled (`totp.enrollment_required` in the login answer; other routes answer 403 `totp-required`). Afterwards a login needs `totp`. A code is accepted once: the step is remembered. The secret is stored encrypted (AES-256-GCM under the key file, bound to the user).

**API tokens.** `POST /tokens {name, read_only, days (1 to 365, default 90), principal}` returns `token` **once**; the database holds the SHA-256 of the secret. A token acts as its principal with that principal's grants; a read-only token can only GET. Tokens cannot make tokens, change passwords or TOTP (a login session is needed). A global master may make a token for another principal (a service account is a user without a password). Disabling a user revokes its tokens.

**Rate limits** (token buckets in memory, one process): logins per address and per user name (`rate-login` a minute), requests with bad credentials per address (the same bucket), requests per principal (`rate-api`) and writes (`rate-write`). Over the limit: 429 with `Retry-After`. Behind a proxy without `trusted-proxy` every client has the address of the proxy.

## PERMISSIONS

A **principal** is a user or a group; groups nest (at most 8 deep, no cycle); a **tenant** is a group that is in no group. A **grant** gives a principal (a user or a group, whose members inherit it) a role and a **record policy**:

| Role | Scope |
|---|---|
| `global_master` | every zone of every dataset |
| `domain_master` | one zone (dataset + zone name) |
| `subdomain_master` | the names at or below a suffix of one zone (label boundary: `sub.example.test` covers `a.sub.example.test`, not `evilsub.example.test`) |

A **policy** (`rr_policy`) lists the record types allowed (never the DNSSEC types, which belong to the signer), whether wildcard names, delegations (NS below the apex) and DNAME are allowed, whether the zone apex may be edited, the TTL range, and `max_rr`. An SOA record is only writable by a global master whose policy allows SOA and the apex. A disabled user or group has no rights. These are the rules of `karidns_auth.rr_ok` / `rr_visible` in the database, written a second time in `webadmin/lib/perm.js`; `tests/auth_vectors.json` holds cases that both must answer alike, and both are tested against it.

**Seeing.** A zone without a grant does not exist for a principal: 404, not 403, whether it exists or not. A domain master reads the whole zone; a subdomain master reads the names under its suffix and the apex SOA and NS.

**Writing.** A change set is allowed when **one grant** allows every RRset of it: the old records and the new ones (a record whose TTL is outside the policy cannot be removed either), the type, the wildcard / delegation / DNAME / apex rules, the TTL range and `max_rr` (the records in the scope of the grant after the change). Only a global master writes an SOA record; the serial of a zone is raised by the API for everybody. Creating and deleting zones, zone attributes and metadata are for global masters; the import is for the masters of the whole zone; DNSSEC key requests for domain and global masters. The rules are applied twice: by the API on the diff `karidns-zone` found (and, before the tools run, on the request itself), and on PostgreSQL by row level security on every row written.

**No escalation.** Everyone reads principals, groups, memberships and policies (their names are needed to grant); only global masters write them. A **domain master** may make and remove grants of its own zone for any principal, as domain master or subdomain master, **with a policy no wider than its own** (types a subset, no flag it has not, TTL range inside, `max_rr` not higher, no limit counts as widest); a subdomain master grants nothing; a global master anything. A grant is seen by its holder, by the members of a holding group and by the domain master of its zone. On PostgreSQL a trigger of the database checks the same rule again.

## CONVENTIONS

Base path `/api/v1`; JSON (`application/json; charset=utf-8`), UTF-8, every document has `"api": 1`. Names are absolute with the final dot (`www.example.test.`), canonical (lower case); in a request the dot may be left out. Zone names are plain LDH names (letters, digits, `-`, `_`); an owner name may also hold `*` as a whole label and `/`; no backslash escapes, no non-ASCII (use the A-label). Unknown fields in a request are refused (400, with a JSON pointer), so a typo is not ignored. Request bodies are limited to 1 MiB (the login to 16 KiB; an import and the creation of a zone from a text to 16 MiB); headers to 16 KiB; the body of a request has 30 seconds to arrive (408 after that; an import 300 seconds). Responses carry `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'` and an `X-Request-Id` (the files of the web interface have their own policy, "THE WEB INTERFACE" below). A query parameter that is a flag takes `true`, `false`, `1` or `0`.

**Lists** take `?limit=` (1 to 500, default 100) and `?cursor=` (opaque, from `next_cursor` of the previous page; `null` at the end). A page of the audit log may hold fewer rows than `limit` when the principal may not see some; follow `next_cursor`.

**Errors** are RFC 9457 problem documents (`application/problem+json`): `type` (`urn:karidns:api:<code>`), `title`, `status`, `detail`, `request_id` and, for a mistake in a request, `errors[]` with `{code, severity, text, pointer}`. A 500 carries the request id and nothing else; the log has the rest.

| Status | Codes |
|---|---|
| 400 | `bad-request`, `malformed-json`, `both-credentials`, `weak-password`, `no-session` |
| 401 | `unauthenticated`, `invalid-credentials`, `totp-required` (at login: a code is needed) |
| 403 | `forbidden` (the role may not; a change that no single grant allows), `max-rr`, `escalation` (grant wider than the granter's), `csrf`, `totp-required` (session without the second step), `totp-required-by-policy`, `read-only-token`, `session-only`, `wrong-password`, `wrong-code` |
| 404 | `not-found` (also: no grant on the zone) |
| 405, 413, 415 | `method-not-allowed`, `too-large`, `unsupported-media-type` |
| 408 | `request-timeout` (the body did not arrive in time) |
| 409 | `exists`, `in-use`, `refused` (a rule of the schema: a cycle of groups, ...), `self`, `not-a-group`, `not-a-user`, `no-password`, `totp-enabled`, `totp-disabled`, `no-enrolment`; the write side: `changed`, `precondition-failed`, `zone-not-editable`, `presigned-zone`, `tagged-rrset`, `signer-managed`, `signer-zones`, `unsupported`, `not-a-catalog`, `request-pending`, `already-signed`, `not-signed`; versions and templates: `version-conflict` (a rollback finds RRsets changed after the versions it undoes), `delta-incomplete` (a version in the range was too big to keep its RRsets), `too-large` (the range holds more RRsets than a fold reads), `cannot-restore` (the history holds something that cannot be written back), `template-invalid` (a record of a stored template is not fit to be copied) |
| 422 | `constraint`, `zone-checks-failed`, `refused`, `template-checks-failed` (karicheck refuses a template) |
| 429 | `rate-limited` (`Retry-After`) |
| 503 | `busy` (`Retry-After`), `database-unavailable`, `reload-failed` |
| 500 | `internal` |

## ENDPOINTS

All paths are relative to `/api/v1`. "Global" means a global master.

### Service

| | |
|---|---|
| `GET /health` | no login. `{"status":"ok","database":"ok"}`, or 503 when the database does not answer within 3 seconds |
| `GET /version` | login. `{version, tools, datasets, types, ui}`: the version, the versions of `karidns-zone` and `karicheck`, the datasets, `types` (the record types a change set takes, sorted, as `karidns-zone --types-list` names them; `null` when the service did not ask) and `ui`, what a client (the web interface) follows: `{reload_after_change, require_totp (global\|all\|none), max_rrsets (1000), max_records (1000, an RRset), zone_text_limit (16777216 octets: a zone text in an import or a zone creation)}` |

### Login and self

| | |
|---|---|
| `POST /auth/login` | `{user, password, totp?}` -> `{principal, csrf, expires_at, totp:{enabled, enrollment_required}}` and the cookie |
| `POST /auth/logout` | `{all?}` -> 204 |
| `GET /auth/me` | the principal, its groups and tenants, its effective grants with their policies, `capabilities` (`global`, `manage_principals`, `manage_policies`, `create_zones`, `grant_on`: the zones it may grant on), and the session (`csrf`, `totp_ok`, `expires_at`, `idle_timeout`) or the token (`read_only`) |
| `POST /auth/totp` | `{action: enroll\|confirm\|disable, code?, password?}` |
| `POST /auth/password` | `{current, new, all?}`; `all` ends the other sessions |
| `GET /tokens` | own tokens (no secrets); `?principal=ID` or `?all=true`: global |
| `POST /tokens` | `{name, read_only?, days?, principal?}` -> 201, `{token, info}` |
| `DELETE /tokens/{id}` | revoke (own, or global) |

### Principals, policies, grants

| | |
|---|---|
| `GET /principals` | `?kind=user\|group`, `?prefix=` |
| `POST /principals` | global. `{kind, name, display_name?, email?, password? (users), disabled?}`. Names: letters, digits, `. _ @ + : -`; unique whatever the case |
| `GET /principals/{id}` | the principal, its groups; `credentials` (password set, TOTP on, failed logins, locked) for global and for oneself |
| `PATCH /principals/{id}` | global. `{name?, display_name?, email?, disabled?}`. Disabling ends the sessions and revokes the tokens; one cannot disable oneself |
| `DELETE /principals/{id}` | global; not oneself |
| `PUT /principals/{id}/password` | global. `{password}`: the user's sessions end |
| `POST /principals/{id}/credentials` | global. `{action: reset-totp\|unlock}` -> `{credentials:{password, totp_enabled, failed_logins, locked}}` as `GET /principals/{id}` shows them. `reset-totp`: TOTP is off, the secret is deleted, the user's sessions end (a global master enrols again at the next login where `require-totp` says so); not for oneself (409 `self`: switch it off from the account, `POST /auth/totp`), 409 `totp-disabled` when there is nothing to reset (a started enrolment counts). `unlock`: the count of failed logins and the lock go, the password stays. A group (409 `not-a-user`) and a user without a password (409 `no-password`) have no credentials. The credentials triggers of the database write the audit rows (the secret is redacted) |
| `GET /principals/{id}/members`, `POST` `{member}`, `DELETE /principals/{id}/members/{mid}` | members of a group (POST and DELETE: global) |
| `GET /rr-policies`, `GET /rr-policies/{id}` | |
| `POST /rr-policies`, `PATCH`, `DELETE` | global. `{name, allowed_types[], allow_wildcard, allow_delegation, allow_dname, apex_editable, ttl_min, ttl_max, max_rr}`. Types are upper-cased; DNSSEC and meta types are refused with a pointer; a policy in use is not deleted (409) |
| `GET /grants` | `?principal=ID`, `?zone=` (what the principal may see, above) |
| `POST /grants` | `{principal, role, dataset?, zone?, suffix?, policy}`: `global_master` has none of `dataset`, `zone`, `suffix`; `domain_master` needs `zone`; `subdomain_master` needs `zone` and `suffix` (at or below the zone). Escalation: 403 |
| `DELETE /grants/{id}` | global, or the domain master of the zone for a grant it could make; a grant one cannot see is 404 |

### Zones

| | |
|---|---|
| `GET /datasets` | `[{name, driver, schema?, views}]` |
| `GET /datasets/{ds}/zones` | the zones the principal has a grant on: `{name, kind, serial, presigned, signer, catalog, role}`. `?prefix=`, `?contains=` (a part of the name, any case: a scan of the zones the principal sees), `?kind=NATIVE\|MASTER\|SLAVE\|PRODUCER\|CONSUMER`, `?signed=true\|false`; ordered by name |
| `GET /datasets/{ds}/zones/{zone}` | kind, serial, catalog, masters, `generation` (grows with every change of the zone's rows, by any writer), `changed_at`, views, `presigned`, `signer` (signed by `karidns-signer`), `nsec3param`, `signer_state`, `waiting_for_signer` (the signer has not signed the current serial yet), the last reload request (PostgreSQL), the principal's role and grants on it |
| `GET /datasets/{ds}/zones/{zone}/rrsets` | `?name=`, `?type=`, `?from=`, `?contains=`, `?rdata=1`, `?limit=`, `?cursor=`: `{rrsets:[{name, type, ttl, tagged, records:[{content, disabled, ttl, rdata?}]}]}` in (name, type) byte order, **at most `limit` RRsets** a page (the records of an RRset are never split). `ttl` is the lowest of the records (RFC 2181 section 5.2). `content` is the stored content; MX and SRV carry their priority in front, as in a zone file; names inside are as stored (PowerDNS stores them without the final dot). **`tagged`** is true for an RRset with a location / ECS tag or a tinydns attribute: it is read-only here (409 `tagged-rrset` on a change). **`?from=`** starts the list at the first owner that is `>=` the text (stored form: lower case, no final dot, compared byte for byte as the order is; a text that is not a name of the zone is fine), an index range, cheap, and `next_cursor` goes on from there. **`?contains=`** lists only the owners that have the text in them (any case; letters, digits and `. _ * / -`), a scan of the zone, at most `limit` RRsets a page and `next_cursor` as usual; with `from` both apply. **`?rdata=1`** (or `true`) adds `rdata` to every record: the record as a change set takes it (below, "Reading and sending back"), or `null` for a record that has no such form |
| `GET /datasets/{ds}/zones/{zone}/export` | `text/plain`: the zone as a zone file in canonical order, as `karidns-zone export` writes it (what the server serves). For the masters of the whole zone (global, domain master); 403 for a subdomain master |

### Changing zones

| | |
|---|---|
| `PATCH /datasets/{ds}/zones/{zone}/rrsets` | a **change set**: RRsets replaced or deleted, one zone, one request (below). Any principal whose grants allow every RRset of it |
| `POST /datasets/{ds}/zones` | global. Makes a zone: `{name, type?, soa:{mname, rname, serial?, refresh?, retry?, expire?, minimum?, ttl?}, nameservers[], ns_ttl?, rrsets[]?, comment?, dry_run?, reload?}` or `{name, type?, zone_text, ...}`, or from a template (`template` by name or `template_id`, below: then `soa` and `nameservers` are optional). 201 with the document of a change set and `Location`. The serial is the day, `YYYYMMDD00`, unless given |
| `PATCH /datasets/{ds}/zones/{zone}` | global. `{catalog?, views?}`: the PRODUCER zone whose catalog the zone is in (`null`: none), the views of the dataset (`dataset` sections of the configuration) the zone is in |
| `DELETE /datasets/{ds}/zones/{zone}` | global. `{confirm: "<the zone's name>", reload?}`: the zone, its records, metadata, keys, versions and the grants on it |
| `POST /datasets/{ds}/zones/{zone}/import` | a domain master or global master. `{zone_text, mode?: replace\|merge, comment?, dry_run?, reload?}` (below) |
| `POST /datasets/{ds}/zones/{zone}/reload` | the "update" button: any grant on the zone. PostgreSQL: a row in `karidns_reload_requests`, every server on the database reloads the zone. SQLite3: `karictl reload` with the restricted key |
| `POST /datasets/{ds}/reload` | global, PostgreSQL: a reload request for every zone of the dataset. 409 `signer-zones` while a zone of the dataset is kept signed by the signer (a reload of every zone would publish its unsigned changes); 409 `unsupported` on SQLite3 |
| `GET /datasets/{ds}/zones/{zone}/metadata` | `{metadata:[{kind, content[]}], writable[]}`: every kind the zone has; `writable` lists the kinds the API writes |
| `PUT /datasets/{ds}/zones/{zone}/metadata/{kind}`, `DELETE ...` | global. `{content: [..]}` replaces the values of the kind (an empty list, or DELETE, removes it). Only `ALLOW-AXFR-FROM`, `ALLOW-DNSUPDATE-FROM`, `TSIG-ALLOW-AXFR`, `TSIG-ALLOW-DNSUPDATE`, `ALSO-NOTIFY`, `X-KARIDNS-PROFILE`, `X-KARIDNS-ECS-TRUSTED-RESOLVERS`, each value checked by the rules of the loader (an address or prefix, a key name, ...). Never `PRESIGNED`, `NSEC3PARAM`, `X-KARIDNS-SIGNER` or `X-KARIDNS-FORMAT` (the signer's and the importer's) |
| `GET /datasets/{ds}/zones/{zone}/dnssec` | for the masters of the whole zone. `{dnssec:{signed, signer, presigned, nsec3param, signer_state, waiting_for_signer, serial, keys[], ds[], cryptokeys[], requests[]}}`. `keys` are the DNSKEY records with their key tags, `ds` the DS records to put in the parent zone (digest types 2 and 4, RFC 4034 section 5.1, RFC 4509, RFC 6605) for the keys with the SEP bit, computed from the public keys in the zone (`cryptokeys.content` is never read) |
| `POST /datasets/{ds}/zones/{zone}/dnssec/requests` | a domain master or global master. `{kind: enable\|add, algorithm? (8, 10, 13, 14, 15, 16; default 13), bits? (RSA), key_type? (csk\|ksk\|zsk; default csk), nsec? (nsec3\|nsec; enable)}`: asks `karidns-signer` to start signing the zone, or for one more key. 201 with the request (`state: pending`; the signer answers it). One request per zone at a time |

### Versions

Paths are `/datasets/{ds}/zones/{zone}/...`. Any principal with a grant on the zone reads them (a subdomain master sees the part of each delta under its suffix, and the apex SOA and NS). Details below, "Versions and rollback".

| | |
|---|---|
| `GET .../versions` | `?limit=`, `?cursor=`. Newest first: `{versions:[{version, kind (create edit template import rollback), at, principal:{id, name}\|null, db_role, change_set, comment, serial:{before, after}, generation:{before, after}, rollback_of, delta_complete, rrsets, changed_outside_before}], changed_outside_since, next_cursor}`. `rrsets` is the number of RRsets the version changed (as far as the principal sees them). The two `changed_outside_*` fields are for the masters of the whole zone only (below) |
| `GET .../versions/{n}` | `?limit=`, `?cursor=`. `{version, rrsets:[{name, type, change: add\|replace\|delete, before:[{ttl, content}]\|null, after:[...]\|null}], next_cursor}`: the delta of version n |
| `GET .../versions/{a}/diff` | `?to={b}` (a later version) or `?to=current` (the default), `?limit=`, `?cursor=`. `{from, to, rrsets:[...], next_cursor}`: for every RRset the versions after a touched, its records at a (`before`) and at b or now (`after`); the same at both ends: not listed |
| `POST .../versions/{n}/rollback` | `{comment?, dry_run?, force?, reload?}`: a change set that restores the zone's RRsets to their state at version n. Any principal whose grants allow the whole change set |

### Templates

| | |
|---|---|
| `GET /templates` | `?prefix=`, `?limit=`, `?cursor=`. Everybody: `{templates:[{id, name, description, revision, soa, created_by, updated_at, record_count}]}` |
| `GET /templates/{id}` | everybody: the same with `records:[{owner, type, ttl, content}]` |
| `POST /templates` | global. `{name, description?, soa?:{mname, rname, refresh, retry, expire, minimum}, records?:[{owner, type, ttl?, content}], dry_run?}` -> 201. The records are checked by `karicheck` first |
| `PATCH /templates/{id}` | global. Any of `name`, `description`, `soa` (`null` clears it), `records` (the whole list), `dry_run`. The revision grows |
| `DELETE /templates/{id}` | global -> 204 |
| `POST /templates/{id}/validate` | everybody: the stored template through `karicheck` again: `{template:{id, name, revision}, valid, messages:[{code, severity, text, pointer?}]}` |
| `POST /datasets/{ds}/zones/{zone}/apply-template` | `{template \| template_id, default_ttl?, comment?, dry_run?, reload?}`: a change set of REPLACE operations. Any principal whose grants allow the whole change set (below) |

### Audit and servers

| | |
|---|---|
| `GET /audit` | newest first. `?zone=`, `?principal=ID`, `?change_set=`, `?table=`, `?since=`, `?until=` (ISO 8601). `{audit:[{id, at, source, principal_id, principal, db_role, change_set, schema, table, op (I U D), zone, row_id, before, after}]}`. A global master reads all; a domain master the rows of its zones (data rows and the grants made on them); others none. Secrets are `"<redacted>"` in the log itself. `source` is `audit` (PostgreSQL), or `zone` / `auth` (SQLite3: the two files) |
| `GET /servers` | PostgreSQL: per dataset and server the generation applied, whether every zone loaded, and the zones that did not (lines filtered to the zones the principal has a grant on). SQLite3: empty, with a note (ask the server with `karictl status`) |

## CHANGE SETS

`PATCH /datasets/{ds}/zones/{zone}/rrsets` changes the RRsets of one zone in one request and one transaction:

```json
{ "comment": "move www", "dry_run": false, "reload": false,
  "rrsets": [
    { "name": "www.example.test.", "type": "A", "changetype": "REPLACE", "ttl": 300,
      "records": [ { "content": "192.0.2.10" }, { "content": "192.0.2.11" } ],
      "expect": [ { "ttl": 3600, "content": "192.0.2.1" } ] },
    { "name": "old.example.test.", "type": "TXT", "changetype": "DELETE" } ] }
```

`REPLACE` puts the records in the place of the RRset (all of them, or it is new); `DELETE` removes the RRset. At most 1000 RRsets, 1000 records an RRset, an RRset once. A name is in the zone (at a label boundary); a type is one `karidns-zone --types-list` names (never the DNSSEC types: the signer's); the text of a record has no control character, no `;` or parentheses outside quotes and does not begin with `$` (the zone checks decide what it means). **`expect`** (optional) is the RRset as the client saw it, the records with their TTLs; an empty list means "must not exist". Without a match the answer is 409 `precondition-failed` with the RRset as it is (`errors[].current`) and nothing is written. The comparison is made with the canonical form `karidns-zone` writes (`GET .../rrsets` shows `content` as stored, which for names and for MX / SRV reads differently: take the text from `GET .../rrsets?rdata=1`, "Reading and sending back" below, or from the `diff` of a dry run).

**Reading and sending back.** The `content` of a record in `GET .../rrsets` is the stored PowerDNS text (names without the final dot, which a change set reads as relative to the zone: `10 mail.example.test` sent back would become `mail.example.test.example.test.`). With **`?rdata=1`** every record also has **`rdata`**: the record as `karidns-zone` writes it in a diff, which is exactly what a change set takes as the `content` of a record in `records` and in `expect` (and what a diff or a version shows). Every name in it is absolute (`10 mail.example.test.`; the root name is `.`), the priority of MX and SRV is in front, strings are quoted and escaped as the zone-file writer does (`"v=spf1 -all"`, a TAB as `\009`), an address is as it was written. A client that reads an RRset, changes it and sends it back with `expect` built from what it read gets no difference where it changed nothing (`tests/run_webadmin_write_test.sh` reads every RRset of `webadmin/test/rt.test.zone`, sends it back with its own records as `expect` and finds no difference). **The SOA is the exception**: a change set that names the SOA RRset writes it with the next serial, so sending it back unchanged is a change (the serial grows) and an `expect` on it never matches; a client leaves the SOA out unless it means to edit it (only a global master may). `rdata` is made by `karidns-zone render`, which reads each stored record through the loader's reader and writes it with the zone-file writer, and gives a text only when that text reads back as the same record; one run for a page. It is **`null`** for a record that has no such form: one the reader refuses (the zone would not load either), a type that has no text of its own (PowerDNS `ALIAS` and `LUA` are shown as stored), a text that does not read back as the same record, a text a change set would refuse (longer than 65535 octets), a content that cannot be framed (a line feed, a NUL, empty). A client then shows `content` and leaves that RRset alone. A `karidns-zone` that cannot be run or does not answer is a 500 (the log says why); the service checks at the start that `karidns-zone render` exists.

**What happens.** (1) The request is checked against the principal's grants (a refusal names the RRset: `errors[].pointer`, `/rrsets/3`); it cannot be used to find out what an RRset outside the scope holds. (2) The **check run**: `karidns-zone apply --dry-run` in a trusted session (PostgreSQL: the check role; it sees the whole zone, which a subdomain master's session does not) applies the change in a transaction, runs the zone checks of `karicheck zone` and reads the zone back through the loader's reader, and rolls back; the answer is the **diff** (each RRset that changes, with its records before and after, in canonical form) and the **generation** of the zone. (3) **One grant must allow the whole change set**: the types, TTLs, wildcard / delegation / DNAME / apex rules of its policy for every RRset of the diff, for the records removed as well as the records written (the policies of the database check each row again), and `max_rr` (the records in the scope of the grant after the change: the zone for a domain master, the names at or below its suffix for a subdomain master). Two grants that each cover half are not enough. (4) The **commit run**: `karidns-zone apply` as the API's role, against the generation of the check run, for the principal and a new change set id (a UUID), with the narrow read-back (`--readback changed`). The SOA serial is raised by one when the change set wrote no SOA of its own (RFC 1982 section 3.1). The RRsets of the change set that already equal the zone's are not written again. (5) If the zone changed in between (any writer, the signer included: the generation is a counter of the owner's triggers) the commit run writes nothing and exits with 3: the API starts again from (2), three rounds at most, with a short random pause, and then answers 409 `changed`. (6) The reload.

**Answer** (200): `{change_set, committed, changed, version, generation:{before, after}, serial:{before, after}, records:{before, after}, diff:[{name, type, change: add|replace|delete, before:[{ttl, content}]|null, after:[...]|null}], messages:[{code, severity, text, pointer?}], reload}`. A change set that changes nothing is `committed: false` and writes nothing (no version, no new serial). `reload` is `not requested`, `requested`, `waiting for the signer` or `failed: ...` (the change is in the database; the server serves the old version until it is reloaded).

**Dry run** (`dry_run: true`): the answer after (3): `{dry_run: true, allowed, diff, version (the number it would have), generation, serial, messages}`; when no grant allows it, `allowed: false` and `denied: {text, pointer}` instead of an error (the diff of a change that is not allowed is not shown).

**Errors.** 400 for a request that is not well formed (with the JSON pointer); 403 `forbidden` (names the first RRset that no grant allows, or says that no single grant allows them all) and `max-rr`; 404 for a zone the principal has no grant on; 409 `zone-not-editable` (a SLAVE, CONSUMER or PRODUCER zone), `presigned-zone` (signed elsewhere: an edit would publish records without valid signatures; sign elsewhere and import with `karidns-zone`), `tagged-rrset` (an RRset with location / ECS tags or tinydns attributes is edited with `karidns-zone`, not here), `precondition-failed`, `changed`; 422 `zone-checks-failed` with the messages of the zone checks and their codes ([`karicheck(1)`](karicheck.md)), each pointing at the record that caused it; 503 `busy` (the zone is locked by another writer, or the pool is full). A 500 says nothing but the request id; the log says what, and names a refusal by row level security as the bug it is.

**Reload.** Explicit by default: `reload: true` in the request (or `reload-after-change = yes`) asks for it, or the "update" button (`POST .../reload`). PostgreSQL: the commit run adds the row to `karidns_reload_requests` in its own transaction (every server reloads the zone). SQLite3: `karictl reload <zone>` (once per view the zone is in) with the key of `karictl-config`. **A zone the signer keeps signed (`X-KARIDNS-SIGNER`) is never reloaded by the API**: the loader reloads it when the signer has signed the change and asks (the zone info says `waiting_for_signer` until then); the button answers 409 `signer-managed`.

**Import.** `POST .../import {zone_text}` takes a zone file (BIND format; the plain records only: no DNSSEC records, location / ECS tags or tinydns attributes; `$INCLUDE` and `$GENERATE` are refused) and makes the zone's RRsets the text's: with `mode: "replace"` (the default) the RRsets the text does not have are deleted (not the apex SOA, nor the DNSSEC records of a signer zone), with `merge` they stay. An apex SOA that differs from the zone's in the serial only is left alone and the serial is raised as for any change set. It is a change set like the others (check run, one grant for the whole diff, commit run, version of kind `import`), for the masters of the whole zone, not for a subdomain master; a zone that has any RRset with tags is not imported into. Creating a zone from a text works the same way (`POST .../zones {name, zone_text}`).

**Deleting a zone** takes the rows with it; on SQLite3 the API deletes the child rows itself (the PowerDNS tables have no foreign keys) and the grants of the zone in the auth file; on PostgreSQL the foreign keys and a trigger do. The audit log names the principal and the change set.

**Cost** (pc200, a FreeBSD jail on a shared host; the API on the same host as the database; median of 3 to 5 requests; `tests/run_webadmin_write_test.sh` and `..._write_pg_test.sh` print them): a change set of one RRset costs two runs of `karidns-zone`, each of which reads the zone. SQLite3: a zone of about 15 records, 11 to 13 ms for a dry run and 20 to 25 ms for the check and the commit together; a zone of 20,000 records, 93 to 96 ms and 123 to 125 ms (a subdomain master: the same). PostgreSQL: 30 ms and 63 ms; 20,000 records, 127 to 134 ms and 440 to 674 ms (a subdomain master: 446 ms). A page of 500 RRsets of that zone: 20 ms (SQLite3), 240 to 283 ms (PostgreSQL, row level security; with the earlier one-statement page query, which could take seconds on a table without statistics). A zone of 100,000 records: 0.6 s (SQLite3) and 1.9 s (PostgreSQL) a change set, 40 ms and 0.16 to 0.7 s a page; memory and the other sizes are in the **MEASUREMENTS** of the [service manual](karidns-webadmin.md). The reload and the loader's work come on top. **The reads of the web interface** on the zone of 100,000 records: `?rdata=1` adds 11 to 17 ms to a page of 500 RRsets (39 ms SQLite3, 191 ms PostgreSQL without it), `?from=` costs a page, `?contains=` scans the zone (SQLite3 33 ms; PostgreSQL 742 ms for a global master, 174 to 207 ms for a domain or subdomain master); `zones?contains=` over 10,000 zones costs what `?prefix=` costs (3 ms SQLite3, 360 ms PostgreSQL).

## VERSIONS AND ROLLBACK

**What a version is.** Every change set that is committed (a `PATCH .../rrsets`, an import, the creation of a zone, a template applied, a rollback) is one **version** of its zone, written by `karidns-zone` in the transaction of the change itself, so the history is exactly as reliable as the data. Numbers are per zone, from 1. A version records who (the principal, and the database role), when, the change set (the id of the audit log's rows of the same change), the comment, the kind (`create`, `edit`, `template`, `import`, `rollback`; for a rollback `rollback_of` is the version it restores), the SOA serial and the zone generation before and after, and the **delta**: every RRset the change touched, as it was and as it is, in the canonical lines `karidns-zone` writes (`<ttl> <TYPE> <rdata>`). `karidns-zone import` and `apply` run by an operator write versions too (no principal), so the history has no silent gaps. Not versioned: the DNSSEC types (the signer's output), and a change of the SOA serial alone (every change raises it). A change of more than 10,000 RRsets is listed without its RRsets (`delta_complete: false`); no diff or rollback crosses such a version (409 `delta-incomplete`). A zone keeps its **newest 100 versions** (the audit log stays the complete record); a version that is gone is 404.

**Changes outside the versions.** A write that does not go through `karidns-zone` (`psql`, a PowerDNS tool) leaves no version. The generation of the zone grows with every writer, the signer included, so a version whose `generation.before` is higher than the `generation.after` of the one before it has something in between, and the list says what:

```json
"changed_outside_before": { "basis": "audit", "count": 2, "rrsets": [ {"name": "www.example.test.", "type": "A"} ] }
```

`basis: "audit"`: the audit log has changes of the zone's records in that time that no version explains; `rrsets` names the first ten. They are **not** counted: the DNSSEC types, an update of nothing but `ordername` / `auth`, a change of the SOA serial alone (what the signer does when it re-signs, so a signed zone is not noisy), the summary rows of an import by the signer, and the rows of the change sets of the versions themselves. Only records count: metadata, keys and views are not RRsets. `basis: "generation"`: the audit log has no row of the zone at all in that time, so only the generation says that something happened (the audit triggers are not on). `changed_outside_since` is the same for the time after the newest version (first page of the list). The fields are for the masters of the whole zone (a subdomain master cannot read the audit log, and sees part of each delta only: the fields are not in its answers). "In that time" means between the times of the two versions. The rows of a version made by the API are told by their change set, so the window includes the second (SQLite3's audit log has no finer time) of such a version; the rows of an operator's version (an import) carry no change set and cannot be told from others', so the second of such a version is not looked at: a change made in that very second is not seen.

**Diff.** `GET .../versions/{a}/diff?to={b}` lists, for every RRset the versions a+1 to b touched, its records at the end of a (the `before` of the first version that touched it) and at the end of b (the `after` of the last one); an RRset that is the same at both ends (changed and changed back) is left out, an SOA that differs in its serial only too. `?to=current` compares version a with **the zone as it is**: the state at a of those RRsets is written as a change and `karidns-zone` (a check run) says what that would change, so a change made outside the versions to an RRset a version touched shows. (An RRset no version touched has no known state at a: it is not in any diff.) A state that the zone checks refuse in the zone as it is (a CNAME beside data that came later) is a 422 with the messages, as for any change.

**Rollback.** `POST .../versions/{n}/rollback {comment?, dry_run?, force?, reload?}` is a **new change set** that undoes the versions after n:

1. Every RRset that the versions after n touched is restored to its state before the first of them (that is the state at n; a change made outside the versions between n and that version is part of it); an RRset that did not exist then is deleted. The apex SOA is not restored (its serial only grows, and its other fields are the zone's parameters: change them with a change set); the answer's `skipped` names it.
2. **Conflict check.** Each of these RRsets must now be as the newest version that touched it left it; otherwise something else changed it, and restoring it would undo that too: 409 `version-conflict`, `errors[]` has `{name, type, expected, current}` for each. `force: true` restores them anyway. A `dry_run` does not fail on a conflict: it lists them in `conflicts` and shows the diff that a forced rollback would make.
3. The result goes through the pipeline of every change set (above): the zone checks, **one grant must allow every RRset restored** (old and new records; so a domain master cannot undo an apex change if its policy has no apex), the serial raised by one, a version of kind `rollback` with `rollback_of`, the reload on request. The answer is that of a change set plus `rollback_of`, `restored` (the RRsets in the plan), `versions_undone` and `skipped`. A rollback to the newest version, or to a state the zone is in already, changes nothing (`committed: false`).
4. Rolling back a rollback is an ordinary rollback to an earlier version: roll back to the version before the rollback.

A subdomain master sees, and so restores, only the RRsets under its suffix (and the apex NS, which every grant on the zone sees): "roll back to n" for it means "put my names back as they were". It cannot undo what lies outside its suffix; if the versions after n changed the apex NS the plan has it, no grant of a subdomain master allows the apex, and the rollback is refused (403).

**Signed zones.** The rollback is unsigned data, like every change set: the signer signs it and asks for the reload (S-5), the API files no reload (`reload: "waiting for the signer"`). The signer's records are not in the history and a rollback does not touch them; the signer removes the signatures of an RRset that is gone and signs the one that came back. This is the durable way to undo a change in a signed zone: `karictl rollback` refuses a signed zone.

| | `karictl rollback <zone>` | the API's rollback |
|---|---|---|
| acts on | the memory of one server: the previous published image, within `rollback-window` | the database |
| servers | the one server | every server reading the database, after a reload |
| signed zones | refused | yes, re-signed |
| speed | instant | the pipeline, the reload (and the signer) |
| who | an operator, or a restricted key with `rollback` | any principal whose grants allow the restored RRsets |

The API does **not** call `karictl rollback`: it is an operator's emergency tool. Use it first when a bad change must go at once, then roll back in the database to make it durable (after that the next reload installs the same content with a higher serial).

## TEMPLATES

A **template** is a named set of records whose owners are relative to the zone: `@` is the apex, `www` is `www.<zone>.`. It is **copied** into a zone, when the zone is made or when the template is applied; afterwards nothing links the zone to the template except the version (kind `create` or `template`, whose comment names the template, its id and its revision). A later change of the template changes no zone. Everybody reads templates, global masters write them.

```json
{ "name": "basic", "description": "mail and web",
  "soa": { "mname": "ns1.nsprovider.test", "rname": "hostmaster.nsprovider.test", "refresh": 1800, "minimum": 120 },
  "records": [ { "owner": "@", "type": "NS", "content": "ns1.nsprovider.test." }, { "owner": "@", "type": "MX", "content": "10 mail" },
               { "owner": "www", "type": "A", "ttl": 600, "content": "192.0.2.41" } ] }
```

- **Records.** `owner` is `@` or a name without the final dot (labels as in a change set; `*` and `_` allowed); `type` a record type `karidns-zone --types-list` names, not `SOA` (the `soa` fields are for that) and not a DNSSEC type; `content` the RDATA in zone file format, by the rules of a change set's records; a name in it that is not absolute is relative to the zone it is copied into (`10 mail` is `mail.<zone>.`). `ttl` is optional; the records of one RRset have one TTL (RFC 2181 section 5.2): all given and equal, or none given. A record without a TTL gets `default_ttl` of the request (3600 if none). At most 1000 records.
- **Validation on save** (and `POST .../validate`). The records are put in a zone text under `template.invalid.` (RFC 6761: never a real zone) with an SOA, and an NS outside the zone when the template has no NS at its apex, and `karicheck --json zone template.invalid -` reads it: a CNAME beside data, bad RDATA, a missing glue and so on. Errors are a 422 `template-checks-failed` with the messages, each pointing at the record (`/records/3`) and nothing is stored; warnings come back in `messages`. `dry_run: true` only checks. The `soa` fields are defaults: `mname` and `rname` (host names; always absolute) and the four timers.
- **A zone from a template.** `POST /datasets/{ds}/zones {name, template: "basic", ...}` (or `template_id`). The SOA is made of the request's `soa` fields, then the template's, then `refresh 7200, retry 3600, expire 1209600, minimum 300`; the serial is the day, `YYYYMMDD00`, unless the request gives one; the zone's records are the template's, and the request's own `rrsets` and `nameservers` **replace** the template's RRset of the same name and type (the request's `nameservers` replace the template's apex NS). The `soa` of the request may be left out when the template has the names. Global masters only, as for any new zone; the whole new zone is checked as one (`dry_run` shows it). The version 1 (kind `create`) has the comment `<comment> [template "basic" (id 3, revision 7)]`.
- **A template applied to a zone** (`POST .../apply-template {template | template_id, default_ttl?, comment?, dry_run?, reload?}`): every RRset of the template **replaces** the zone's RRset of the same name and type (an RRset merge: the zone's other RRsets stay; the template's SOA fields are not used). It is a change set like any other: the caller needs one grant that allows every RRset (a domain master whose policy has no apex cannot apply a template that has apex records: 403, `errors[].pointer` is `/template/records/<i>` of the record), the `dry_run` shows what would be overwritten, the version has the kind `template`. To undo it, roll back to the version before.

## THE WEB INTERFACE

The service also serves the files of the web interface (the GUI of the same release: plain ES modules, no build step, no framework), unless `ui = no`. The interface is a client of this API and nothing else: same origin, the cookie session, the CSRF token in memory only (taken from the login answer or `GET /auth/me`, replaced after `POST /auth/totp {confirm}`), every refusal read as the problem document above (the `type` selects the text in the user's language, `request_id` is shown for a 5xx, `Retry-After` for 429 and 503). It makes **no request on its own**: a session ends after `session-idle` without one (see "Authentication"), and the page only asks `GET /auth/me` when the person chooses "Stay signed in". A write is not repeated after a 401 and a new login; a read is. The text of every error code in the table above exists in English and Japanese in `webadmin/ui/i18n/` (a test keeps them in step with this table). For the manual of the screens see the [service manual](karidns-webadmin.md). They are read **once when the service starts** from `ui-dir` (default: `webadmin/ui/` of the installation) into memory and answered from there: no file system access at request time, so no path to traverse, no listing, no race. Requests that are not under `/api/v1/` are answered as follows; everything else is the usual 404 problem document.

| Request | Answer |
|---|---|
| `GET` or `HEAD /` | `index.html` (`Cache-Control: no-store`) |
| `GET` or `HEAD /ui/<path>` | the file of that name, with its `Content-Type` and a strong `ETag`; `Cache-Control: no-cache`, so the browser asks again with `If-None-Match` and gets a `304` (no body, no `Content-Length`) while the file is the same. Weak comparison, a list of tags and `*` are understood |
| any other method on these | 405 `method-not-allowed`, `Allow: GET, HEAD` |
| a name that is not in the map (`/ui/`, `/ui/../x`, `/index.html`, a `%` escape, another case) | 404. A request line is parsed as a URL first, so `..` is resolved before the lookup, and the names of the map have no `%` in them |

The directory is refused at the start (the service does not run, `--check` and the rc script's `configtest` say which file) if a name has a character outside letters, digits, `.`, `_`, `-` or starts with a dot; if an entry is not a regular file (a link, a socket); if an extension is not one of `html css js mjs json svg png ico txt`; if there are more than 512 files or 8 MiB, a directory more than 8 deep, or no `index.html`.

**Headers** of every answer for these files (the headers of the API's answers, `nosniff`, `no-referrer`, `X-Frame-Options: DENY` and `Strict-Transport-Security` under https, are added to them as to every answer):

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none';
                         frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'
Cross-Origin-Opener-Policy: same-origin        Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
```

No inline script or style, no `eval`, no outside origin and no framing is allowed, and no HTML-string sink (`innerHTML` and the like) may be used: every one of them throws in a browser that enforces Trusted Types, and the pages do not use them anyway. A proxy that injects a script or a stylesheet breaks the policy, which is the point. The files are the **same origin** as the API, so there is no CORS; the session cookie is `Path=/api/`, so the files are fetched without it (no login is needed for them, and they hold no secret and no zone data).

## SECURITY

- **Secrets on disk**: the connection files and the TOTP key file (mode 0600, owner checked at start), the auth file (0600). The API never reads `cryptokeys.content` (the role has no right to) and never logs passwords, tokens, cookies, TOTP codes, request bodies or query strings; the access log has the client address, the request id, the user, the method, the route template, the status and the time.
- **Input**: see CONVENTIONS. Paths and queries are validated before they reach SQL or a program's arguments; the programs get a fixed environment and no shell.
- **Output**: JSON (and the export as `text/plain` with `nosniff` and `Content-Disposition: attachment`); a front end must escape record data in the DOM.
- **SQLite3**: anyone who can write the auth file or run SQL on the zone file bypasses every rule here. Run the service as its own user, keep the files 0600 (auth file) and the zone file in a group the loader is in, and treat the host as the trust boundary.
- **PostgreSQL**: `karidns.principal` is a setting any session can make; the API is trusted to set it to the logged-in user. Row level security catches mistakes in the API's statements, not a compromised API process.
- Expired sessions: the service deletes them at the start and every hour. SQLite3: all of them. PostgreSQL: the API role sees the rows of its own principal only, so a SECURITY DEFINER function does it (`karidns_auth.sweep_expired()`, `EXECUTE` granted to the API role by `db/karidns_api_role.pgsql.sql`; it deletes the sessions whose absolute time is over, of every principal and nothing else); a user's own expired sessions are also deleted at its next login.
- **Zone texts and change sets are hostile input.** The text of a record is checked for the characters that could end its line or hide the rest of it before it is written to the change file, and `karidns-zone` checks the same again (a mistake in the API is not a hole); a zone text goes to the parser of the server with `$INCLUDE` refused (no file is read) and `$GENERATE` refused by the API (it could make more records than a host has memory for). The tools run with a timeout, without a shell, in a pool of `workers` (the export too: at most `workers` of them at a time, each up to 256 MiB of output in memory; more wait, 64 at most, then 503).
- **Limits** (all fixed in the code): headers 16 KiB; body 1 MiB, a zone text 16 MiB; 30 seconds to receive a body (300 for an import); 256 connections; 5 seconds of keep-alive; a change set of 1000 RRsets with 1000 records each; one change set per zone at a time (about 16 may wait, then 503). Rate limits per address and per principal as described under AUTHENTICATION.
- **The password asked for again** (`POST /auth/password`, switching TOTP off) has the limits of a login: five tries a minute per principal, and every wrong password or wrong code counts towards the lock of the account. Otherwise the holder of a stolen session could guess the password at the speed of the API.
- **The log does not keep what was typed in the name field of a failed login**: a login for a name that does not exist (or is disabled) is logged as `an unknown or disabled user`, because a password typed in the wrong field would otherwise be in the log.
- **Errors that leak nothing**: a 500 carries the request id and no text; a failed reload shows karictl's words (which can hold paths of the host) to a global master only, others are pointed at the log; a database error is mapped to a status and a code, never passed on.
- **Reading is one snapshot**: a PostgreSQL read runs in one `REPEATABLE READ READ ONLY` transaction, and a page of RRsets is read in two statements (the keys, then the records of those names) — one statement with a join planned as a nested loop that tested row level security 500,000 times on a table that has no statistics yet (a zone just imported, before autovacuum's analyze; 2.9 seconds for a zone of 1000 records).
- **The unauthenticated routes** are `/health` (one database check at a time, however many callers) and `/auth/login` (rate limited before the database is asked). A request with bad credentials is limited per address but costs a database lookup before that; put a rate limit in the proxy.

## FILES

`/usr/local/etc/karidns/karidns-webadmin.conf` (settings, no secrets), the connection files, `totp.key`, the SQLite3 zone file and auth file. The shared Node code is in `node/lib/` (also used by `karidns-signer`); the service is `webadmin/` (`npm ci --ignore-scripts` installs its one dependency, `pg`).

## EXIT STATUS

0: fine, or stopped by a signal. 1: a problem (the configuration, a file, the database, a tool; `--create-admin` failed). 2: a usage error.

## EXAMPLES

```sh
karidns-webadmin --check -c /usr/local/etc/karidns/karidns-webadmin.conf
curl -s -c jar -H 'Content-Type: application/json' -d '{"user":"admin","password":"..."}' http://127.0.0.1:8053/api/v1/auth/login
curl -s -b jar http://127.0.0.1:8053/api/v1/datasets/main/zones
curl -s -b jar 'http://127.0.0.1:8053/api/v1/datasets/main/zones/example.test./rrsets?type=A&limit=50'
curl -s -b jar http://127.0.0.1:8053/api/v1/datasets/main/zones/example.test./export > example.test.zone
# an unsafe request with a cookie: the CSRF token and the Origin
curl -s -b jar -H "X-KariDNS-CSRF: $CSRF" -H 'Origin: https://dns.example.test' -H 'Content-Type: application/json' \
     -d '{"kind":"group","name":"customers"}' https://dns.example.test/api/v1/principals
# automation: a token
curl -s -H "Authorization: Bearer $TOKEN" https://dns.example.test/api/v1/datasets/main/zones
# a change set with a token: look first (dry run), then do it and ask for the reload
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X PATCH \
     -d '{"dry_run":true,"rrsets":[{"name":"www.example.test.","type":"A","changetype":"REPLACE","ttl":300,"records":[{"content":"192.0.2.10"}]}]}' \
     https://dns.example.test/api/v1/datasets/main/zones/example.test./rrsets
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X PATCH \
     -d '{"reload":true,"comment":"move www","rrsets":[{"name":"www.example.test.","type":"A","changetype":"REPLACE","ttl":300,"records":[{"content":"192.0.2.10"}]}]}' \
     https://dns.example.test/api/v1/datasets/main/zones/example.test./rrsets
# the history: the versions, what version 3 changed, version 1 against now, and a rollback to version 1 (look first, then do it; "force":true restores RRsets that were changed outside the versions)
curl -s -H "Authorization: Bearer $TOKEN" https://dns.example.test/api/v1/datasets/main/zones/example.test./versions
curl -s -H "Authorization: Bearer $TOKEN" https://dns.example.test/api/v1/datasets/main/zones/example.test./versions/3
curl -s -H "Authorization: Bearer $TOKEN" 'https://dns.example.test/api/v1/datasets/main/zones/example.test./versions/1/diff?to=current'
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X POST -d '{"dry_run":true}' https://dns.example.test/api/v1/datasets/main/zones/example.test./versions/1/rollback
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X POST -d '{"comment":"undo the move","reload":true}' https://dns.example.test/api/v1/datasets/main/zones/example.test./versions/1/rollback
# a template, a zone made from it, the template applied to another zone
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X POST -d '{"name":"basic","soa":{"mname":"ns1.nsprovider.test","rname":"hostmaster.nsprovider.test"},"records":[{"owner":"@","type":"NS","content":"ns1.nsprovider.test."},{"owner":"www","type":"A","content":"192.0.2.41"}]}' https://dns.example.test/api/v1/templates
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X POST -d '{"name":"customer.test","template":"basic","reload":true}' https://dns.example.test/api/v1/datasets/main/zones
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X POST -d '{"template":"basic","dry_run":true}' https://dns.example.test/api/v1/datasets/main/zones/example.test./apply-template
# the update button, and the DS records of a signed zone
curl -s -H "Authorization: Bearer $TOKEN" -X POST https://dns.example.test/api/v1/datasets/main/zones/example.test./reload
curl -s -H "Authorization: Bearer $TOKEN" https://dns.example.test/api/v1/datasets/main/zones/example.test./dnssec
```

## SEE ALSO

[Service manual](karidns-webadmin.md) (install, roles, TLS, backups, measurements), [`karidns-zone(1)`](karidns-zone.md), [`karidns-dbloader(8)`](karidns-dbloader.md) ("Roles and row level security", the WebAdmin tables), [`karidns-signer(8)`](karidns-signer.md), [`karicheck(1)`](karicheck.md), RFC 9457 (problem details), RFC 6238 (TOTP).
