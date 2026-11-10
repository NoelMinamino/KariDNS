# KARIDNS-WEBADMIN SERVICE MANUAL — installing and running the WebAdmin API

## NAME

**karidns-webadmin** — the service that gives people and programs an HTTP API for the zones, users and grants of a KariDNS database. This manual is for the person who installs and runs it: packages, database roles, the first administrator, TLS, backups, upgrades, and what to watch. The API itself (every endpoint, every error code, every setting) is in the **[API reference](karidns-api.md)**.

## OVERVIEW

```
 browser (item F) / scripts with API tokens
        |  HTTPS            (a reverse proxy: nginx, relayd; or the built-in TLS)
        v
 karidns-webadmin           Node.js 22.13+, one process, user karidns-webadmin, 127.0.0.1:8053 or a UNIX socket
        |  SQL  (PostgreSQL: role karidns_api, row level security on;  SQLite3: the zone file + the auth file)
        |  runs: karidns-zone (read and write zone data), karicheck, karictl (SQLite3: the reload)
        v
 the database  <---- karidns-dbloader <---- karidns (the DNS server), and karidns-signer (optional)
```

The service decides **who may do what** (users and groups, three kinds of grant, record policies), checks every change set against the zone rules, and writes it through `karidns-zone`. It does not serve DNS and does not talk to a DNS server, except to ask `karictl` for a reload on SQLite3. If the database is PostgreSQL, row level security checks every statement a second time as the database role `karidns_api`; on SQLite3 the service's own checks are the only checks (read "The two models" below before you choose).

### The two models

| | PostgreSQL | SQLite3 |
|---|---|---|
| Who may read or write what | the service **and** the database (row level security, the audit triggers) | the service only |
| A bug in the service that allows too much | the database still refuses (and the log says `row level security refused what the API allowed (a bug)`) | the change is made |
| Someone who can write the files | n/a (they are not on the host) | can do anything: the zone file and the auth file are the credential |
| Several DNS servers on one database | yes (reload requests reach every server) | no: one host (the file is local) |
| Choose it when | several hosts, several teams, tenants that must not be able to harm each other | one host, a small team that trusts the host |

## INSTALLING

### The packages

```
pkg add karidns-postgresql-0.6.0-FreeBSD-15-amd64.pkg      # or karidns-sqlite3, or karidns-db: they hold karidns, karicheck, karictl, karidns-zone, the loader and db/*.sql
pkg install node24                                         # pkg add does not fetch dependencies
pkg add karidns-webadmin-0.6.0-FreeBSD-15-amd64.pkg
```

`karidns-webadmin` installs `/usr/local/sbin/karidns-webadmin` (a wrapper that starts the Node.js of the package with core dumps off), `/usr/local/libexec/karidns-webadmin/` (the program, its one dependency `pg`, and the code it shares with `karidns-signer`; root-owned, read-only), `/usr/local/etc/rc.d/karidns_webadmin`, `/usr/local/etc/karidns/karidns-webadmin.conf.sample`, the web interface (`webadmin/ui/` under the program directory), these manuals in `/usr/local/share/doc/karidns/` (`karidns-webadmin.md`, `karidns-api.md`, `karidns-webadmin-gui.md`, `karidns-webadmin-gui-checklist.md`), and creates the user and group `karidns-webadmin` (no login shell, no password, home `/var/db/karidns-webadmin`). The package refuses to install without `/usr/local/bin/karidns-zone` and `/usr/local/bin/karicheck` (the database packages conflict with each other, so the dependency cannot name one). The SQL files are in `/usr/local/share/karidns/db/`.

From a source tree (no package): `cd webadmin && npm ci --ignore-scripts`, then `node webadmin/bin/karidns-webadmin.js --check -c <config>`. The dependency is pinned by `package-lock.json`; there are no install scripts, and CI runs `npm audit --audit-level=high`.

### Files the service uses

| File | Owner, mode | Holds |
|---|---|---|
| `/usr/local/etc/karidns/karidns-webadmin.conf` | root:karidns-webadmin, 0640 | the settings (no secret) |
| `api.conninfo`, `check.conninfo` (PostgreSQL) | karidns-webadmin, **0600** | the connection of the roles `karidns_api` and the check role, with passwords if the database needs them; `--check` and the start refuse any other owner or mode |
| `/usr/local/libexec/karidns-webadmin/webadmin/ui/` | root, 0444 files in 0755 directories | the files of the web interface (`ui-dir`); read once at the start, served under `/` and `/ui/` |
| `/var/db/karidns-webadmin/totp.key` | karidns-webadmin, **0600** | the AES-256 key that wraps the TOTP secrets in the database; made at the first start; the directory is made by the rc script (0700) |
| the auth file, `auth.sqlite3` (SQLite3) | karidns-webadmin, **0600** | users, password hashes, grants, sessions, tokens, templates; `--check` refuses a wider mode |
| the zone file, `zones.sqlite3` (SQLite3) | karidns-webadmin, group of the loader, 0660, directory writable by that group | the zones; SQLite3 opens it read-write even to read (WAL mode) |
| `tls.key` (only for the built-in TLS) | karidns-webadmin, **0600** | the certificate key; `--check` refuses any other owner or mode |
| `webadmin-karictl.conf` (SQLite3, optional) | karidns-webadmin, **0600** | the restricted control key for the reload |
| `oidc.secret` (one for each `[oidc]` section, optional) | karidns-webadmin, **0600** | the client secret that the identity provider gave the service; one line; `--check` and the start refuse any other owner or mode |

### PostgreSQL

The owner of the PowerDNS tables does this once (and again at every upgrade: the files can be applied again):

```
psql -v ON_ERROR_STOP=1 -f /usr/local/share/karidns/db/karidns_ext.pgsql.sql karidns                       # schema version 3 and the karidns_auth schema
psql -v ON_ERROR_STOP=1 -v role=karidns_api   -v schema=public -f /usr/local/share/karidns/db/karidns_api_role.pgsql.sql   karidns
psql -v ON_ERROR_STOP=1 -v role=karidns_check -v schema=public -f /usr/local/share/karidns/db/karidns_check_role.pgsql.sql karidns
psql -v ON_ERROR_STOP=1 -v role=karidns_loader -v schema=public -f /usr/local/share/karidns/db/karidns_loader_role.pgsql.sql karidns    # if not done already
```

What this sets up, and why two roles:

- **`karidns_api`** is what the service connects as for everything it does for a user. Row level security (RLS) is switched on by its script: every row it reads or writes must be covered by a grant of the acting user (`karidns.principal`, set in every transaction). It cannot read the key material (`cryptokeys.content`), cannot write the audit log, and has no `BYPASSRLS`. The script stops, before it changes anything, if the role is a superuser, owns the tables, or is a member of `karidns_rls_trusted` — RLS would not bind it.
- **`karidns_check`** is the role of the *check runs*: `karidns-zone apply --dry-run` has to see the **whole** zone to check a change (a CNAME beside other data, the size limits), and a subdomain master's session sees only its part. The check role sees every row but **can never commit**: a deferred trigger on every table it writes refuses the COMMIT. A compromised service could use the check role to *read* whole zones, not to change them.
- Both scripts create the role as `NOLOGIN` if it does not exist. Make login roles that are members of them, **not** the roles themselves and not members of `karidns_rls_trusted`:

```
CREATE ROLE karidns_web   LOGIN PASSWORD '...' IN ROLE karidns_api;
CREATE ROLE karidns_webck LOGIN PASSWORD '...' IN ROLE karidns_check;
```

```
# /usr/local/etc/karidns/api.conninfo   (karidns-webadmin, 0600)
host=db.example.test port=5432 dbname=karidns user=karidns_web password=... sslmode=verify-full
# /usr/local/etc/karidns/check.conninfo (the same, user=karidns_webck)
```

Use a UNIX socket (`host=/tmp`) or `sslmode=verify-full` for a remote database. The keywords understood are `host`, `port`, `dbname`, `user`, `password`, `sslmode`, `connect_timeout` and `application_name`; any other is an error. **`sslmode=prefer` and `allow` do not try TLS** (the Node driver has no opportunistic mode): they mean plain text. Use `require` (encrypted, the certificate not checked), `verify-ca` or `verify-full`.

Several data schemas (views with their own zone data): run the role scripts once per schema and list the schemas in `[dataset NAME]` sections of the configuration ([API reference](karidns-api.md), "Configuration file").

### SQLite3

```
sqlite3 /var/db/karidns/zones.sqlite3 < /usr/local/share/karidns/db/karidns_ext.sqlite3.sql        # schema version 3
sqlite3 /var/db/karidns/zones.sqlite3 < /usr/local/share/karidns/db/karidns_audit.sqlite3.sql      # the audit triggers (without them the audit log stays empty)
install -m 0600 -o karidns-webadmin -g karidns-webadmin /dev/null /var/db/karidns/auth.sqlite3
su -m karidns-webadmin -c 'sqlite3 /var/db/karidns/auth.sqlite3 < /usr/local/share/karidns/db/karidns_auth.sqlite3.sql'
chown karidns-webadmin:<the loader group> /var/db/karidns/zones.sqlite3; chmod 0660 /var/db/karidns/zones.sqlite3
```

The zone file is in WAL mode; the directory must be writable by the service **and** by the loader's user (they both create the `-wal` and `-shm` files). The **loader must not be able to read the auth file** (it holds the password hashes): that is why it is a file of its own. Everything in the zone file and the auth file is protected by file permissions alone; read the first row of "The two models".

**Reload with SQLite3.** There are no reload requests on SQLite3, so the service asks the running server with `karictl`, using a key that can do nothing but `reload-zone` (a full-power key must never sit in the web tier):

```
# karidns.conf
key "webadmin" { algorithm hmac-sha256; secret "..."; };          # a secret of your own:  karictl tsig-keygen webadmin
control-channel { socket "/var/run/karidns/control.sock"; allow-group "karidns-webadmin"; keys { "webadmin" read-only yes allow-commands { reload-zone; }; }; };
# /usr/local/etc/karidns/webadmin-karictl.conf   (karidns-webadmin, 0600); karictl-config in karidns-webadmin.conf points here
socket "/var/run/karidns/control.sock";
key "karictl" { algorithm hmac-sha256; secret "..."; };           # the same secret
```

The control socket must be reachable by the service user, so on SQLite3 the service runs on the DNS host. Without `karictl-config` the API changes zones but cannot reload them; an operator reloads with `karictl`.

### The configuration

Copy the sample and edit it. A minimal PostgreSQL deployment behind nginx:

```
listen = 127.0.0.1:8053
public-origin = https://dns.example.test
trusted-proxy = 127.0.0.1
database = pg
api-conninfo-file = /usr/local/etc/karidns/api.conninfo
check-conninfo-file = /usr/local/etc/karidns/check.conninfo
log = daemon
```

```
chown root:karidns-webadmin /usr/local/etc/karidns/karidns-webadmin.conf; chmod 0640 /usr/local/etc/karidns/karidns-webadmin.conf
chown karidns-webadmin /usr/local/etc/karidns/api.conninfo /usr/local/etc/karidns/check.conninfo; chmod 0600 /usr/local/etc/karidns/*.conninfo
service karidns_webadmin oneconfigtest       # karidns-webadmin --check as the service user: files and modes, tools, the database schema (the "one" prefix: it works before the service is enabled)
```

**The files of the web interface.** The service also serves the files of its web interface from memory: it reads the directory `webadmin/ui/` of the installation (or the directory `ui-dir` names) **once, when it starts**, and answers `/` (the page) and `/ui/...` (the rest) from what it read; there is no file access at request time, so a change of the files needs a restart. Names are letters, digits, `.`, `_` and `-`, only regular files, only the types the interface uses (`html css js mjs json svg png ico txt`), at most 512 files and 8 MiB, and an `index.html`; anything else keeps the service from starting (`configtest` says which file). `ui = no` switches the interface off (`/` is then a 404 and only `/api/v1/` is served), for an operator who serves the files from elsewhere. The files carry their own security headers (no inline script, no outside origin, no framing; [API reference](karidns-api.md), "THE WEB INTERFACE"), so a proxy must not add scripts or rewrite them.

`configtest` says `ok:` for what is fine and `problem:` for what is not, and exits 1 on a problem. It checks the files and their modes, that `karidns-zone` has the driver of the database and speaks the JSON schema this version expects (and has the `render` command of the web interface), that the files of the web interface can be read, that `karicheck` runs, and that the database is at schema version 3 with every table the service uses.

### The first administrator

There is no default account. As the service user, once:

```
# SQLite3
su -m karidns-webadmin -c 'karidns-webadmin --create-admin admin'

# PostgreSQL: the API role cannot make the first user (row level security), so --create-admin needs the connection of the table owner.
# Put it in a file of the service user for the minutes this takes, and delete it afterwards.
install -m 0600 -o karidns-webadmin /dev/null /var/db/karidns-webadmin/owner.conninfo      # then write: host=... dbname=karidns user=<the owner> password=...
su -m karidns-webadmin -c 'karidns-webadmin --create-admin admin --bootstrap-conninfo-file /var/db/karidns-webadmin/owner.conninfo'
rm -P /var/db/karidns-webadmin/owner.conninfo
```

It makes the user `admin` with a global master grant, the record policy `all-types`, and a random password that is **shown once**. A second `--create-admin` with the same name is refused; use another name to make another administrator (this is also the way back in when every administrator is locked out). Then:

```
sysrc karidns_webadmin_enable=YES
service karidns_webadmin start
```

### TOTP: the first login

With the default `require-totp = global`, a global master has to use a second factor. The first login gets a session that can do nothing but enrol:

```
O=https://dns.example.test
curl -s -c jar -H 'Content-Type: application/json' -d '{"user":"admin","password":"<the password>"}' $O/api/v1/auth/login
#  -> {"csrf":"<token>","totp":{"enabled":false,"enrollment_required":true},...}   the session cookie is in the jar
curl -s -b jar -c jar -H 'Content-Type: application/json' -H "Origin: $O" -H 'X-KariDNS-CSRF: <token>' -d '{"action":"enroll"}' $O/api/v1/auth/totp
#  -> {"secret":"JBSWY3DPEHPK3PXP...","uri":"otpauth://totp/KariDNS:admin?..."}      put the secret in an authenticator app (SHA-1, 6 digits, 30 s)
curl -s -b jar -c jar -H 'Content-Type: application/json' -H "Origin: $O" -H 'X-KariDNS-CSRF: <token>' -d '{"action":"confirm","code":"123456"}' $O/api/v1/auth/totp
#  -> a new session (the jar is updated) and a new csrf token: from now on the login needs "totp"
```

An unsafe request (POST, PUT, PATCH, DELETE) with a session cookie needs the `X-KariDNS-CSRF` header **and** an `Origin` equal to `public-origin`, and `Content-Type: application/json`. Automation should not use the cookie: make an **API token** (`POST /api/v1/tokens`, a login session is needed to make it) and send `Authorization: Bearer kdt_...`; a token needs no CSRF header, can be read-only, and expires (90 days by default, 365 at most).

Then make the real users and grants ([API reference](karidns-api.md), "Permissions"): groups for the tenants, users in them, record policies (`POST /api/v1/rr-policies`), grants (`POST /api/v1/grants`: `domain_master` on a zone, `subdomain_master` on a name below it). A domain master can grant on its own zone, with a policy no wider than its own, without a global master.

## TLS AND THE REVERSE PROXY

The service listens on **127.0.0.1** or a **UNIX socket** and speaks plain HTTP there; it refuses to start with plain HTTP on any other address. TLS is the job of a reverse proxy in front. `public-origin` must be the https origin a browser uses (an unsafe request with a cookie must carry exactly this `Origin`, and the cookie gets the `Secure` flag and HSTS from it).

**Set `trusted-proxy`** to the proxy's address (`local` for a UNIX socket): the rate limits and the log use the address the proxy reports in `X-Forwarded-For` (the first from the right that is not a trusted proxy), and only from a trusted proxy is the header believed. Without it every client has the proxy's address and shares one login limit.

### nginx

```
# in the http { } block: a flood of requests with bad credentials costs the service a database lookup each; stop it here
limit_req_zone $binary_remote_addr zone=webadmin:10m rate=20r/s;

server {
    listen 443 ssl;
    server_name dns.example.test;
    ssl_certificate     /usr/local/etc/ssl/dns.example.test.crt;
    ssl_certificate_key /usr/local/etc/ssl/dns.example.test.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 17m;               # a zone import is up to 16 MiB; everything else is under 1 MiB
    client_header_buffer_size 16k;          # the service refuses more than 16 KiB of headers
    proxy_http_version 1.1;
    proxy_read_timeout 330s;                # an import may take 300 s

    location / {                            # the API (/api/v1/) and the files of the web interface (/ and /ui/): the service decides what exists, the rest is a 404
        limit_req zone=webadmin burst=40 nodelay;
        proxy_pass http://127.0.0.1:8053;                                     # or http://unix:/var/run/karidns_webadmin/api.sock;
        proxy_set_header X-Forwarded-For $remote_addr;                       # set, not append: the client's own header is not passed on
        proxy_set_header Host $host;
    }
}
```

With a UNIX socket put `listen = /var/run/karidns_webadmin/api.sock` and `trusted-proxy = local` in the configuration (the rc script makes `/var/run/karidns_webadmin` for the pid files and the service makes the socket mode 0660 in it; the proxy's user must be in the group `karidns-webadmin` to open it). Any other path must be in a directory the service user can write.

### relayd

```
table <webadmin> { 127.0.0.1 }
http protocol "webadmin" {
    tls { no tlsv1.0, no tlsv1.1 }
    match request header set "X-Forwarded-For" value "$REMOTE_ADDR"          # set: a header from the client is replaced
    block                                                                     # relayd takes the last rule that matches: block everything ...
    pass request path "/api/*"                                                # ... except the API,
    pass request path "/ui/*"                                                 # the files of the web interface
    pass request path "/"                                                     # and its page
}
relay "webadmin_tls" {
    listen on 192.0.2.10 port 443 tls
    protocol "webadmin"
    forward to <webadmin> port 8053
}
```

(Neither proxy configuration is run by KariDNS's tests; check the syntax against your version. What the service needs from the proxy is only: TLS, the paths `/api/`, `/ui/` and `/` forwarded (`/` and `/ui/` only with the web interface, unless `ui = no`), `X-Forwarded-For` set to the client's address, bodies up to 16 MiB, and a read timeout longer than 300 seconds for imports.)

### The built-in TLS

For a single host without a proxy: set `tls-cert` and `tls-key` (both, PEM files; `tls-key` owned by the service user, mode 0600, which `--check` verifies) and `listen = 192.0.2.10:8443`. TLS 1.2 or newer; the key and certificate are read at the start (restart to renew). There is no HTTP to HTTPS redirect and no OCSP stapling; a proxy does those better.

## THE WEB INTERFACE

The service serves a browser front end of its own API under `/` (settings `ui` and `ui-dir`, [API reference](karidns-api.md), "The web interface"). **What the screens are and how to use them — by role, with the messages and a glossary in English and Japanese — is the [user manual](karidns-webadmin-gui.md)**; this section is for the operator. It is plain JavaScript modules and one style sheet, no build step, no framework, no outside address: the page's policy (`default-src 'none'`, scripts and styles only from the origin, no inline code, Trusted Types) makes anything else fail, which is why **a proxy that injects a script or a style sheet breaks it** (the page then shows a banner that something was blocked). It needs no database and no login for its files; everything it shows comes from `/api/v1/` with the cookie session of the person (`HttpOnly`, `SameSite=Strict`, `Path=/api/`, so the files are fetched without it).

This release has the foundation and the person's own pages: **sign-in** (user, password, the code when the account has TOTP; one message for every refusal; a button that waits when the service says 429), **TOTP set-up** (the QR code is drawn in the page by the interface's own encoder, the key as text only when asked for; a global master under `require-totp = global` can do nothing else until it has done this), the **account** (password, TOTP on and off where the configuration allows, API tokens shown once, language, signing out here or everywhere), the start page with the person's grants, and **About** (versions). English and Japanese, chosen by the browser and changed in the account.

It also has **the zone screens** (item F, milestone M3). Everything they show is what the API answers; what is hidden is a hint, and every call can still be refused (the page handles 401, 403, 404, 409, 422, 429 and 503 everywhere):

- **Zones** (menu "Zones"): the zones the person has a grant on, with its role on each, the kind, the serial and notes (kept signed by the signer, signed elsewhere, catalog); a dataset selector when there is more than one, a search by a part of the name or its start, by kind and by signed or not, paged by cursor ("next page", no totals). A global master also has "New zone" and "Update every zone of this dataset" (PostgreSQL) here.
- **A zone** (sections Records, Import, Settings, DNSSEC, and the export link): the header shows the kind, the serial and generation, when it changed, the signer's state ("waiting for the signer"), the last reload request, and the person's role and record policy. The **records** are read a page at a time with their text form (`?rdata=1`, the form a change set takes: names are absolute, MX and SRV have their numbers in front), names are shown relative to the zone, a search by a part of the owner name or from a name, and the page size. A record set the person may not edit is shown with the reason: the zone is not a primary zone, is signed elsewhere (`PRESIGNED` without the signer), has location / ECS tags or tinydns attributes (`tagged`), is a DNSSEC type, a record has no text form or is switched off, the type is not in the person's policy, or the name is outside a subdomain master's suffix or at the apex. The SOA is shown and is only edited by a global master, in a form of its own that says the service writes the next serial whatever is typed, and that there is no precondition on it.
- **Editing is a draft.** Edit, Add and Delete put an entry into a change set that lives in the memory of the page (nothing is stored in the browser: closing the tab loses it, and the page asks before it is left while a draft exists; it survives a new sign-in of the same person after a 401 and is dropped for another person or at logout). Each entry has an undo. **Preview** is a dry run: the diff (before and after per record set, as the service computes it), the messages of the zone checks with their codes (a message that names a record is shown at that record), and the version and serial it would write. **Commit** sends the same change set with a precondition (`expect`: the records as they were loaded, from the text form) and, if ticked, the reload. The button waits for a new preview after any change, and waits `Retry-After` after a 429 or 503. A diff of more than 200 record sets is shown in pages of 200.
- **Conflicts.** If somebody changed a record set after it was loaded, the service answers 409 `precondition-failed` with the record set as it is: the page shows, per record set, what was loaded, what is there now and the person's change, and the person takes theirs (the entry is dropped and the page read again) or keeps their own (the precondition becomes the present state; preview again). 409 `changed` (the zone kept changing), 403 (the record set that no grant allows is named at its entry) and 422 (the zone checks) are shown where they belong.
- **The update button.** Changes are in the database after a commit; the servers serve them after a reload, which is explicit (`reload-after-change` sets the default of the box, the button "Update the servers now" asks for one). A zone the signer keeps has no button: the signer asks for the reload when it has signed (the page says so). After a request the page looks at the zone and at `/servers` every 5 seconds for at most two minutes and says how many servers have loaded the change (PostgreSQL; with SQLite3 there is no server status and the page asks nothing more). This is the only polling the page does; it extends the session like any request. The **Servers** screen shows the same per dataset and server (generation, time, whether every zone loaded, the zones that did not) and, on SQLite3, the service's note.
- **New zone** (global masters): from a form (SOA values, name servers, more records written as `name [ttl] TYPE data`), from a template (its values are the defaults of the form) or from a zone file (typed, pasted or read from a file; the file is decoded as strict UTF-8 and refused otherwise, with the hint to write other bytes as `\DDD`; the size is checked against `GET /version` before it is sent). The dry run shows the whole new zone; the commit goes to its page. A refusal is shown at the field its pointer names.
- **Import and export.** The import takes a zone file the same way (mode replace or merge, a dry run first, the diff in pages) and is for the masters of the whole zone. The export is a plain link to `.../export` (the service answers with `Content-Disposition: attachment`; the cookie goes with it because it is the page's own address).
- **Settings.** The attributes (kind, catalog, views, masters), the metadata the zone has (the kinds the API writes are editable by global masters: one value a line, a refusal is shown at the box), the catalog and views of the zone, and deleting the zone, which asks for its name to be typed again (the API's `confirm`).
- **DNSSEC** (domain and global masters): the signer's state (when it signed, the serial, when it is due, the time left until the first signature expires, the last error as text), the keys with their key tags, the DS records for the parent zone with copy buttons (digest types 2 and 4, computed by the service), the key requests with their state, and a form for `enable` (not signed yet) or `add` (kept by the signer). Keys and signatures are the signer's: this only asks.

The history, the templates, the administration and the audit log are the screens of item F, milestone M4:

- **Versions** (section "Versions" of a zone; every person with a grant on the zone): every saved change is a version, listed newest first with its number, kind (created, edit, template applied, import, rollback), time, who (the person, or `operator (<database role>)` for a tool such as `karidns-zone import`), the comment, the serial before and after and the number of record sets it changed. A zone keeps its newest 100 versions, so the list is one page; the audit log is the complete record. For the masters of the whole zone the list marks **changes outside the versions** (a write that did not go through `karidns-zone`: `psql`, a PowerDNS tool): between two versions, or since the newest one, with the record sets the audit log names, or, when the audit log has nothing for that time, only that the zone's generation grew. A subdomain master sees the part of each change under its suffix, and no marker. A number opens **one version**: its fields and the change it made, as the diff the editor shows; **a difference** (the form of the list, or "Against the zone now" of a row) compares version A with a later version or with the zone as it is (`-` lines are the record set after version A, `+` lines the other end; a version that was too big to keep its record sets, or a range of more than 50,000 record sets, is refused by the service and told).
- **Rollback** (on the page of a version): the dry run first (the diff, how many record sets would be restored and how many versions undone, the SOA that is not restored because its serial only grows), then the commit, with the comment and the reload box like any change. A record set that something outside the versions changed after the versions that would be undone is a **conflict**: the commit stays off, a table lists each (what the newest version left, what is there now) and the way on is a second question, "Roll back anyway and overwrite these", that names the number of record sets it overwrites; that one commit carries `force`. A conflict that appears only at the commit (409 `version-conflict`) is shown the same way. One grant must allow every record set restored (403 otherwise, at the record set). `karictl rollback` (the server's memory, for emergencies) and this rollback (the database, durable, re-signed for signed zones) are told apart in the API reference.
- **Templates** (menu "Templates"; everybody reads, global masters write): the list with a search by name, a template with its SOA defaults and its records (owner relative to the zone, `@` the apex, type, TTL, data), "Check again" (the zone checks, `karicheck`, as of now), and for global masters the form: name, description, the six SOA fields, and the records as text, one a line, `owner [TTL] TYPE data` (lines that begin with `;` are ignored). **Check** is a dry run; a refusal of the zone checks (422) is shown with the line of each record in the box. Deleting asks first; zones made from a template keep their records. In the section "Template" of a zone (the masters of the whole zone) a template is **applied**: its record sets replace the zone's record sets of the same name and type, with a preview (what would be overwritten) and the same commit as any change; to undo it, roll back to the version before.
- **Administration** (menu "Administration", global masters; a domain master and a subdomain master get a notice and the page makes no request): *Users* and *Groups* (search by name, a new user with a password, a new group), the page of one user or group (name, display name, e-mail, disabled; a disabled user is signed out and loses its tokens), for a user the state of its sign-in (password set, two-step verification, failed attempts, locked) with the administrator's actions: **unlock** (clears the failed attempts and the lock) and **reset two-step verification** (for a user who lost the device: it is switched off and the user's sessions end; where `require-totp` says so, the next sign-in enrols again), each after a question, and a new password (the user's sessions end); the groups a user is in; for a group its members (add by exact name, remove after a question; groups nest). One cannot disable, delete or reset the two-step verification of oneself (the page does not offer it; the service answers 409 `self`). *Record policies* (the types, wildcard, delegation, DNAME and apex flags, the TTL range, the most records; a policy in use is not deleted: 409). *Grants* (all grants with a filter by user or group and by zone; a new grant by role, zone, suffix and policy; removing asks first) and the same on the page of a principal.
- **Grants of a zone** (section "Grants" of a zone, for its domain master and for global masters): who holds a grant on this zone and the form to give one. A domain master may give domain-master and subdomain-master grants on **its** zone with a policy no wider than its own; the form offers the policies that look so (types a subset, each flag not more, TTL range inside, `max_rr` not more) and the service decides (403 `escalation`).
- **Audit log** (menu "Audit log", global masters and domain masters; a domain master reads the rows of its zones): newest first, 100 a page ("next page"), with filters for the zone, the user or group (by name), the change set, the table, and a time range (`since`, `until`, ISO 8601, for example `2026-11-08T12:00:00Z`). A row shows when, who (the person, or the database role of a tool), the table and what (added, changed, deleted), the zone, the change set and the row; "all rows" lists the rows of the same change, "version" opens the versions of the zone with that version marked (where the dataset is known). The database rows `before` and `after` are shown as pretty-printed JSON **text** (cut at 20,000 characters), never interpreted: what is in them was written by others.

All record data, names, comments and error texts are drawn as text: C0 and C1 characters as `\DDD`, bidi and zero-width characters as `<U+XXXX>`, and never as HTML or as an attribute that decides an address (the tests import hostile data and check that nothing runs).

- **Sessions.** Nothing in the page asks the service on its own, so the idle time of `session-idle` means what it says: the page counts down from its last request, warns two minutes before (a minute earlier than the service ends it, which writes the time of the last request at most once a minute), and "Stay signed in" is one request made because the person asked. When the session has ended, a 401 on any page opens the sign-in over what is on the screen; the same person goes on, another person starts at the start page. A sign-out in one tab signs out the others (a `BroadcastChannel`).
- **Browsers.** Firefox ESR, Chrome and Edge (current and previous), Safari 17 or newer; no polyfills. The accessibility target is WCAG 2.1 level AA (not certified); the [checklist](karidns-webadmin-gui-checklist.md) says how each point is met and has the manual check for Chrome, Edge and Safari that the project runs before a release. The automated tests run Firefox (`tests/run_webadmin_gui_test.sh` on SQLite3 and `tests/run_webadmin_gui_pg_test.sh` on PostgreSQL, headless through geckodriver; the screens of zones need root and a real `karidns`, so that the update button is checked with `dag`; on the FreeBSD build host that needs `pkg install firefox geckodriver dejavu`: Firefox crashes at the start on a system without a font).
- **Identity providers** (item F, milestone M5; set-up under SIGNING IN WITH AN IDENTITY PROVIDER). With `[oidc]` sections the sign-in screen has a button for each provider below the password form ("Sign in with Corp ID"), and the sign-in dialog that opens after a 401 has them too (a click leaves the page; the browser asks first if there is a draft). The button is a plain link to the service, which sends the browser to the provider and back to the page the person was at; if it did not work, the screen says so with one message in the person's language. A person whose TOTP is on and who comes in through a provider is asked for the code on a page of its own; a person with no password sees no password form in the account and gives the code alone to switch TOTP off. The account shows the identity the user is linked to (read only: a global master links and unlinks, in the user's page under *Administration*). A group has no identity.
- **Storage.** The page keeps the chosen language in `localStorage` and nothing else: no token, no zone data, no secret.
- **Files.** The interface is in the package (`webadmin/ui/`); the page asks for the version of the service after the sign-in and tells the person to reload when it differs from its own (the service was upgraded while the page was open).

## SIGNING IN WITH AN IDENTITY PROVIDER

People can sign in with an OpenID Connect identity provider (Keycloak, an enterprise IdP, ...) instead of, or besides, a password. The service is a confidential client of the authorization code flow with PKCE. It makes no account for a person who signs in: a **global master links** a user of the service to the person's identity at the provider, and a sign-in whose identity is linked to nobody is refused. Setting it up takes four steps; the examples use the invented provider `idp.example.test`.

**1. Register the service at the provider.** Make a client of the type "confidential" with the authorization code flow and PKCE (S256), and give it this redirect URI, exactly (the provider compares it as text):

```
https://dns.example.test/api/v1/auth/oidc/corp/callback
```

that is `public-origin`, `/api/v1/auth/oidc/`, the name you give the provider in the next step, and `/callback`. Note the client id and the client secret. The provider must sign ID tokens with RS256, ES256 or EdDSA (the usual default is RS256) and publish a discovery document at `<issuer>/.well-known/openid-configuration`.

**2. Put the secret in a file and the provider in the configuration.**

```
install -o karidns-webadmin -g karidns-webadmin -m 0600 /dev/null /usr/local/etc/karidns/oidc-corp.secret
printf '%s\n' 'the-client-secret' > /usr/local/etc/karidns/oidc-corp.secret     # one line
```

and at the end of `karidns-webadmin.conf` (after the global settings):

```
[oidc corp]
issuer = https://idp.example.test/realms/corp
client-id = karidns-webadmin
client-secret-file = /usr/local/etc/karidns/oidc-corp.secret
label = Corp ID
# scopes = openid                (default; "openid" is always asked for)
# mfa = totp                     (default; see below)
```

`issuer` is the issuer identifier **exactly as the provider writes it** in its discovery document and in its ID tokens (a trailing slash counts: some providers have one). `label` is the text of the button on the sign-in screen ("Sign in with Corp ID"). Up to 8 providers; each name is 1 to 32 characters (lower case letters, digits, `-`, `_`) and each issuer once. `service karidns_webadmin oneconfigtest` checks that the secret file is the service user's and has mode 0600 or 0400, and names the redirect URI of each provider; **it does not contact the provider**. Restart the service (or send SIGHUP: the sections and the secret files are read again, and a mistake in them keeps the old ones). The service fetches the discovery document and the key set when it starts and says so in the log (`oidc: provider corp (...) is reachable`, or `... cannot be used yet: <why>`); a provider that is down at that moment does not stop the service, and is asked again at the next sign-in, at most every ten seconds.

**3. Allow the egress.** The service now makes outbound HTTPS requests: to the host of the issuer (the discovery document), and to the hosts the discovery document names for the key set (`jwks_uri`) and the token endpoint (`token_endpoint`), which are often, but not always, the same host. If the machine's firewall (`pf`) restricts outgoing connections, allow `karidns-webadmin` to reach those. Each request has 10 seconds and a size limit, follows no redirect, and refuses an address that is not https, has credentials, or is an IP address. The proxy in front of the service needs nothing new: the browser, not the service, talks to the provider's authorization endpoint, and it comes back to `public-origin` like any visitor.

**4. Link the users.** In the web interface: *Administration*, the user, *Identity at a provider*: the provider, the **subject**, *Link the identity*. The subject is the `sub` claim of the person's ID token, the provider's own identifier for them (many providers show it in the user's page; it is **not** the e-mail address or the login name, which can change hands: the service never matches on those). The same through the API:

```
curl -b jar -H "X-KariDNS-CSRF: $CSRF" -H "Origin: https://dns.example.test" -H 'Content-Type: application/json' \
     -X PUT -d '{"issuer":"https://idp.example.test/realms/corp","subject":"8f14e45f-ceea-4672-a1b0-0c5f4a1f6c11"}' \
     https://dns.example.test/api/v1/principals/12/oidc
```

If you do not know the subject yet, have the person press the button: the sign-in is refused, and the log says which subject it came with (`auth: oidc corp: sign-in refused from 192.0.2.7: no user is linked to the subject 8f14e45f-...`); link that. A user may be made without a password (`POST /principals` without `password`): such a user signs in with the provider only. Unlinking an identity (or linking another one) signs the user out; **disable the user** to lock a person out for good (their sessions end and the sign-in is refused).

**The second step.** `require-totp` applies to a sign-in with a provider as it does to a password: where it makes TOTP mandatory for a user (every global master with the default `global`), or where the user has TOTP on, the session made by the sign-in can do nothing but the second step: the user sets TOTP up the first time, and gives the code of the authenticator app afterwards (the redirect from the provider has no room for a code field, so the page asks after it). If the provider itself requires two factors and says so in the ID token (`amr`, RFC 8176), set `mfa = idp` in the section: then the step is left out for sign-ins whose token shows two factors (`mfa`, or two of password/PIN, OTP/hardware key/SMS/smart card, fingerprint/face/iris), and only for them. Do that only if you trust the provider's policy as you trust your own: it is then the only second factor.

**What a failed sign-in looks like.** The person returns to the sign-in screen with one message ("The sign-in with the identity provider was not accepted"), whatever the reason: a subject that is linked to nobody, a disabled or locked user, an ID token with a bad signature, a wrong audience or nonce, a state that is used already or too old, a callback address that was handed to another browser. The reason is in the log (`auth: oidc corp: sign-in refused from <address>: <reason>`), without secrets; read it to answer "why can't Taro sign in?". The message "cannot be reached" means the provider or the database did not answer; "too many attempts" means the rate limit of logins (`rate-login`, a minute, per address; the start and the callback each count) was hit.

**Operating notes.**

- A provider that rotates its signing keys needs nothing from you: a token with a `kid` the service does not know makes it fetch the key set again (at most once a minute).
- A provider that changes its issuer or a client secret that is renewed: edit the section and send SIGHUP. Identities are linked to the **issuer string**; if the issuer changes, link the users again.
- Clocks: the service accepts an ID token a minute either side of its time (`exp`, `iat`). Keep the clock of the machine right (`ntpd`).
- The unfinished sign-ins are in `karidns_auth.oidc_states` (PostgreSQL) or the table `oidc_states` of the auth file (SQLite3): ten minutes each, at most 1000, deleted when used and swept every hour. The table is not audited and holds no secret that the provider's answer could use (the PKCE verifier is useless without the provider's code and the client secret).
- On PostgreSQL the API role has no right on that table: `db/karidns_ext.pgsql.sql` (schema version 3) makes it and the three functions the role calls; **run it again** (and `db/karidns_api_role.pgsql.sql`, which grants `EXECUTE`) when you upgrade from a build made before the sign-in with a provider. On SQLite3 run `db/karidns_auth.sqlite3.sql` again; `--check` names a missing table.

## RUNNING IT

```
service karidns_webadmin start | stop | restart | status
service karidns_webadmin configtest      # karidns-webadmin --check as the service user
service karidns_webadmin reload          # SIGHUP: reads the configuration again
```

`rc.conf` variables: `karidns_webadmin_enable`, `karidns_webadmin_config` (default `/usr/local/etc/karidns/karidns-webadmin.conf`), `karidns_webadmin_user` (default `karidns-webadmin`; rc.subr runs `daemon(8)` as this user with `su -m`), `karidns_webadmin_flags`. The script makes the directory of the TOTP key and `/var/run/karidns_webadmin` for the service user, sets `ulimit -c 0`, and starts the program under `daemon -r`, which starts it again 10 seconds after it dies (for example because the database was down at boot). **Standard error goes to /dev/null under the rc script: set `log = daemon` (or another syslog facility) in the configuration file.** If the database is on this host, start it first (add its service name to `REQUIRE` in the rc script or to the `rcorder` of your site).

SIGHUP changes the rate limits, the session times, `require-totp`, `public-origin`, `trusted-proxy` and `scrypt-ln`; the database, the datasets, `workers`, the paths of the tools, the listen address and the TLS files need a restart. A configuration with a mistake is refused and the old settings stay (the log says why).

### The log

One line per request, to syslog (`logger(1)`, tag `karidns-webadmin`, `notice`): `<client address> <request id> <user or -> <METHOD> <route template> <status> <ms>ms [cs=<change set>]`. Never the query string, a body, a password, a cookie, a token, or a TOTP code; the user name of an unknown login is not logged either (what was typed there may be a password). The request id is also in the `X-Request-Id` header and in every error document: a user who reports a 500 gives you the id and the log has the rest.

| Line | Means |
|---|---|
| `auth: <user> logged in from <address>` | a login |
| `auth: login refused for <user> from <address>` | a wrong password, a locked account, a user without a password; for a name that does not exist: `an unknown or disabled user` |
| `auth: <user> is locked after N failed logins` | ten failures in a row (also from the password form and the TOTP form of a logged-in session): 15 minutes, doubling for every further failure, a day at most; a new password from an administrator ends the lock |
| `<id>: row level security refused what the API allowed (a bug)` | PostgreSQL: the database refused a statement the service had allowed; the answer was 500. Report it with the id |
| `<id>: karidns-zone apply failed (exit status N): ...` | a tool broke or is not the version the service expects |
| `<id>: karictl reload <zone> failed: ...` | SQLite3: the reload did not happen; the change is in the database |

### What to watch

- `GET /api/v1/health` (no login): 200, or 503 when the database does not answer within 3 seconds. It is cheap and may be polled once a second.
- `GET /api/v1/servers` (PostgreSQL): per DNS server the generation it applied and the zones that failed to load.
- Errors with code `internal` (500) and the lines above; `busy` (503) answers mean the tools pool (`workers`, 64 more may wait) or the database is saturated.
- The sessions table stays small by itself: the service deletes expired sessions (and, with identity providers, the sign-ins that never came back) at the start and every hour.
- Lines `auth: oidc NAME: sign-in refused from ADDRESS: REASON` are the answer to "why can't she sign in?"; many of them from one address are somebody trying; `oidc: provider NAME ... cannot be used yet` is the provider's documents not coming (the egress, the issuer, the provider down).
- Disk: the audit log (`karidns_auth.audit_log`, or `karidns_audit_log` and `karidns_auth_audit` on SQLite3) grows with every change and is never pruned by the service. Prune it as the owner when your policy says so: `DELETE FROM karidns_auth.audit_log WHERE at < now() - interval '1 year'`.

## BACKUP, RESTORE, UPGRADE

**Back up** the zone data and the auth data together, and the **TOTP key file** with them: without that key the TOTP secrets in the database cannot be read and every TOTP user has to enrol again (below). PostgreSQL: `pg_dump` of the database (the schema `karidns_auth` is in it; `-n karidns_auth -n public` for the parts). SQLite3: `sqlite3 zones.sqlite3 ".backup /backup/zones.sqlite3"` and the same for `auth.sqlite3` (the online backup of SQLite, not `cp`: the files are in WAL mode). Keep the backup as protected as the live files: it holds the password hashes.

**Restore** the database, then the key file with its mode (0600, the service user), then `service karidns_webadmin configtest`. Sessions and tokens come back with the database; a restored session older than its idle time is simply dead.

**Upgrade.** `pkg add` the new `karidns-webadmin` package (the program is replaced, the configuration and the key file stay). Apply the new SQL files again (they only create what is missing and replace the functions: PostgreSQL `karidns_ext.pgsql.sql`, then the role scripts; SQLite3 `karidns_ext.sqlite3.sql`, `karidns_audit.sqlite3.sql`, and `karidns_auth.sqlite3.sql` on the auth file), run `service karidns_webadmin configtest` — it names a schema that is not at the version the service wants — and restart. Upgrade `karidns-zone` and `karicheck` with the same release: the service refuses a `karidns-zone` that speaks another JSON schema.

**Rotate the TOTP key.** There is no re-wrapping: a new key makes every stored TOTP secret unreadable. Stop the service, remove `totp.key` (a new one is made at the next start), and switch TOTP off for every user as the database owner (`UPDATE karidns_auth.credentials SET totp_enabled = false, totp_secret = NULL;`, or the same on the `credentials` table of the auth file); the users enrol again, a global master at its next login.

### When someone is locked out

| Case | Remedy |
|---|---|
| a user forgot the password | an administrator: `PUT /api/v1/principals/{id}/password` (this also ends the lock and the user's sessions) |
| a user lost the TOTP device | an administrator: `POST /api/v1/principals/{id}/credentials {"action":"reset-totp"}` (TOTP is off, the secret is gone, the user's sessions end; a global master enrols again at the next login). Not for oneself: ask another global master. Without an administrator who can log in, as the database owner: `UPDATE karidns_auth.credentials SET totp_enabled = false, totp_secret = NULL WHERE principal_id = <id>;` |
| an account is locked (ten failed logins) | an administrator: `POST /api/v1/principals/{id}/credentials {"action":"unlock"}` (the count and the lock go, the password stays); or wait out the lock (15 minutes, twice as long for every further failure, a day at most) |
| every administrator is locked out | `karidns-webadmin --create-admin another-name` (PostgreSQL: with `--bootstrap-conninfo-file`) as above |
| a token leaked | `DELETE /api/v1/tokens/{id}` (the owner or an administrator); disabling a user revokes its tokens and ends its sessions |

## SECURITY

What the service does, in short (the details are in the [API reference](karidns-api.md), "Security"):

- **Hostile input.** Every request body has a fixed shape; unknown fields are refused. Names are canonicalised and checked against the zone at a label boundary before anything else. The text of a record is checked for what could end its line or hide the rest of it, and `karidns-zone` checks it again. Every SQL value is a bound parameter; every word given to a program was checked first; no shell is involved. Limits: headers 16 KiB, body 1 MiB (zone import 16 MiB), a change set of 1000 RRsets with 1000 records each, 256 connections, 30 seconds for a body (300 for an import).
- **Sessions.** A 256-bit cookie (`HttpOnly`, `SameSite=Strict`, `Secure` under https, `Path=/api/`); the database keeps only its SHA-256. Idle time 30 minutes, 12 hours at most; a new session at the login and after the TOTP step; a disabled user's sessions end. Cookie plus token in one request is refused. CSRF: the `X-KariDNS-CSRF` token, the `Origin`, and `application/json`.
- **Passwords** are scrypt hashes (128 MiB, two at a time); a wrong user and a wrong password cost the same time and give the same answer; ten failures lock the account for 15 minutes and longer. Asking for the password again (change it, switch TOTP off) is limited like a login.
- **Rate limits** (in memory): 5 logins a minute per address and per user name, 20 requests a second and 2 writes a second per principal. A flood of requests with bad credentials is limited per address but still costs a database lookup each: put a rate limit in the proxy (the nginx example does).
- **Identity providers**: an ID token is accepted only with a signature of the provider's own key set (never `none`, never a shared secret), for this client, with the nonce of this sign-in, and for a user a global master linked to that identity; no account is made by a sign-in. The state of a sign-in is single use and tied to the browser that began it. The provider can sign in as the users linked to it and do nothing else; its documents are read with size and time limits, without redirects, and only from https names. The details are in the [API reference](karidns-api.md), "OpenID Connect".
- **The web interface**: its files are read once at the start and served from memory (no path to traverse, no directory to list, GET and HEAD only); the page's policy allows no inline script or style, nothing from another origin, no frame, and no HTML string (Trusted Types), and the page tells the person when a proxy or an extension made the browser block something; every text that comes from the service (zone data, names, comments, the rows of the audit log, error texts) is drawn as text, with control, right-to-left and zero-width characters made visible, and no address, attribute or style is ever built from it (a name that is `.` or `..` is "not found": the browser would take it out of an address and the request would reach another resource); the CSRF token is kept in memory and the cookie is not readable by the page; the answers of the API carry `Cross-Origin-Resource-Policy: same-origin` like the files. The tests scan the source (`ui_scan.test.js`), run the screens against hostile data on a fake DOM and in Firefox, and the review of milestone M6 is `ui_review.test.js`.
- **Secrets**: see the table of files. The service never logs a secret and never reads the key material of the DNSSEC keys.

What it does **not** do, so that you can decide:

- On **SQLite3** whoever can write the files bypasses every rule. On PostgreSQL `karidns.principal` is a setting any session of the API role can make: the service is trusted to set it to the logged-in user; RLS catches mistakes of the service, not a compromised service process.
- Every logged-in user can **list all users, groups and record policies** (`GET /principals`, `/rr-policies`: their names are needed to grant). In a deployment with tenants that must not see each other's user names, do not give them accounts, or put the API behind your own front end.
- A **global master** can do everything the service can, and a stolen global master session (with its TOTP step done) is that. Keep few of them; use domain masters for day-to-day work.
- A subdomain master or domain master can ask for a reload (`POST .../reload`) of a zone it has a grant on, up to 2 requests a second.
- There is no per-request audit of reads; the audit log records changes.

## MEASUREMENTS

Measured on 2026-11-08 on the FreeBSD 15.1 build host (a jail with 4 vCPU on a shared host; PostgreSQL 18.6 with `shared_buffers` 128 MB in a private cluster; Node 24.22; the service, `karidns-zone` and the database on the same host; one request at a time; the median of 3 to 5 requests; times are the client's, including the HTTP round trip and, for a change set, both runs of `karidns-zone`). They are what `tests/run_webadmin_write_test.sh` and `tests/run_webadmin_write_pg_test.sh` print as `[COST]` lines (`BIG=1000` or `BIG=100000` makes the big zone). The zone is half A records and half TXT records, one RRset per record.

**A change set of one RRset** (a `PATCH .../rrsets` of one record: the check run, the permission check, the commit run; the dry run is the check run alone):

| Zone | SQLite3 dry run | SQLite3 change set | PostgreSQL dry run | PostgreSQL change set |
|---|---|---|---|---|
| 15 records | 12 ms | 20 to 23 ms | 30 ms | 60 to 63 ms |
| 1,000 records | 15 ms | 24 ms | 35 ms | 81 to 84 ms |
| 100,000 records | 464 to 467 ms | 576 to 579 ms | 546 to 550 ms | 1.9 s |

A subdomain master pays about the same (SQLite3: 581 ms at 100,000 records) or less (PostgreSQL: 0.8 s; the commit run under row level security tests each row against the policy, and a subdomain master's policy is cheaper to test than a global master's name test, below). The cost is two runs of `karidns-zone`, each of which reads the zone once, so it grows with the size of the zone, not with the size of the change. The reload and the loader's work come on top. The tools run `workers` at a time; a burst beyond that waits, and beyond 64 waiting answers 503.

**Reading RRsets** (`GET .../rrsets?limit=500`, the median of the first 20 pages of the 100,000-record zone, 500 RRsets a page):

| Reader | SQLite3 | PostgreSQL (row level security) |
|---|---|---|
| global master | 40 ms | 683 ms |
| domain master | 39 ms | 161 ms |
| subdomain master (half of the zone) | 38 ms | 103 to 237 ms |

Zone of 1,000 records, one page of 500: 5 to 7 ms (SQLite3), 8 to 17 ms (PostgreSQL). A page costs a pass over the zone's rows after the cursor (the keys are sorted, the first 501 kept), so every page of a big zone costs about the same, not more the deeper it is. On PostgreSQL the policy of a global master tests every row with the function `name_in_zone` (the exact name test of A-23: a row of the zone's `domain_id` whose name is outside the zone stays invisible), which is why a global master reads *slower* than a domain master, whose rows are covered by a grant on the zone with no function call per row; both are a few times what SQLite3 costs without any policy.

**Reading for the web interface** (item F; the same host and method, measured on 2026-11-09 by `tests/run_webadmin_write_test.sh` and `..._write_pg_test.sh` with `BIG=100000 ZONES=10000`: a zone of 100,000 records and 10,000 more zones with no records; a global master unless said; the median of 3):

| Request | SQLite3 | PostgreSQL |
|---|---|---|
| `GET .../rrsets?limit=500` (the comparison) | 39 ms | 191 ms |
| ... with `rdata=1` (one run of `karidns-zone render` for the 500 RRsets) | 56 ms | 202 ms |
| ... with `from=` the middle of the zone | 43 ms | 187 ms |
| ... with `contains=` a text no owner has (the whole zone scanned) | 33 ms | 742 ms |
| ... with `contains=` a text half of the zone has, the first page | 49 ms | 501 ms |
| ... `contains=` a text no owner has, as a domain master / a subdomain master | 30 / 31 ms | 174 / 207 ms |
| `GET .../zones?limit=100` of 10,002 zones | 16 ms | 1113 ms |
| ... with `contains=` a text one zone has | 3 ms | 362 ms |
| ... with `prefix=` (the comparison) | 3 ms | 357 ms |
| ... with `contains=` a text no zone has | 3 ms | 32 ms |

`rdata` costs about 20 to 35 microseconds a record (17 ms for a page of 500 records on SQLite3, 11 ms on PostgreSQL): each record is read by the loader's reader inside a small zone of its own and written by the zone-file writer, twice (the second time to prove that the text reads back as the same record). `contains` on RRsets is a scan of the zone's rows: on SQLite3 it costs no more than a page, on PostgreSQL a global master's scan costs 3 to 4 pages (the policy of a global master tests every row, above) and a domain or subdomain master's scan about what a page of its own costs; it is one request for a search box, not something a page load makes. `from` is an index range and costs a page. On the zone list the scan for `contains` is as cheap as the `prefix` comparison.

**Statistics matter.** A table that has just been filled (`karidns-zone import` of a big zone) has no statistics for the planner until the analyze of autovacuum has run (within about a minute of the load). An earlier version of the page query joined the keys with the records, and without statistics PostgreSQL planned a nested loop that tested the policy 500,000 times: **2.9 seconds** for one page of a zone of 1000 records, and 0.9 s (global master) for a zone of 100,000. The query is two statements now (the keys, then the records of those names): without statistics, 21 ms at 1000 records and 0.7 s at 100,000 (global master). After a big import you can run `ANALYZE` on the PowerDNS tables by hand; nothing breaks if you do not.

**Memory.** `karidns-zone apply --dry-run` (the check run) of a zone of 1,000 records: 12 MB resident; of 100,000 records: 87 MB; `export` of 100,000 records (2.3 MB of text): 128 MB. With `workers` at 4 that is up to 4 of them at a time, and an export is limited to 256 MiB of output. The service itself is about 100 MB resident when idle. A password hash at the default `scrypt-ln = 17` needs 128 MiB while it runs and takes 240 to 250 ms (`scrypt-ln = 14`: 30 ms; 19: 1 s); at most two run at a time, so a burst of eight logins takes about a second and holds 256 MiB, and more than 64 waiting answers 503.

**Not measured:** more than one request at a time (the pool and the rate limits bound it; nothing was loaded to find the limit), several DNS hosts, a database on another host, and the loader's reload of a big zone (that is the loader's: [`karidns-dbloader(8)`](karidns-dbloader.md), "Measurements").

## TROUBLESHOOTING

| You see | Because | Do |
|---|---|---|
| `--check`: `api-conninfo-file: ... has mode 0644` | the connection file is readable by others | `chmod 0600`, `chown karidns-webadmin` |
| `--check`: `karidns-zone has no postgresql driver` | the package with `karidns-zone` has another driver than `database` | install `karidns-postgresql` or `karidns-db` (or `karidns-sqlite3` for SQLite3) |
| `--check`: `the schema version is 2/3 (auth/data), 3 is needed` | the SQL files of this release are not applied | apply them (above) |
| `--check`: `listen ... is not a loopback address: plain HTTP is only allowed on ...` | a public address without TLS | `127.0.0.1`, a UNIX socket, or `tls-cert` and `tls-key` |
| the service restarts every 10 seconds | it cannot start (the database is down, a file has the wrong mode); standard error is /dev/null | `service karidns_webadmin configtest`; look in the syslog |
| login: 401 `invalid-credentials` for a right password | the account is locked (ten failures), disabled, or has no password | wait, or an administrator sets a password |
| login: 403 `csrf` | the `Origin` header is not exactly `public-origin` (scheme, host, port) | fix `public-origin` or the proxy's host name |
| login: 429 | five logins a minute per address or per name; behind a proxy without `trusted-proxy` every client is one address | set `trusted-proxy` |
| a write: 403 `csrf` | the cookie request lacks `X-KariDNS-CSRF` or `Origin` | send both (the token is in the login answer and in `GET /auth/me`), or use a token |
| a write: 403 `totp-required` | a global master's session before its TOTP step | enrol and confirm ([The first login](#totp-the-first-login)) |
| 500 `internal` | a bug or a broken installation; the body has only the request id | find the id in the log |
| 503 `busy` | the pool of tool runs is full (`workers` + 64), or the database is busy (SQLite3 `busy_timeout` 5 s) | retry; raise `workers` |
| 409 `changed` | the zone kept changing under the request (another writer, the signer) | retry |
| a change is in the database but the DNS answer is old | no reload was asked for | `POST .../reload`, or `reload: true`, or `reload-after-change = yes`; a zone the signer keeps signed is reloaded by the signer |

## SEE ALSO

[User manual of the web interface](karidns-webadmin-gui.md) (the screens by role, the messages, the measurements, the glossary) and its [accessibility and browser checklist](karidns-webadmin-gui-checklist.md), [API reference](karidns-api.md) (`karidns-webadmin(8)`: every endpoint, error and setting), [`karidns-zone(1)`](karidns-zone.md), [`karidns-dbloader(8)`](karidns-dbloader.md) ("The auth schema, roles and the audit log"), [`karidns-signer(8)`](karidns-signer.md), [`karictl(1)`](karictl.md) (restricted control keys), [`karicheck(1)`](karicheck.md).
