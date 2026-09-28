# KARICTL(8) — KariDNS Reference Manual

```text
KARICTL(8)                     KariDNS Manual                     KARICTL(8)
```

---

## NAME

**karictl** — Remote Control and Management Utility for KariDNS

---

## SYNOPSIS

```sh
karictl [-c config_path | -f config_path] [-s socket_path] <command> [arguments...]
karictl -v | --version
karictl tsig-keygen [keyname]
```

---

## DESCRIPTION

`karictl` is the management utility for the [`karidns(8)`](karidns.md) authoritative DNS server daemon. It communicates with the daemon over a local UNIX domain socket (default `/var/run/karidns/control.sock`) and authenticates each connection with an HMAC-SHA256 challenge-response handshake: the server sends a 64-character challenge, and `karictl` answers with the HMAC-SHA256 of the challenge keyed with the shared secret.

---

## OPTIONS

`-c config_path`, `-f config_path`
: Path to the `karictl` configuration file (default: `/usr/local/etc/karidns/karictl.conf`; if that file does not exist and `/usr/local/etc/karictl.conf` does, the latter is used).

`-s socket_path`
: UNIX domain socket to connect to. Takes precedence over the `socket` setting of the configuration file (default: `/var/run/karidns/control.sock`).

`-v`, `--version`
: Display version information and exit.

---

## COMMANDS

Commands that take a zone name accept an optional view name as the next argument. The view name is required when the zone exists in more than one view; otherwise the command fails with `ERROR zone exists in multiple views; specify view`.

`status`
: Query and display runtime statistics from the running `karidns` daemon:
  - Version, host name, OS, architecture and kernel release, CPU count and worker thread count
  - Server boot time, time of the last (re)configuration and the configuration file path
  - Number of zones and number of running AXFR/IXFR transfers
  - Whether query and response logging are enabled
  - Current and high-water TCP connection counts
  - Frontend process health status
  - Security counters: RRL dropped/slipped responses, Extended DNS Error counters (18 Prohibited, 20 Not Authoritative, 21 Not Supported, other) and truncated dnstap messages

`reload [zone [view]]`
: Without arguments, re-read the configuration file and **all** zone files. With a zone name, reload only that zone: a primary zone re-reads its zone file (errors such as a missing file, a parse error, a missing SOA or a running AXFR are reported), and a secondary zone starts a new transfer from its primary.

`reconfig`
: Re-read the configuration file and apply it (added or removed zones, ACLs, rate limits, ...). Zone files whose modification time has not changed are not re-read. This is the same as sending `SIGHUP` to the server.

`stop`
: Stop the `karidns` daemon.

`notify <zone> [view]`
: Send DNS NOTIFY messages for `<zone>` now: to the `also-notify` servers and to the addresses of the zone's apex NS hosts, except the host named in the SOA MNAME field (RFC 1996 §3.2).

`retransfer <zone> [view]`
: For a secondary zone, discard the current serial and start a new transfer from the primary immediately.

`zonestatus <zone> [view]`
: Display the SOA serial and refresh interval of `<zone>` (`OK serial=<n> refresh=<n>`).

`observatory [zone [view]]`
: Display per-zone statistics for all zones, or only for the given zone (and view): role (primary/secondary), SOA serial, query counts (total and TCP), response codes (NOERROR, NXDOMAIN, NODATA, SERVFAIL, REFUSED), EDNS/DO/ECS query counts, RRL dropped/slipped counts, successful inbound AXFR/IXFR transfers (secondary) or NOTIFY messages sent (primary) with the time of the last one, and wire-cache hits, misses and size.

`tsig-keygen [keyname]`
: Generate a 256-bit random TSIG secret with OpenSSL `RAND_bytes(3)` and print a `key` block (`algorithm hmac-sha256`) ready for `karidns.conf`. The default key name is `transfer-key`. This command does not contact the server and does not read the configuration file.
  ```sh
  karictl tsig-keygen transfer-key
  ```

---

## CONFIGURATION FILE (`karictl.conf`)

By default, `karictl` reads the shared secret from `/usr/local/etc/karidns/karictl.conf`. The package installs `karictl.conf.sample` next to it.

### Configuration Syntax

```
socket "/var/run/karidns/control.sock";

key "karictl" {
    algorithm "hmac-sha256";
    secret "UkVQTEFDRS1NRTpvcGVuc3NsLXJhbmQtYmFzZTY0LTMy"; // placeholder: replace with `openssl rand -base64 32`
};
```

The `secret` defined in `karictl.conf` must match the secret configured in the `control-channel` block of [`karidns.conf`](karidns.md).

The file is not parsed as a full configuration file: `karictl` takes the quoted value that follows the **first** occurrence of the word `secret`, and the quoted value that follows the first occurrence of the word `socket`, anywhere in the file (comments included). The key name and `algorithm` are not used; the control channel always uses HMAC-SHA256. The secret may decode to at most 256 bytes. `karictl` prints a warning when the file is readable by group or other users; it should have mode `0600`.

---

## EXIT STATUS

`0`
: Command executed successfully (including `tsig-keygen` and `-v`).

`1`
: Usage error, socket path too long, connection failure to the control socket, or failure to receive the challenge.

`2`
: The secret could not be read or decoded from the configuration file, the challenge was invalid, or authentication failed.

`3`
: The server returned an error (`ERROR ...`) or an invalid `observatory` response.

---

## FILES

`/usr/local/etc/karidns/karictl.conf`
: Default control channel client configuration file.

`/var/run/karidns/control.sock`
: Default UNIX domain socket endpoint monitored by the `karidns` daemon.

---

## SEE ALSO

- [`karidns(8)`](karidns.md) — KariDNS authoritative DNS server daemon
- [`karicheck(1)`](karicheck.md) — Configuration and zone file validation utility
- [`dag(1)`](dag.md) — DNS anomaly generator and test client
- [`KariDNS RFC Guideline`](../KariDNS_RFC_GUIDELINE.md) — Detailed RFC compliance and design boundary document

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

```text
KariDNS                         September 2026                    KARICTL(8)
```
