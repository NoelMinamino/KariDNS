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
karictl [-f config_path] [-s socket_path] [-v] <command> [arguments...]
```

---

## DESCRIPTION

`karictl` is the management utility for the [`karidns(8)`](karidns.md) authoritative DNS server daemon. It communicates with the daemon over a local UNIX domain socket (`/var/run/karidns/control.sock`) and authenticates transactions using an HMAC-SHA256 challenge-response handshake.

---

## OPTIONS

`-f config_path`
: Specify the path to the `karictl` configuration file (default: `/usr/local/etc/karidns/karictl.conf`).

`-s socket_path`
: Specify the UNIX domain socket path to connect to (default: `/var/run/karidns/control.sock` or `socket` directive in configuration).

`-v`
: Display version information and exit.

---

## COMMANDS

`status`
: Query and display runtime statistics from the running `karidns` daemon, including:
  - System architecture, OS kernel release, CPU cores, and worker thread count
  - Server boot time and last reconfiguration timestamp
  - Active zone count and in-progress AXFR/IXFR transfer count
  - Query and response logging states
  - Active and high-water TCP connection counts
  - Frontend process health status
  - Security and rate-limiting metrics (RRL dropped/slipped counters, Extended DNS Error [EDE] code counters)

`reload [zone]`
: Reload server configuration and zone files without dropping active network connections. If a `zone` domain name is specified, only that specific zone file is reloaded.

`reconfig`
: Check for changes in `karidns.conf` and apply configuration modifications (such as adding or removing zones, updating ACLs, or adjusting rate-limiting parameters) without reloading unmodified zones.

`stop`
: Instruct the `karidns` daemon to complete in-flight transactions and terminate.

`notify <zone>`
: Manually trigger an outbound DNS NOTIFY message to all configured slave nameservers for the specified `<zone>`.

`retransfer <zone>`
: Force an immediate AXFR zone transfer from the primary master nameserver for the specified slave `<zone>`, regardless of the current serial number.

`zonestatus <zone>`
: Display the operational status, current SOA serial number, and transfer state for `<zone>`.

`tsig-keygen [keyname]`
: Generate a cryptographically secure 256-bit random TSIG shared secret using OpenSSL `RAND_bytes(3)` and print a formatted `key` configuration block ready for inclusion in `karidns.conf` and `karictl.conf`.
  ```sh
  karictl tsig-keygen transfer-key
  ```

---

## CONFIGURATION FILE (`karictl.conf`)

By default, `karictl` reads authentication credentials from `/usr/local/etc/karidns/karictl.conf`.

### Configuration Syntax

```
socket "/var/run/karidns/control.sock";

key "karictl" {
    algorithm "hmac-sha256";
    secret "BASE64_ENCODED_SECRET_HERE=";
};
```

The `secret` defined in `karictl.conf` must match the secret configured in the `control-channel` block of [`karidns.conf`](karidns.md).

---

## EXIT STATUS

`0`
: Command executed successfully and confirmed by the server daemon.

`1`
: Usage error, connection failure to control socket, or socket communication error.

`2`
: Authentication failure or invalid challenge response.

`3`
: Server returned an explicit command execution error.

---

## FILES

`/usr/local/etc/karidns/karictl.conf`
: Default control channel client configuration file.

`/var/run/karidns/control.sock`
: UNIX domain socket endpoint monitored by the `karidns` daemon.

---

## SEE ALSO

- [`karidns(8)`](karidns.md) — KariDNS authoritative DNS server daemon
- [`karicheck(1)`](karicheck.md) — Zone file syntax and ZONEMD validation utility
- [`dag(1)`](dag.md) — DNS anomaly generator and test client
- [`KariDNS RFC Guideline`](../KariDNS_RFC_GUIDELINE.md) — Detailed RFC compliance and design boundary document

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

```text
KariDNS                          August 2026                      KARICTL(8)
```
