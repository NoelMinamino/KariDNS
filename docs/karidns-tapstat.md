# KARIDNS-TAPSTAT(1) — KariDNS Reference Manual

```text
KARIDNS-TAPSTAT(1)               KariDNS Manual               KARIDNS-TAPSTAT(1)
```

---

## NAME

**karidns-tapstat** — Aggregates the dnstap stream of `karidns` into periodic query statistics

---

## SYNOPSIS

```sh
karidns-tapstat -s socket [options]
karidns-tapstat -r file [options]
karidns-tapstat -V | -h
```

---

## DESCRIPTION

`karidns-tapstat` is the "query analytics" tool of KariDNS. The server does not analyse queries itself (nothing is added to the query path beyond the existing counters and [dnstap](https://dnstap.info/)); this separate program consumes the dnstap stream and counts, per interval:

- the **zone** the query belongs to,
- the query name (**qname**),
- the query type (**qtype**),
- the response code (**rcode**), and
- the **client prefix** (the client address cut to /24 for IPv4 and /56 for IPv6).

It works in one of two ways:

- `-s socket` — it listens on a UNIX domain socket as a **Frame Streams** receiver. `karidns` (or any dnstap sender) connects to that socket (`dnstap { socket "..."; }`), the two sides run the bidirectional handshake (the sender's READY, the receiver's ACCEPT, the sender's START), data frames follow, and the sender ends with STOP, which the receiver answers with FINISH. Every `-i` seconds it writes a summary and starts over. A sender that goes away is simply reconnected by `karidns`; several senders may be connected at once (up to 16), and their frames are added together.
- `-r file` — it reads a Frame Streams file (START, data frames, optional STOP; `-` reads standard input) and writes one summary at the end.

The summary goes to standard output, or, with `-o`, into a file that is replaced atomically. Nothing is uploaded or sent anywhere: files and standard output only.

`karidns-tapstat` is an ordinary unprivileged process (it is not in Capsicum capability mode). Run it as its own user. It is a POSIX program (FreeBSD, Linux, macOS); it is not part of the Windows build of `dag`.

### Input is untrusted

Everything on the socket and in the file is treated as hostile: Frame Streams lengths are capped before a buffer is sized from them (data frames 256 KiB, control frames 512 bytes), every protobuf field is bounds-checked, only the DNS header and question are read from the embedded DNS message, and a sender that breaks the protocol (data before START, a wrong content type, an oversized frame, ...) has its connection closed with a message on standard error. A sender that does not finish the handshake within 5 seconds is dropped. The content type accepted is `protobuf:dnstap.Dnstap`.

### What is counted

`karidns` sends `AUTH_QUERY` and `AUTH_RESPONSE` messages (`dnstap { log-queries yes; log-responses yes; }`; both by default).

- The zone, qname, qtype and client tables count the messages of one type, chosen with `-t`: `response` (default) or `query`. With `-t response` the messages of the other type are only counted in the totals. If `karidns` is set to log queries only, use `-t query`.
- The rcode table always counts `AUTH_RESPONSE` messages (a query has no response code). It is the low four bits of the DNS header (RFC 1035 section 4.1.1); the EDNS extended part (RFC 6891) is not added.
- **Zone**: with `-z` (or `-Z`) the zone is the longest listed name that the query name is at or below (compared label by label, case-insensitive); a name below none of them is `other`. Without a zone list, the zone that the server put into the dnstap message (`query_zone`) is used; a message without one (REFUSED, ...) is `other`.
- **Client prefix**: the `query_address` of the message. An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is counted as IPv4. `-4` and `-6` change the prefix lengths.
- The query name is lower-cased and written in master-file notation (a dot inside a label as `\.`, unprintable bytes as `\DDD`). It is read from the question of the message, which must not be compressed; a message whose question is malformed is counted under `malformed` and not in the name tables.

### Bounded memory

Each of the five tables holds at most `-k` keys (default 10000; qname keys take about 280 bytes each, so `-k 1000000` needs roughly 300 MB for that table; the other tables are much smaller). The tables use the **Space-Saving** algorithm (Metwally, Agrawal and El Abbadi, "Efficient Computation of Frequent and Top-k Elements in Data Streams", 2005): while there is room a new key is added; when the table is full, a key that is not in it replaces the kept key with the smallest count and inherits that count, then counts its own event. Memory is fixed by `-k` (a min-heap and a hash index, nothing allocated per event, O(log k) per event). The result is a list of the heaviest keys of the interval that does not depend on the order of arrival: a heavy name that first appears after the table filled up still gets into the list. The price is that a count may be too high. For every listed key the true count lies between `count - error` and `count`; `error` is the count the key inherited when it replaced another key (0 for a key that was never in doubt). Every key whose true count is above `events / k` is certainly in the list, and the counts of all kept keys add up to `events`. `evictions` is the number of events that replaced a key; with 0 evictions all counts are exact. Choose `-k` large enough that the keys you care about stay well above `events / k`. The tables are reset after every summary, so memory never grows with time. The hash of the tables is keyed with a random value drawn at start, so names cannot be chosen to collide.

---

## OPTIONS

`-s socket`
: Listen on this UNIX socket. A stale socket file of an earlier run is removed; a socket that another process still listens on, or any other kind of file, is an error. The file is created with mode `660` (see `-m`) and removed again on exit. A UNIX socket path holds at most 103 bytes.

`-r file`
: Read a Frame Streams file. `-` is standard input.

`-z names`
: Comma-separated zone names (`example.test,example.org`). May be given more than once. Names are written without escapes; `.` is the root zone.

`-Z file`
: Zone names, one per line; `#` starts a comment.

`-i seconds`
: Summary interval for `-s`, 1 to 86400 (default 60). Not used with `-r`.

`-f format`
: `text` (default), `json` (one line per summary) or `prom` (Prometheus text exposition format).

`-o file`
: Write each summary to this file, replacing the previous one: the text is written to `file.tmp.<pid>` in the same directory and renamed, so a reader (for instance the node_exporter textfile collector) never sees a half-written file. The file is created with mode 644. Without `-o`, summaries are appended to standard output.

`-k n`
: Keys kept per dimension, 1 to 1000000 (default 10000).

`-n n`
: Entries printed per dimension, most frequent first (default 20; 0 = all that are kept).

`-t type`
: `response` (default) or `query`: the message type counted for zone, qname, qtype and client.

`-4 bits`, `-6 bits`
: Client prefix lengths, 0 to 32 (default 24) and 0 to 128 (default 56).

`-m mode`
: Octal permission of the socket file (default `660`). The sender (`karidns`) must be able to connect to the socket: the Backend of `karidns` connects through its unprivileged broker, so give the socket a group or mode that the user of `karidns` can write to.

`-V`, `--version`
: Print the version.

`-h`, `--help`
: Print the usage.

On `SIGINT` or `SIGTERM` the summary of the interval in progress is written and the program exits.

The exit status is 0, 1 for a runtime error (a bad file, a protocol error in a file, a failing output) and 2 for a usage error.

---

## OUTPUT

### text

```text
karidns-tapstat 2026-11-11T12:00:00Z - 2026-11-11T12:01:00Z (60.0 s)
frames 1204  bad 0  queries 0  responses 1204  other-messages 0  no-question 0  malformed 0
zone: events 1204  keys 2  evictions 0
         900  example.test.
         304  other
qname: events 1204  keys 87  evictions 0
         211  www.example.test.
         ...
qtype: events 1204  keys 4  evictions 0
         ...
rcode: events 1204  keys 3  evictions 0
         ...
client: events 1204  keys 5  evictions 0
         610  192.0.2.0/24
         ...
```

A key that may be over-counted is followed by `(may be over-counted by up to E)`; see "Bounded memory". `frames` is the number of dnstap frames, `bad` those that could not be decoded, `other-messages` those of a message type that is neither query nor response, `no-question` messages with an empty question section, `malformed` those whose question could not be read.

### json

One JSON object per summary on one line: `start`, `end`, `seconds`, the counters above (`frames`, `bad_frames`, `queries`, `responses`, `other_messages`, `no_question`, `malformed`) and `dimensions`, an object with `zone`, `qname`, `qtype`, `rcode` and `client`, each `{"events":N,"keys":N,"evictions":N,"top":[{"key":"...","count":N,"error":N},...]}`; `count` may be too high by up to `error` (Space-Saving).

### prom

Gauges for the interval just ended (the counters restart after every summary, so they are not Prometheus counters): `karidns_tapstat_interval_seconds`, `karidns_tapstat_last_summary_timestamp_seconds`, `karidns_tapstat_messages{kind=...}`, `karidns_tapstat_events{dimension=...,kind="total"|"evictions"}`, `karidns_tapstat_count{dimension=...,key=...}` for the most frequent keys and `karidns_tapstat_count_error{dimension=...,key=...}` for the over-count bound of each key where it is not 0. Label values are escaped as the format requires (`\\`, `\"`, `\n`). With `-o` into the textfile directory of node_exporter this gives query statistics without opening another port.

---

## EXAMPLES

Statistics of two zones as a Prometheus textfile, refreshed every minute:

```sh
karidns-tapstat -s /var/run/karidns/tapstat.sock -z example.test,example.org -i 60 -f prom -o /var/tmp/karidns_tapstat.prom
```

with, in `karidns.conf`:

```text
dnstap {
    socket "/var/run/karidns/tapstat.sock";
    log-responses yes;
};
```

The 50 most asked names of a recorded Frame Streams file, as JSON:

```sh
karidns-tapstat -r queries.fstrm -f json -n 50
```

---

## SEE ALSO

[`karidns(8)`](karidns.md), [`dag_replay(1)`](dag_replay.md) (replays the same dnstap files), [dnstap](https://dnstap.info/), the Frame Streams protocol (libfstrm, `fstrm_capture`).
