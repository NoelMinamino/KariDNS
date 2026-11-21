# dnsqps - a DNS query load generator

`dnsqps` sends DNS queries at a server as fast as the machine it runs on can, or at a rate you set, and reports what came back: queries sent, completed and lost, the queries per second, the latency (average, median, 99th and 99.9th percentile, maximum) and the response codes. It is a tool of its own (it is not a mode of [`dag`](dag.md), and its options need not be dig-compatible), built from this repository's sources on FreeBSD, Linux, macOS and Windows (MinGW). It was written for the benchmarks of KariDNS: a client that tops out at a few hundred thousand queries per second cannot show where a server tops out, so dnsqps has kernel-bypass paths (AF_XDP on Linux, netmap on FreeBSD) next to the portable ones, and a way to measure its own ceiling.

`dnsqps` takes the behaviour and the report format of `dnsperf` and `resperf` as a model only; none of their code is used.

## Building

`make dnsqps` (also part of `make all`). The AF_XDP path is built when `pkg-config` finds `libxdp` and `libbpf` (Debian and Ubuntu: `libxdp-dev libbpf-dev`); without them `--io=xdp` says so and `--io=auto` uses sockets. The netmap path is built on FreeBSD (`net/netmap_user.h` is in the base system). `dnsqps --version` lists the I/O paths of the build.

## Synopsis

```
dnsqps [@server] [options] [+query-options]
dnsqps --reflect [ADDR:]PORT
```

Examples:

```
dnsqps @192.0.2.53 -d queries.txt -l 10              # 10 seconds from a query file, as fast as the server answers
dnsqps -s 192.0.2.53 -d queries.txt -n 1 -Q 50k --json   # one pass over the file at 50 000 queries per second, JSON report
dnsqps -z names.txt --miss 0.1 --qtypes A:80,AAAA:15,MX:5 -N 2000000 -S 5
dnsqps -d queries.txt +dnssec +bufsize=1232 +nsid -n 3   # EDNS with DO, the buffer size and an NSID request
dnsqps -z names.txt --null-target -l 5 -T 2          # the ceiling of this machine, no server
dnsqps --reflect 127.0.0.1:15300 -l 2                # a reflector, for ceiling runs and tests
```

## Queries

**A query file** (`-d FILE`): one query per line, `name [type] [+option ...]`. The type defaults to `A`; `TYPEnnn` is accepted; a line that starts with `#` or `;` is a comment. The options on a line (the dig-style `+options` below) override the command line's for that line only. Every line is checked when the file is read, and a bad one is named (`line 17: ...`). The file is read once into memory; the wire form of every name is kept once and a query is put together from it, so nothing is allocated per query. With several threads the entries of a pass are shared by stride (thread *k* of *n* takes entries *k*, *k+n*, ...); `-n N` is the number of passes over the whole file, without `-n` the file is used again and again until the time or count limit.

**Generated queries** (`-z FILE`): the file lists names (the first field of each line, so a zone file's owner column or a plain list both work). Each query draws a name with a Zipf-like popularity (`--zipf S`, default 1.0; 0 is uniform; the most popular name is the first of the list, the others are spread over the list), a type from `--qtypes A:70,AAAA:20,MX:10` (weights, default `A`) and, with probability `--miss F`, a name that does not exist instead: `nx<i>.<a name of the list>` for one of `--miss-pool N` (default 65 536) different `i`, so the answer is NXDOMAIN from a zone that is served (a name of the list must therefore be under a zone of the server for the share of NXDOMAIN to be what you set). `--seed N` makes a run repeatable (the same seed, the same queries, thread by thread).

**Query options**, in dig's spelling; the default is a query without EDNS and with RD set, as `dig +noedns` (and `dnsperf`):

| Option | Effect |
|---|---|
| `+edns`, `+noedns` | send or do not send an OPT record (RFC 6891) |
| `+bufsize=N` | the UDP payload size announced (default 1232); asks for EDNS |
| `+dnssec` | the DO bit (RFC 3225); asks for EDNS |
| `+nsid` | an NSID request (RFC 5001); asks for EDNS |
| `+cookie` | a client cookie (RFC 7873 4.1, 8 octets, no server cookie), the same for the whole run; asks for EDNS |
| `+cookie=random` | a new random client cookie in every query (dnsqps's own spelling: dig's `+cookie=VALUE` takes hex digits, so there is no clash); the cookie is part of the query, so each one is a client the server has not seen: it measures the COOKIE path without a valid cookie |
| `+cookie=HEX16` | this client cookie, 16 hex digits (dig's `+cookie=VALUE` for a client cookie) |
| `+padding=N` | pad the message to a multiple of N octets (RFC 7830, RFC 8467); 1-512 |
| `+subnet=ADDR[/LEN]` | EDNS Client Subnet (RFC 7871); the address is cut to the prefix |
| `+rd`, `+nord` | the RD flag (default on) |
| `+cd`, `+ad`, `+aa` | the CD, AD and AA flags (off by default) |
| `+opcode=N` | the opcode, 0-15 (for tests) |
| `+class=IN`/`CH`/`HS`/N | the query class (dnsqps's own option) |

`+no` forms exist for each (`+nocd`, `+noedns`, `+nosubnet`, ...). A line of the query file may use all of them; at most 32 different option sets are kept per file.

## Load

| Option | Meaning |
|---|---|
| `-s ADDR`, `@ADDR` | the server (default 127.0.0.1); `-p N` the port (default 53) |
| `-b ADDR` | the source address (needed on a host with several addresses; required by the kernel-bypass paths) |
| `-b ADDR/LEN` | a source prefix, raw paths only: the source address of every query is drawn from the range (see "Many source addresses") |
| `--frame-mem MB` | memory for the pre-built frames of the raw paths (default 1024) |
| `--agent ADDR:PORT`, `--agents H:P,H:P` | several client hosts in one run (see "Several client hosts") |
| `-l SEC` | run time; without `-l`, `-n` and `-N` the default is 30 seconds |
| `-n N`, `-N N` | passes over the query file, total number of queries; the run ends at whichever limit is reached first |
| `-Q N` | **open loop**: N queries per second in all (suffixes `k`, `M`, `G`), a token bucket in every thread |
| `-q N` | **closed loop**: N queries in flight in all, shared by the threads (default 256 per thread); with `-Q` it caps the queries in flight |
| `-T N` | worker threads (default: the CPUs, at most 4); each pins itself to a CPU where the OS allows it (`--no-pin`, `--cpu-base N`) |
| `-c N` | channels per thread: sockets (source ports) on the socket paths, UDP source ports on the raw paths (default 1) |
| `-t SEC` | a query without an answer after this is counted lost (default 5; fractions allowed) |
| `-B N` | datagrams per system call or ring pass (default 64) |

How the engine matches answers: every thread owns its channels and, per channel, 65 536 outstanding-query slots; the 16-bit ID of a query is its slot, handed out in order, so the oldest outstanding query is always at one end and a timeout is found without a scan. An answer counts when it is an answer (QR set), comes on the channel (the connected socket, or the source address, port and destination port on a raw path) and its ID is outstanding; a second answer to the same ID, or an answer after the timeout, is counted as *unmatched*; a datagram that is too short or has QR clear is counted *malformed*, and so is an answer whose records are cut. The answer is read with every offset checked (RFC 1035 4.1; the extended RCODE comes from the OPT record, RFC 6891 6.1.3).

The run time in the report is the time from the first send to the last send or last answer, so the seconds spent waiting for the timeout of lost queries do not lower the rate.

## I/O paths

One small interface (send a batch of datagrams on a channel, receive a batch) sits between the engine and the network; `--io` chooses the path:

| `--io` | OS | How |
|---|---|---|
| `sendto` | all | one connected UDP socket per channel, `send` and `recv`, poll when idle |
| `mmsg` | Linux, FreeBSD | the same sockets with `sendmmsg` / `recvmmsg` in batches |
| `xdp` | Linux | AF_XDP (libxdp), one XDP socket per thread on a NIC queue |
| `netmap` | FreeBSD | netmap, one descriptor per thread on a ring pair of the NIC |
| `auto` (default) | all | `xdp` (Linux) or `netmap` (FreeBSD) when `--iface` is given and the path is available, else `mmsg`, else `sendto`; the choice is printed on the first line |

When a path is not available (not built, not this OS, no privileges, the interface does not open) an explicit `--io` stops with a message (exit 2); `auto` says why and falls back to sockets. The Windows Registered I/O path and a kqueue path for macOS are not there yet; Windows and macOS use `sendto`.

### The kernel-bypass paths

They build the Ethernet, IPv4 or IPv6 and UDP headers themselves, with the checksums (RFC 1071, RFC 768, RFC 8200 8.1), and read the answers from the receive ring, so they need:

* **root** (or `CAP_NET_RAW` and `CAP_BPF`);
* `-b ADDR`, the source address (of the server's family), and the interface: `--iface NAME`, or, on Linux and FreeBSD, the interface that holds `-b`;
* the next hop's MAC: `--next-hop-mac M`, or, by default, resolved by an ARP request (RFC 826) or a neighbor solicitation (RFC 4861) that dnsqps sends and reads through the path itself; `--next-hop IP` names the gateway to ask for when the server is not on the interface's network;
* a source MAC read from the interface, or `--src-mac M`;
* `--queue N`: the first NIC queue; thread *k* uses queue *N + k*; `--sport-base N` (default 40000): the first UDP source port, thread *k*'s channel *c* uses `N + k * channels + c`.

The traffic of a NIC queue that a kernel-bypass thread has opened does not reach the host's own stack: use a NIC (or a port or VF) the machine does not need for anything else, never the one you are logged in on. The answers have to arrive on the queue of the thread that sent the query: on a NIC with several queues steer them (`ethtool -N IFACE flow-type udp4 dst-port P action Q`, or set the number of queues to the number of threads and let RSS spread, and check `foreign`/`unmatched` in the report; one thread on one queue needs nothing).

**AF_XDP** (Linux, libxdp): the default XDP program of libxdp redirects every frame of the queue to the socket. `--xdp-mode skb` forces generic (skb) mode for a NIC or virtual device without native XDP (veth: the test of this repository), `drv` the driver mode, `auto` lets the kernel choose; copy or zero-copy is the kernel's choice. A status line shows what the kernel gave: `[Status] xdp drv, zero-copy` (the attach mode of the interface's XDP program: `drv`, `skb` or `hw`, and whether the first thread's socket is `zero-copy` or `copy`). With `--xdp-mode drv` and a program in another mode, the line is a warning: generic mode and copy mode send far fewer frames than the driver can. Frames are 2 KiB in a UMEM of 4 096 frames per thread; `XDP_USE_NEED_WAKEUP` is on.

**netmap** (FreeBSD): `--iface em1` opens the ring pair `netmap:em1-N` per thread; a name with a colon (`vale0:c`) is used as it is, which is how the test of this repository runs on a VALE switch without taking a NIC over. Load the module first if needed (`kldload netmap`; it is in GENERIC). A status line shows the rings thread 0 got: `[Status] netmap netmap:em1-0: tx ring 0-0 of 4 (1024 slots), rx rings 4`. A NIC with one queue (em(4) on many boards) has one ring pair, so one thread (`-T 1`; ring 1 does not open). The ring depth is the driver's: on iflib drivers the loader tunables `dev.em.0.iflib.override_ntxds` / `override_nrxds`, not an option of dnsqps.

`dnsqps --reflect [ADDR:]PORT` answers every datagram with QR set (on sockets); with `--io=netmap --iface NAME --src-mac M` it is a raw reflector on a netmap port that also answers ARP; these are what the tests use as a peer.

### Pre-built frames

On the raw paths every query of the table is built once, at start-up, as the whole Ethernet / IP / UDP / DNS frame (a query file: one frame per line; generated mode: one per name and type of the mix, the misses included). A send copies the frame into the transmit ring (netmap) or the UMEM frame (AF_XDP) and patches only what differs between queries: the DNS ID, the UDP source port (the channel), with `-b ADDR/LEN` the source address, and with `+cookie=random` the 8 cookie bytes. The IPv4 header checksum and the UDP checksum are updated from the patched words, not computed again (RFC 1624 3, eqn. 3: HC' = ~(~HC + ~m + m')); IPv6 has no header checksum, its UDP checksum is mandatory (RFC 8200 8.1), and a computed UDP checksum of zero goes out as 0xFFFF (RFC 768). Nothing is allocated per query; the unit tests compare every patched frame with a full recomputation, the zero case included.

*Memory.* The table is shared by the threads and read only. A frame costs 12 octets of bookkeeping (the offset and a 4-octet header) plus the headers (42 octets over IPv4, 62 over IPv6) plus the DNS message (12 + the name + 4 + the OPT record and padding the options ask for): about 90 octets for an `A` query without EDNS and a 20-octet name, so a million names cost about 90 MB, a generated table with three types about 270 MB. `--frame-mem MB` (default 1024) is the limit: a table that needs more is not pre-built, and every query is composed and framed when it is sent (the status line says so: "frames built per query"); the patching is the same. A very large name list with several types is therefore slower on the raw path, not refused.

### Many source addresses

`-b 198.18.0.0/16` (or `-b 2001:db8::/48`) makes the source address of every query a uniformly random address of the range (the network bits kept, the host bits drawn by the same fast generator as the cookies, one or two 64-bit draws per query). A given address, `-b 198.18.0.7/32`, is one address; the host bits of the address you write are cleared. Any prefix length is accepted, `/0` to `/32` (`/128`), but a range that is not wholly inside **198.18.0.0/15** (RFC 2544, the benchmark range), **240.0.0.0/4** or **2001:db8::/32** (RFC 3849) is refused unless `--allow-any-source` is given: the server answers each of those addresses, and answers to real addresses would leave through the router as backscatter and reach hosts that never asked. A prefix needs `--io=netmap|xdp` and `--iface`; sockets cannot send from addresses the host does not have.

The answers to those addresses have to come back to this host. The client's NIC is taken over by the raw path, so the server needs a route that sends the range to the client's own address on the shared link, never through the default gateway (a static route on the server; the address of the client must resolve by ARP, which dnsqps's first request teaches the server, or by a static ARP entry):

```
# on the server, FreeBSD (pc31 -> pc41 in the benchmarks)
route add -net 198.18.0.0/15 192.168.20.41
route delete -net 198.18.0.0/15            # afterwards
```

The receive side takes a UDP datagram addressed to any address of the prefix, on one of the thread's source ports, from the server's address and port; those answers are counted like any other (the ID decides, the destination address does not). The sender address of the ARP or neighbor request that resolves the next hop is the interface's own address (`getifaddrs`), or the first address of the prefix when the interface has none (a VALE port).

## Several client hosts

One client host may not be enough (`foreign` and `unmatched` stay at zero and the server is still not saturated). One dnsqps can drive others over TCP:

```
host2$ dnsqps --agent 192.0.2.42:5301 --agent-key /etc/dnsqps.key
host1$ dnsqps --agents 192.0.2.42:5301,192.0.2.43:5301 --agent-key /etc/dnsqps.key \
         -s 192.0.2.53 -d queries.txt -Q 600k -l 20 -b 198.18.0.0/16 --io=netmap --iface em1
```

* An **agent** (`--agent ADDR:PORT`) listens on that one address of its host (a wildcard address is refused: it must not listen on every interface); off loopback it needs `--agent-key FILE`, or `--agent-no-key` on a private network where every host may control it, serves one controller at a time and, after each run, waits for the next. It takes the controller's options, except `--agent`, `--agents`, `--agent-key`, `--agent-no-key`, `--no-local`, `--reflect`, `-h` and `-V`; no option of dnsqps writes a file or runs a command, but a controller can make an agent send a load wherever it likes and read the query files the agent can read, so only a controller you trust should be able to connect (see the key below). Files named by `-d` and `-z` are read **on the agent**: put them on every host.
* The **controller** is an ordinary dnsqps run with `--agents HOST:PORT,...` (at most 16). It connects to every agent, sends it the command line (without the controller-only options and without the rc file, which is not sent), and does its own set-up at the same time; it then waits until every agent says READY (the query table loaded, the frames built, the NIC open), sends GO to all, and the senders start within the round trip of the network, which on a LAN is well under a millisecond. The controller is a sender too, unless `--no-local` is given.
* The load is **shared**: `-Q`, `-N` and `-q` are divided evenly among the senders (the remainder to the first), a `-b` prefix is cut into disjoint equal sub-prefixes (a `/16` among three senders becomes three `/18`, one left unused), and every sender gets its own seed. `-l`, the query options and the query-file paths are the same on all of them, so the hosts need the same paths. **The sending path is each host's own**: an agent ignores the controller's `--io`, `--iface`, `--src-mac`, `--next-hop-mac`, `--next-hop`, `--xdp-mode`, `-b ADDR` (an address, not a prefix), `-T`, `-c`, `-B`, `--queue`, `--sport-base`, `--cpu-base`, `--no-pin` and `--frame-mem` and uses those of its own command line (and its rc file), so a netmap controller can drive an agent on the socket paths and the hosts may name their NICs differently. netmap takes its interface from the host stack while it runs (netmap(4)), so a sender with netmap on the interface that carries the control connection is refused on both sides (exit 2): give the control connection another interface, or loopback when both ends are on one host.
* While it runs each agent sends its totals once a second; the controller adds them to its own for the `-S` lines. At the end each agent sends its result, the counters and the **latency histogram** (the same 976 log buckets everywhere), which the controller adds to its own: the sums and the percentiles of the merged report are exact for the histogram's resolution. The text (or `--json`) report is the usual one for the whole run, with the sender count in the server field and one `[Agent HOST:PORT]` line each (and `[Local]`) before it; the run time is the longest of the senders.
* **Failures stop the run.** An agent that cannot connect, does not answer HELLO, refuses the run (a bad option, a missing query file, a NIC that does not open), is not READY within `--agent-timeout` seconds (default 60), sends a malformed or inconsistent message, or whose connection drops during the run makes the controller send ABORT to the others, stop its own load, print the reason and exit with status 2 (before GO) or 3 (after it); no merged report is printed, because a partial one would pass for the whole. An agent whose controller goes away stops its load too.
* **Trust.** Every message is untrusted on both sides: a length prefix of at most 256 KiB, at most 600 `key=value` lines, keys of `[a-z0-9_.-]`, numbers of decimal digits only and below 2^58 (so the sums cannot overflow), the histogram buckets in rising order, and a result whose counts do not add up (completed above sent, response codes that do not sum to completed, ...) is refused. With `--agent-key FILE` (16 to 255 characters, the same file on both sides) the agent sends a random nonce and the controller proves it knows the key with HMAC-SHA256 over it (RFC 2104, OpenSSL's `HMAC`); an agent with a key refuses a controller without the proof. Nothing is encrypted and the proof does not cover the later messages: this keeps a stranger from starting a run, not an attacker on the path. **Keep the control port on a private network** and bind the agent to the LAN address.

The time the senders wait for each other is the set-up of the slowest one, so give `--agent-timeout` room when the query table is big. The merge is exact only when every sender ran with the same options; the controller does not check that the agents' I/O paths are the same (it prints `mixed` when they are not).

## Measuring the ceiling

`--null-target` sends to a reflector inside the process, on loopback (`--null-target=reflect`, the default: one reflector thread per worker thread, using the same batch system calls), or to a socket that is never read (`--null-target=sink`: nothing is answered, nothing is tracked, and the report shows the send rate only). The reflector costs about what the client does, so the figure of the reflect mode is a bound on the machine and the path (client plus reflector), the sink figure the cost of sending alone. For a client-only figure with the reflector on another machine, start `dnsqps --reflect ADDR:PORT` there (or any discard service) and run dnsqps against it. A run against the real server is meaningful when its figure is clearly below the ceiling; say "client ceiling X, server reached Y" with both numbers from the same host, path and thread count.

## Output

The text report is modelled on `dnsperf`'s:

```
[Status] dnsqps 0.7.0: 192.0.2.53 port 53, I/O path mmsg (auto), 4 thread(s) x 1 socket(s), closed loop

Statistics:

  Queries sent:         3181200
  Queries completed:    3181200 (100.00%)
  Queries lost:         0 (0.00%)

  Response codes:       NOERROR 2863080 (90.00%), NXDOMAIN 318120 (10.00%)
  Average packet size:  request 41, response 97
  Run time (s):         10.002
  Queries per second:   318056.5 (sent 318056.5)

  Average Latency (s):  0.000812 (min 0.000041, max 0.012339)
  Latency percentiles (s): p50 0.000720, p90 0.001240, p99 0.003100, p99.9 0.007900

  I/O path: mmsg, 4 thread(s) x 1 socket(s), server 192.0.2.53:53
```

The percentiles come from a log histogram (16 steps per power of two, about 6 % wide): they are the upper edge of the bucket, never above the maximum. `-S SEC` prints a line `[Interval] t=... sent=... completed=... lost=... qps=... avg_latency=...` every SEC seconds. `--json` prints one JSON object instead of the text report (the status and interval lines then go to standard error):

```
{"tool":"dnsqps","io":"mmsg","server":"192.0.2.53:53","threads":4,"sockets":1,"null_sink":false,"run_s":10.002,"sent":3181200,"completed":3181200,"lost":0,"qps":318056.5,"sent_qps":318056.5,"malformed":0,"unmatched":0,"foreign":0,"send_errors":0,"recv_errors":0,"sent_bytes":130429200,"recv_bytes":308576400,"latency_s":{"avg":0.000812,"min":0.000041,"p50":0.00072,"p90":0.00124,"p99":0.0031,"p999":0.0079,"max":0.012339},"rcodes":{"NOERROR":2863080,"NXDOMAIN":318120}}
```

Exit status: 0 when the run was done and at least one answer came, 1 when queries were sent and none was answered, 2 for a usage or setup error (a controller: also an agent that failed before GO), 3 an agent lost during the run. Interrupt (Ctrl-C) stops the sending and waits for the outstanding queries (at most the timeout).

## The rc file

`~/.dnsqpsrc` (`%USERPROFILE%` on Windows) holds default options, the same words as the command line, one or more per line; `#` starts a comment, a word may be quoted with `'` or `"`. It is read first, the command line after it. `-r` (`--ignore-rc`) does not read it. A bad file is an error that names the file and says so.

## Tests

`tests/test_dnsqps.c` (unit: encoder, options, table, generator, parser, histogram, reports, frames, socket paths), `tests/run_dnsqps_test.sh` (every platform: the engine against the reflector, every example of `--help`), `tests/run_dnsqps_karidns_test.sh` (against karidns), `tests/run_dnsqps_xdp_test.sh` (AF_XDP on a veth pair in generic mode), `tests/run_dnsqps_netmap_test.sh` (netmap on a VALE switch, with pre-built frames, a source prefix and a cookie per query), `tests/run_dnsqps_cookie_test.sh` (the cookies a server sees: random, fixed, per-line), `tests/run_dnsqps_agent_test.sh` (a controller and two agents on loopback, against karidns where there is one: the merge, an agent killed in the run, an agent that is not ready, a wrong key, bad messages); the libFuzzer harnesses `fuzz_dnsqps_resp` (answers and frames from the network) and `fuzz_dnsqps_args` (options, rc file, query-file lines). The veth and VALE tests check correctness; they say nothing about the rate of a NIC.
