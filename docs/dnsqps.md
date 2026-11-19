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
| `+cookie` | a client cookie (RFC 7873), the same for the whole run; asks for EDNS |
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

**AF_XDP** (Linux, libxdp): the default XDP program of libxdp redirects every frame of the queue to the socket. `--xdp-mode skb` forces generic (skb) mode for a NIC or virtual device without native XDP (veth: the test of this repository), `drv` the driver mode, `auto` lets the kernel choose; copy or zero-copy is the kernel's choice. Frames are 2 KiB in a UMEM of 4 096 frames per thread; `XDP_USE_NEED_WAKEUP` is on.

**netmap** (FreeBSD): `--iface em1` opens the ring pair `netmap:em1-N` per thread; a name with a colon (`vale0:c`) is used as it is, which is how the test of this repository runs on a VALE switch without taking a NIC over. Load the module first if needed (`kldload netmap`; it is in GENERIC).

`dnsqps --reflect [ADDR:]PORT` answers every datagram with QR set (on sockets); with `--io=netmap --iface NAME --src-mac M` it is a raw reflector on a netmap port that also answers ARP; these are what the tests use as a peer.

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

Exit status: 0 when the run was done and at least one answer came, 1 when queries were sent and none was answered, 2 for a usage or setup error. Interrupt (Ctrl-C) stops the sending and waits for the outstanding queries (at most the timeout).

## The rc file

`~/.dnsqpsrc` (`%USERPROFILE%` on Windows) holds default options, the same words as the command line, one or more per line; `#` starts a comment, a word may be quoted with `'` or `"`. It is read first, the command line after it. `-r` (`--ignore-rc`) does not read it. A bad file is an error that names the file and says so.

## Tests

`tests/test_dnsqps.c` (unit: encoder, options, table, generator, parser, histogram, reports, frames, socket paths), `tests/run_dnsqps_test.sh` (every platform: the engine against the reflector, every example of `--help`), `tests/run_dnsqps_karidns_test.sh` (against karidns), `tests/run_dnsqps_xdp_test.sh` (AF_XDP on a veth pair in generic mode), `tests/run_dnsqps_netmap_test.sh` (netmap on a VALE switch); the libFuzzer harnesses `fuzz_dnsqps_resp` (answers and frames from the network) and `fuzz_dnsqps_args` (options, rc file, query-file lines). The veth and VALE tests check correctness; they say nothing about the rate of a NIC.
