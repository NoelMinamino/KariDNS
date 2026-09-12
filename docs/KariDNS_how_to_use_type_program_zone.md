# KariDNS: Complete Guide to 'type program' Zones (Plugin Zone Architecture & Implementation)

The `type program` zone feature in KariDNS delegates authoritative DNS queries for specific zones to an external program or script over standard input and output pipes. This mechanism allows developers and administrators to **generate dynamic, context-aware DNS wire-format responses** with minimal overhead.

Typical use cases include:
- Real-time database-driven name resolution (MySQL, PostgreSQL, Redis).
- GeoDNS and client-IP-based traffic steering.
- Dynamic load balancing and health-check failover.
- Generating crafted malformed packets, protocol edge-case testing, and mock servers.

---

## Table of Contents

1. [Architecture & Execution Mechanism](#1-architecture--execution-mechanism)
2. [KariDNS ⇄ Plugin IPC Protocol Specification](#2-karidns--plugin-ipc-protocol-specification)
3. [Configuration Reference (karidns.conf)](#3-configuration-reference-karidnsconf)
4. [Language-Specific Implementation Examples](#4-language-specific-implementation-examples)
   - [Perl Implementation](#perl-implementation)
   - [Python Implementation](#python-implementation)
   - [C Implementation](#c-implementation)
   - [Rust Implementation](#rust-implementation)
   - [Go Implementation](#go-implementation)
5. [Troubleshooting & Best Practices](#5-troubleshooting--best-practices)

---

## 1. Architecture & Execution Mechanism

Unlike traditional CGI-like designs, KariDNS **does not fork or execute a new process for every query**.

```text
+------------------+         Unix Pipes (STDIN / STDOUT)        +----------------------+
|  KariDNS Server  | =========================================> | External Plugin Proc |
|                  |   "QUERY <proto> <client_ip>\n"            | (Perl, Python, C,    |
|  - Worker Thread |   + [2-byte len] + [Raw DNS Query Packet]  |  Rust, Go, etc.)     |
|  - Timeout Watch | <========================================= |                      |
|  - RRL Limiter   |   [2-byte len] + [Raw DNS Response Packet] | - Long-running       |
+------------------+                                            +----------------------+
```

### Key Architectural Characteristics

1. **Persistent Process Model**
   - KariDNS launches the external plugin during server startup (`spawn_program_zone_plugins`).
   - The plugin runs as a persistent daemon process that blocks on STDIN and loops over incoming queries, eliminating per-query process instantiation overhead.

2. **Thread-Safe Asynchronous I/O Pool**
   - Queries targeting a `type program` zone are dispatched to KariDNS's asynchronous I/O worker pool.
   - Access to the plugin's STDIN and STDOUT is serialized via an internal mutex, ensuring request and response stream order integrity across concurrent worker threads.

3. **Fault Tolerance and Deadline Monitoring**
   - Each query is assigned a deadline based on `program-timeout` (default: 2000 ms). If the plugin does not respond within this deadline, KariDNS terminates the waiting cycle and synthesizes a `SERVFAIL` response to the client.
   - If communication fails repeatedly (e.g., plugin crashes or times out), an atomic failure counter is incremented. When `program-max-failures` is reached, KariDNS forcibly kills the process (`SIGKILL`) and marks the zone dead to protect system resources.

4. **Transparent Binary Wire Passthrough & Truncation**
   - KariDNS passes the raw DNS query packet directly to the plugin and returns the plugin's response bytes directly to the client.
   - If the plugin's response exceeds the maximum allowed transmission size (e.g., 512 bytes for standard UDP or the client's EDNS buffer limit), KariDNS automatically truncates the response and sets the `TC=1` bit to trigger TCP fallback.

---

## 2. KariDNS ⇄ Plugin IPC Protocol Specification

Communication between KariDNS and the plugin process occurs over standard Unix pipes (`STDIN` and `STDOUT`) in binary mode.

### 1. Request Stream (KariDNS → Plugin STDIN)

For each query, KariDNS writes three elements sequentially to the plugin's standard input:

```text
+-------------------------------------------------------------+
| 1. Text Header Line: "QUERY <proto> <client_ip>\n"          |
+-------------------------------------------------------------+
| 2. Query Length: 2 bytes uint16_t (Big-Endian)              |
+-------------------------------------------------------------+
| 3. Raw DNS Query Packet: <Query Length> bytes               |
+-------------------------------------------------------------+
```

1. **Text Header Line**:
   - Format: `QUERY <proto> <client_ip>\n`
   - `<proto>`: Transport protocol string, either `udp` or `tcp`.
   - `<client_ip>`: Client IP address string (e.g., `192.0.2.1` or `2001:db8::1`).
2. **Query Length**:
   - 16-bit unsigned integer in network byte order (Big-Endian).
3. **Raw DNS Query Packet**:
   - The exact binary DNS query payload as received from the client.

---

### 2. Response Stream (Plugin STDOUT → KariDNS)

After generating the response, the plugin writes to standard output:

```text
+---------------------------------------------------------------+
| 1. Response Length: 2 bytes uint16_t (Big-Endian)             |
+---------------------------------------------------------------+
| 2. Raw DNS Response Packet: <Response Length> bytes           |
|    (Omitted if Response Length is 0)                          |
+---------------------------------------------------------------+
```

1. **Response Length**:
   - `> 0`: Length in bytes of the accompanying DNS response packet.
   - `== 0`: **Silent Drop / Query Discard**. KariDNS will silently discard the query and return nothing to the client (useful for blackholing or testing client timeout handling).
2. **Raw DNS Response Packet**:
   - Complete wire-format DNS packet to be delivered to the client.

> [!IMPORTANT]
> The plugin's standard output **must be unbuffered or explicitly flushed** immediately after writing each response. If output is buffered in user space, KariDNS will time out waiting for the response.

---

## 3. Configuration Reference (karidns.conf)

To enable `type program` zones, configure the `options` block and define the zone in `karidns.conf`.

### Safety Requirement
Because executing external binaries involves system-level privileges, `allow-program-zones yes;` must be explicitly declared in the global `options` block. If this option is omitted or set to `no`, KariDNS will refuse to start.

```text
options {
    port 53;
    bind-address { 0.0.0.0; ::; };

    # Mandatory security guard: enable program zones
    allow-program-zones yes;

    user "nobody";
    group "nobody";
};

zone "dynamic.example.com." {
    type program;

    # Absolute path to the plugin executable or script
    program "/usr/local/libexec/karidns/my_dns_plugin.py";

    # OS user under which the plugin process runs (optional; defaults to options.user)
    program-user "nobody";

    # Plugin response timeout in milliseconds (default: 2000)
    program-timeout 1500;

    # Maximum consecutive communication failures before isolation (default: 500)
    program-max-failures 50;
};
```

---

## 4. Language-Specific Implementation Examples

The following complete, runnable examples listen on STDIN, parse the incoming DNS query, echo back the Question section, and attach an authoritative `A` record (`192.0.2.1`) with a 300-second TTL.

---

### Perl Implementation

Perl is lightweight, ubiquitous on UNIX systems, and requires no external CPAN dependencies.

```perl
#!/usr/bin/env perl
use strict;
use warnings;

# Enforce raw binary mode
binmode(STDIN,  ':raw');
binmode(STDOUT, ':raw');

# Enable autoflush on STDOUT (crucial)
$| = 1;

while (my $line = <STDIN>) {
    chomp($line);
    my ($cmd, $proto, $client_ip) = split(/\s+/, $line);
    next unless $cmd && $cmd eq 'QUERY';

    # 1. Read 2-byte query length
    my $len_buf;
    read(STDIN, $len_buf, 2) or last;
    my $req_len = unpack('n', $len_buf);

    # 2. Read raw DNS query packet
    my $req;
    read(STDIN, $req, $req_len) or last;
    next if $req_len < 12;

    # Extract Transaction ID
    my $id = unpack('n', substr($req, 0, 2));

    # Find the end of the Question section
    my $offset = 12;
    while ($offset < $req_len) {
        my $len = ord(substr($req, $offset, 1));
        if ($len == 0) { $offset++; last; }
        if (($len & 0xC0) == 0xC0) { $offset += 2; last; }
        $offset += 1 + $len;
    }
    $offset += 4; # QTYPE (2) + QCLASS (2)
    my $question = substr($req, 12, $offset - 12);

    # 3. Assemble response
    # Header: ID, Flags (QR=1, AA=1, NOERROR -> 0x8400), QD=1, AN=1, NS=0, AR=0
    my $resp_header = pack('n6', $id, 0x8400, 1, 1, 0, 0);

    # Answer RR: Pointer 0xC00C (points to Question name), TYPE=A (1), CLASS=IN (1), TTL=300, RDLEN=4, IP=192.0.2.1
    my $answer = "\xc0\x0c" . pack('nnNnC4', 1, 1, 300, 4, 192, 0, 2, 1);
    my $resp = $resp_header . $question . $answer;

    # 4. Write 2-byte length prefix and response packet
    print STDOUT pack('n', length($resp)) . $resp;
}
```

---

### Python Implementation

Python 3 using `sys.stdin.buffer` and `struct` provides robust binary wire manipulation.

```python
#!/usr/bin/env python3
import sys
import struct

def main():
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    while True:
        # 1. Read text header line
        line = stdin.readline()
        if not line:
            break
        parts = line.decode('ascii', errors='ignore').strip().split()
        if not parts or parts[0] != 'QUERY':
            continue
        proto, client_ip = parts[1], parts[2]

        # 2. Read 2-byte query length prefix
        len_buf = stdin.read(2)
        if len(len_buf) < 2:
            break
        req_len = struct.unpack('!H', len_buf)[0]

        # 3. Read raw query packet
        req = stdin.read(req_len)
        if len(req) < req_len or req_len < 12:
            continue

        id = struct.unpack('!H', req[:2])[0]

        # Find the end of the Question section
        off = 12
        while off < req_len:
            label_len = req[off]
            if label_len == 0:
                off += 1
                break
            if (label_len & 0xC0) == 0xC0:
                off += 2
                break
            off += 1 + label_len
        off += 4  # QTYPE (2) + QCLASS (2)
        question = req[12:min(off, req_len)]

        # 4. Assemble response: QR=1, AA=1, NOERROR (0x8400), QD=1, AN=1
        header = struct.pack('!HHHHHH', id, 0x8400, 1, 1, 0, 0)
        # Answer RR: Pointer 0xC00C, TYPE=A, CLASS=IN, TTL=300, 192.0.2.1
        answer = b'\xc0\x0c' + struct.pack('!HHIH4B', 1, 1, 300, 4, 192, 0, 2, 1)
        resp = header + question + answer

        # 5. Write response and flush immediately
        stdout.write(struct.pack('!H', len(resp)) + resp)
        stdout.flush()

if __name__ == '__main__':
    main()
```

---

### C Implementation

A high-performance implementation with zero dynamic memory allocation on the request path.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static ssize_t read_exact(int fd, void *buf, size_t count) {
    size_t got = 0;
    while (got < count) {
        ssize_t n = read(fd, (char *)buf + got, count - got);
        if (n <= 0) return -1;
        got += n;
    }
    return (ssize_t)got;
}

int main(void) {
    char line[128];
    while (fgets(line, sizeof(line), stdin)) {
        char cmd[16], proto[16], ip[64];
        if (sscanf(line, "%15s %15s %63s", cmd, proto, ip) != 3 || strcmp(cmd, "QUERY") != 0) {
            continue;
        }

        uint8_t len_buf[2];
        if (read_exact(STDIN_FILENO, len_buf, 2) != 2) break;
        uint16_t req_len = (len_buf[0] << 8) | len_buf[1];

        uint8_t req[4096];
        if (req_len > sizeof(req) || read_exact(STDIN_FILENO, req, req_len) != req_len) break;
        if (req_len < 12) continue;

        uint16_t id = (req[0] << 8) | req[1];

        // Locate end of Question section
        size_t off = 12;
        while off < req_len {
            uint8_t l = req[off];
            if (l == 0) { off++; break; }
            if ((l & 0xC0) == 0xC0) { off += 2; break; }
            off += 1 + l;
        }
        off += 4; // QTYPE + QCLASS
        if (off > req_len) off = req_len;
        size_t qlen = off - 12;

        uint8_t resp[4096];
        // DNS Header (QR=1, AA=1, QD=1, AN=1)
        resp[0] = id >> 8; resp[1] = id & 0xFF;
        resp[2] = 0x84;    resp[3] = 0x00;
        resp[4] = 0x00;    resp[5] = 0x01; // QDCOUNT = 1
        resp[6] = 0x00;    resp[7] = 0x01; // ANCOUNT = 1
        resp[8] = 0x00;    resp[9] = 0x00;
        resp[10] = 0x00;   resp[11] = 0x00;
        size_t rlen = 12;

        // Question section
        memcpy(resp + rlen, req + 12, qlen);
        rlen += qlen;

        // Answer RR: Pointer 0xC00C, TYPE=A, CLASS=IN, TTL=300, 192.0.2.1
        resp[rlen++] = 0xC0; resp[rlen++] = 0x0C;
        resp[rlen++] = 0x00; resp[rlen++] = 0x01;
        resp[rlen++] = 0x00; resp[rlen++] = 0x01;
        resp[rlen++] = 0x00; resp[rlen++] = 0x00; resp[rlen++] = 0x01; resp[rlen++] = 0x2C; // 300
        resp[rlen++] = 0x00; resp[rlen++] = 0x04;
        resp[rlen++] = 192;  resp[rlen++] = 0;    resp[rlen++] = 2;    resp[rlen++] = 1;

        uint8_t out_len[2] = { (uint8_t)(rlen >> 8), (uint8_t)(rlen & 0xFF) };
        write(STDOUT_FILENO, out_len, 2);
        write(STDOUT_FILENO, resp, rlen);
    }
    return 0;
}
```

---

### Rust Implementation

Combining memory safety with zero-cost abstractions for production-grade throughput.

```rust
use std::io::{self, BufRead, Read, Write};

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();

    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() || parts[0] != "QUERY" {
            line.clear();
            continue;
        }

        // 1. Read 2-byte query length
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf)?;
        let req_len = u16::from_be_bytes(len_buf) as usize;

        // 2. Read raw query packet
        let mut req = vec![0u8; req_len];
        reader.read_exact(&mut req)?;
        if req_len < 12 {
            line.clear();
            continue;
        }

        let id = [req[0], req[1]];

        // Locate end of Question section
        let mut off = 12;
        while off < req_len {
            let l = req[off];
            if l == 0 { off += 1; break; }
            if (l & 0xC0) == 0xC0 { off += 2; break; }
            off += 1 + (l as usize);
        }
        off += 4; // QTYPE + QCLASS
        let question = &req[12..off.min(req_len)];

        // 3. Assemble response
        let mut resp = Vec::with_capacity(512);
        resp.extend_from_slice(&id);
        resp.extend_from_slice(&[0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        resp.extend_from_slice(question);
        // Answer RR: Pointer 0xC00C, TYPE=A, CLASS=IN, TTL=300, 192.0.2.1
        resp.extend_from_slice(&[
            0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x01, 0x2C,
            0x00, 0x04,
            192, 0, 2, 1,
        ]);

        // 4. Write length prefix and packet, then flush
        let out_len = (resp.len() as u16).to_be_bytes();
        writer.write_all(&out_len)?;
        writer.write_all(&resp)?;
        writer.flush()?;

        line.clear();
    }
    Ok(())
}
```

---

### Go Implementation

Using `bufio` and `encoding/binary` for clean, idiomatic, and concurrent server programming.

```go
package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) < 3 || parts[0] != "QUERY" {
			continue
		}

		var reqLen uint16
		if err := binary.Read(reader, binary.BigEndian, &reqLen); err != nil {
			break
		}

		req := make([]byte, reqLen)
		if _, err := io.ReadFull(reader, req); err != nil {
			break
		}
		if reqLen < 12 {
			continue
		}

		id := binary.BigEndian.Uint16(req[:2])

		// Locate end of Question section
		off := 12
		for off < int(reqLen) {
			l := req[off]
			if l == 0 {
				off++
				break
			}
			if (l & 0xC0) == 0xC0 {
				off += 2
				break
			}
			off += 1 + int(l)
		}
		off += 4 // QTYPE + QCLASS
		if off > int(reqLen) {
			off = int(reqLen)
		}
		question := req[12:off]

		// Assemble response
		resp := make([]byte, 0, 512)
		hdr := make([]byte, 12)
		binary.BigEndian.PutUint16(hdr[0:2], id)
		binary.BigEndian.PutUint16(hdr[2:4], 0x8400) // QR=1, AA=1, NOERROR
		binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
		binary.BigEndian.PutUint16(hdr[6:8], 1)      // ANCOUNT=1
		resp = append(resp, hdr...)
		resp = append(resp, question...)

		// Answer RR: Pointer 0xC00C, TYPE=A, CLASS=IN, TTL=300, 192.0.2.1
		ans := []byte{
			0xC0, 0x0C,
			0x00, 0x01, 0x00, 0x01,
			0x00, 0x00, 0x01, 0x2C, // TTL=300
			0x00, 0x04,
			192, 0, 2, 1,
		}
		resp = append(resp, ans...)

		// Write length prefix and packet, then flush
		binary.Write(writer, binary.BigEndian, uint16(len(resp)))
		writer.Write(resp)
		writer.Flush()
	}
}
```

---

## 5. Troubleshooting & Best Practices

### 1. KariDNS Returns `SERVFAIL` / Query Timeouts
- **Missing Output Flush**: By default, standard libraries buffer stdout when connected to a pipe. Ensure that `flush()` or equivalent unbuffered mode is enabled.
- **External Network or Database Latency**: If your plugin performs external network requests or database queries synchronously, slow queries can exceed `program-timeout` (default: 2000 ms). Utilize in-memory caching (e.g., Redis or local shared memory) to keep response times under 10 ms.

### 2. Standalone CLI Testing (Piping Without KariDNS)
You can test your plugin independently from the command line without launching KariDNS.

On FreeBSD `/bin/sh` or `/bin/csh` / `/bin/tcsh`, use `printf` with hexadecimal escapes (`\xHH`) to construct the IPC header and wire-format query (avoids bash-specific `<(...)` process substitution):

```sh
# FreeBSD sh / tcsh compatible:
# Transmits "QUERY udp 127.0.0.1\n" + 2-byte length (29 bytes) + query for "example.com A"
printf 'QUERY udp 127.0.0.1\n\x00\x1d\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' | ./my_plugin.py | hd
```

Alternatively, you can use a portable Perl one-liner to generate the test query stream:

```sh
perl -e '
  my $hdr = "QUERY udp 127.0.0.1\n";
  my $qname = "\x07example\x03com\x00";
  my $pkt = pack("n6", 0x1234, 0x0100, 1, 0, 0, 0) . $qname . pack("n2", 1, 1);
  print $hdr . pack("n", length($pkt)) . $pkt;
' | ./my_plugin.py | hd
```

### 3. Intentional Silent Drop (Blackholing)
To drop queries silently without sending any reply to the client (for rate limiting, DDoS mitigation, or simulating network loss), write a 2-byte length of `0` (`\x00\x00`):

```python
# Python example of dropping a query silently
stdout.write(b'\x00\x00')
stdout.flush()
```
KariDNS will release the connection and suppress response transmission entirely.

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)

