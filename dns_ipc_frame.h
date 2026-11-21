/*
 * dns_ipc_frame.h - the UDP message header between the Frontend routers and the Backend workers (udp_ipc_t), and the framing of the
 * worker -> router replies (B3 phase 3, 0.7).
 *
 * A datagram from a worker to a router holds one or more frames.  A frame is a udp_ipc_t header followed by payload_len octets of payload
 * (a DNS reply, or a KLS1 record when sock_fd_idx is UDP_IPC_LOGSTATE): its length is sizeof(udp_ipc_t) + payload_len.  The next frame starts
 * at the next multiple of UDP_IPC_FRAME_ALIGN octets (the padding octets are zero), so every header is read at an aligned address from an
 * aligned receive buffer; the last frame ends the datagram, with no padding.  A datagram of one frame is exactly the message of one reply as
 * it was before the framing, so the senders of a single message (the asynchronous resolution threads, the logging state) did not change.
 *
 * Why: FreeBSD's libc implements sendmmsg() and recvmmsg() as loops of sendmsg() / recvmsg(), so one reply cost one IPC sendmsg() in the worker
 * and one recvmsg() in the router (about 19 % of a worker's time at 600k qps, planning B3 "R/W split and worker profile").  The replies of one
 * receive batch now go in as few datagrams as fit under the unix-dgram limit (net.local.dgram.maxdgram: a larger datagram is refused with
 * EMSGSIZE whatever the socket buffers are, measured on FreeBSD 15.1).
 *
 * The router treats every frame as hostile input (the Backend parses the network and may be compromised): udp_ipc_frame_next() checks the
 * lengths of each frame; the first bad frame ends the datagram (what follows it cannot be found) and is counted by the caller.
 * Header only (static inline): the server, the unit tests and the fuzz harness (tests/fuzz/fuzz_ipc_frame.c) use the same code.
 */
#ifndef DNS_IPC_FRAME_H
#define DNS_IPC_FRAME_H

#include <netinet/in.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

// Frontend/Backendプロセス間のUDPパケット受け渡し用コンパクトソケットアドレス (IPv4: 16B, IPv6: 28B, 8B aligned)
typedef union {
  alignas(8) struct sockaddr sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  struct {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    uint8_t ss_len;
    sa_family_t ss_family;
#else
    sa_family_t ss_family;
#endif
  };
} ipc_sockaddr_t;

// Frontend/Backendプロセス間のUDPパケット受け渡し用ヘッダ (80 bytes, 8B aligned)
typedef struct {
  int32_t sock_fd_idx;
  uint16_t addr_len;
  uint16_t payload_len;
  bool has_source_addr;
  uint8_t reserved[7];
  alignas(8) ipc_sockaddr_t client_addr;
  alignas(8) ipc_sockaddr_t source_addr;
} udp_ipc_t;

/* the layout is the format between the Frontend and the Backend (one binary, two processes): a change has to be deliberate */
_Static_assert(sizeof(ipc_sockaddr_t) == 32, "ipc_sockaddr_t: 28 octets of sockaddr_in6, 8-aligned");
_Static_assert(sizeof(udp_ipc_t) == 80, "udp_ipc_t: 16 octets of header and two ipc_sockaddr_t");

/* sock_fd_idx values that are no socket: -2 on the notify pair is the Backend's stop command; UDP_IPC_LOGSTATE on a worker's pair (the Backend
 * to a router) carries a KLS1 record as the payload: the debug level and the logging runtime (dns_log_state.h, 0.7 M2) */
#define UDP_IPC_LOGSTATE (-3)

#define UDP_IPC_FRAME_ALIGN 8
_Static_assert(alignof(udp_ipc_t) == UDP_IPC_FRAME_ALIGN && sizeof(udp_ipc_t) % UDP_IPC_FRAME_ALIGN == 0, "frames start at aligned offsets");
/* the shortest payload of a reply frame: a DNS header (RFC 1035 4.1.1, DNS_HEADER_SIZE).  A KLS1 frame is checked by klog_state_apply(). */
#define UDP_IPC_REPLY_MIN 12
/* The limit of one packed datagram while the kernel's is not known (a unit test, or a sysctl that cannot be read): small on purpose; FreeBSD 15.1 has
 * net.local.dgram.maxdgram = 8192 (setup_ipc_tables() reads it) */
#define UDP_IPC_PACK_DEFAULT 2048

/* the offset of the frame after one of len octets (len counts the header) */
static inline size_t udp_ipc_frame_padded(size_t len) {
  return (len + (UDP_IPC_FRAME_ALIGN - 1)) & ~(size_t)(UDP_IPC_FRAME_ALIGN - 1);
}

typedef enum {
  UDP_IPC_FRAME_BADLEN = -2,   /* payload_len past the end of the datagram, or a reply shorter than a DNS header */
  UDP_IPC_FRAME_SHORT = -1,    /* fewer octets left than a header (or a buffer that is not aligned) */
  UDP_IPC_FRAME_END = 0,       /* no frame left */
  UDP_IPC_FRAME_OK = 1,        /* *hdr is a frame whose payload_len octets follow it in the datagram */
} udp_ipc_frame_rc_t;

/* The frame at *off of the datagram d[0 .. len) (hostile input).  d must be aligned for udp_ipc_t (the router's receive buffers are).
 * UDP_IPC_FRAME_OK: *hdr is the header, its payload is at (const uint8_t *)*hdr + sizeof(udp_ipc_t), payload_len octets, all inside d; *off is
 * moved to the next frame.  Any other result leaves *off at len: a bad frame ends the datagram, as nothing after it can be found. */
static inline udp_ipc_frame_rc_t udp_ipc_frame_next(const uint8_t *d, size_t len, size_t *off, const udp_ipc_t **hdr) {
  const size_t o = *off;
  *hdr = NULL;
  if (o >= len) {
    *off = len;
    return o == 0 ? UDP_IPC_FRAME_SHORT : UDP_IPC_FRAME_END;   /* (an empty datagram is a short one, as before the framing) */
  }
  *off = len;
  if (len - o < sizeof(udp_ipc_t) || ((uintptr_t)(d + o) & (UDP_IPC_FRAME_ALIGN - 1)) != 0) return UDP_IPC_FRAME_SHORT;
  const udp_ipc_t *h = (const udp_ipc_t *)(const void *)(d + o);
  const size_t pl = h->payload_len;
  if (pl > len - o - sizeof(udp_ipc_t)) return UDP_IPC_FRAME_BADLEN;
  if (pl < UDP_IPC_REPLY_MIN && h->sock_fd_idx != UDP_IPC_LOGSTATE) return UDP_IPC_FRAME_BADLEN;
  const size_t next = udp_ipc_frame_padded(o + sizeof(udp_ipc_t) + pl);   /* (o is a multiple of the alignment: o + 80 + 65535 + 7 cannot wrap) */
  *off = next < len ? next : len;
  *hdr = h;
  return UDP_IPC_FRAME_OK;
}

/* One packed datagram: the frames fr[first .. first + count). */
typedef struct {
  uint16_t first;
  uint16_t count;
} udp_ipc_group_t;

/* The worker's side: the frames fr[0 .. n) (iov_len = sizeof(udp_ipc_t) + payload_len, each base aligned and with room for
 * udp_ipc_frame_padded(iov_len) octets) are grouped in order into datagrams of at most `limit` octets; a frame that does not fit a
 * datagram alone gets one of its own (it is sent as before the framing, and the kernel says whether it fits).  Every frame but the last of
 * its group is padded: its iov_len is raised to the next frame's offset and the padding octets are written with zeros, so no stale octet of
 * an earlier reply goes into the IPC.  g has room for n groups.  Returns the number of groups. */
static inline int udp_ipc_pack(struct iovec *fr, int n, size_t limit, udp_ipc_group_t *g) {
  int ng = 0;
  size_t bytes = 0;                                     /* (the octets of the current group, its last frame unpadded) */
  for (int i = 0; i < n; i++) {
    const size_t len = fr[i].iov_len;
    if (ng > 0) {
      const size_t pad = udp_ipc_frame_padded(fr[i - 1].iov_len) - fr[i - 1].iov_len;
      if (bytes + pad + len <= limit && bytes + pad + len >= bytes) {
        memset((uint8_t *)fr[i - 1].iov_base + fr[i - 1].iov_len, 0, pad);
        fr[i - 1].iov_len += pad;
        bytes += pad + len;
        g[ng - 1].count++;
        continue;
      }
    }
    g[ng].first = (uint16_t)i;
    g[ng].count = 1;
    ng++;
    bytes = len;
  }
  return ng;
}

#endif
