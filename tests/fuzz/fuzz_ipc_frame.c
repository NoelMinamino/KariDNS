/*
 * fuzz_ipc_frame.c - the framing of the worker -> router replies (dns_ipc_frame.h, B3 phase 3).
 *
 * The router reads what a worker of the Backend sends as hostile input.  Properties:
 *   1. udp_ipc_frame_next() over any bytes (in an aligned buffer, as the router's) never reads past them: every frame it returns has its header and
 *      its payload_len octets inside the datagram, a reply frame holds at least one octet, the offsets only grow and stay aligned, and a result
 *      other than a frame leaves the offset at the end (the loop ends);
 *   2. udp_ipc_pack() of frames whose lengths and limit come from the input groups them in order, every frame once, no group over the limit but a
 *      frame alone; each group gathered into one datagram parses back into exactly its frames, header and payload unchanged, with zero padding.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "../../dns_ipc_frame.h"

#define FZ_DGRAM_MAX 65616               /* the router's receive buffer (UDP_IPC_BUFFER_SIZE) */
#define FZ_FRAMES 16                     /* UDP_BATCH_SIZE */
#define FZ_PAYLOAD_MAX 4200

static void check_parse(const uint8_t *d, size_t len) {
  size_t off = 0, prev = 0;
  int frames = 0;
  for (;;) {
    const udp_ipc_t *h;
    const size_t start = off;
    const udp_ipc_frame_rc_t rc = udp_ipc_frame_next(d, len, &off, &h);
    if (rc != UDP_IPC_FRAME_OK) {
      if (off != len || h != NULL) abort();
      if (rc == UDP_IPC_FRAME_END && (start == 0 || start < len)) abort();   /* (END only past the last frame of a datagram that had one) */
      break;
    }
    if ((const uint8_t *)h != d + start || start % UDP_IPC_FRAME_ALIGN != 0) abort();
    const size_t pl = h->payload_len;
    if (start + sizeof(udp_ipc_t) + pl > len) abort();
    if (pl < UDP_IPC_REPLY_MIN && h->sock_fd_idx != UDP_IPC_LOGSTATE) abort();
    if (udp_ipc_addr_len(h) > sizeof(h->client_addr) || udp_ipc_addr_len(h) > h->addr_len) abort();   /* the address the router hands to the kernel stays in the header */
    if (off <= start || (off != len && off % UDP_IPC_FRAME_ALIGN != 0) || off < prev) abort();
    volatile uint8_t sink = 0;
    const uint8_t *p = (const uint8_t *)h + sizeof(udp_ipc_t);
    for (size_t i = 0; i < pl; i++) sink ^= p[i];            /* (ASan: every octet of the payload is inside the datagram) */
    (void)sink;
    prev = off;
    if (++frames > (int)(len / sizeof(udp_ipc_t)) + 1) abort();
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static alignas(8) uint8_t dg[FZ_DGRAM_MAX];
  /* 1 */
  const size_t len = size < sizeof(dg) ? size : sizeof(dg);
  memcpy(dg, data, len);
  check_parse(dg, len);

  /* 2: the first octets are the limit and the frames' lengths */
  if (size < 4) return 0;
  static alignas(8) uint8_t fb[FZ_FRAMES][sizeof(udp_ipc_t) + FZ_PAYLOAD_MAX + 8];
  struct iovec fr[FZ_FRAMES];
  size_t flen[FZ_FRAMES];
  size_t limit = ((size_t)data[0] << 8 | data[1]) + (data[2] & 1 ? 0 : 1024);
  if (limit > 65536) limit = 65536;                         /* (the server's largest: setup_ipc_tables(); the router's buffer holds it) */
  int n = 1 + data[3] % FZ_FRAMES;
  size_t pos = 4;
  for (int i = 0; i < n; i++) {
    size_t pl = UDP_IPC_REPLY_MIN;
    if (pos + 2 <= size) {
      pl += ((size_t)data[pos] << 8 | data[pos + 1]) % (FZ_PAYLOAD_MAX - UDP_IPC_REPLY_MIN + 1);
      pos += 2;
    }
    memset(fb[i], 0xEE, sizeof(fb[i]));                      /* (stale octets: the padding must not carry them) */
    udp_ipc_t h;
    memset(&h, 0, sizeof(h));
    h.sock_fd_idx = i;
    h.payload_len = (uint16_t)pl;
    memcpy(fb[i], &h, sizeof(h));
    for (size_t k = 0; k < pl; k++) fb[i][sizeof(udp_ipc_t) + k] = (uint8_t)(i * 31 + k);
    fr[i].iov_base = fb[i];
    fr[i].iov_len = flen[i] = sizeof(udp_ipc_t) + pl;
  }
  udp_ipc_group_t g[FZ_FRAMES];
  const int ng = udp_ipc_pack(fr, n, limit, g);
  if (ng < 1 || ng > n) abort();
  int next = 0;
  for (int k = 0; k < ng; k++) {
    if (g[k].first != next || g[k].count < 1) abort();
    size_t total = 0;
    for (int i = g[k].first; i < g[k].first + g[k].count; i++) {
      const int last = i == g[k].first + g[k].count - 1;
      if (fr[i].iov_len != (last ? flen[i] : udp_ipc_frame_padded(flen[i]))) abort();
      for (size_t q = flen[i]; q < fr[i].iov_len; q++)
        if (fb[i][q] != 0) abort();
      if (total + fr[i].iov_len > sizeof(dg)) abort();
      memcpy(dg + total, fr[i].iov_base, fr[i].iov_len);
      total += fr[i].iov_len;
    }
    if (g[k].count > 1 && total > limit) abort();
    /* a frame that would have fitted the previous group was not left out of it */
    if (k > 0) {
      const int pl_last = g[k - 1].first + g[k - 1].count - 1;
      size_t prev_total = 0;
      for (int i = g[k - 1].first; i <= pl_last; i++) prev_total += fr[i].iov_len;
      if (prev_total + (udp_ipc_frame_padded(flen[pl_last]) - flen[pl_last]) + flen[g[k].first] <= limit) abort();
    }
    size_t off = 0;
    for (int i = g[k].first; i < g[k].first + g[k].count; i++) {
      const udp_ipc_t *h;
      const size_t start = off;
      if (udp_ipc_frame_next(dg, total, &off, &h) != UDP_IPC_FRAME_OK) abort();
      if (memcmp(dg + start, fb[i], flen[i]) != 0) abort();
    }
    const udp_ipc_t *h;
    if (udp_ipc_frame_next(dg, total, &off, &h) != UDP_IPC_FRAME_END) abort();
    next += g[k].count;
  }
  if (next != n) abort();
  return 0;
}
