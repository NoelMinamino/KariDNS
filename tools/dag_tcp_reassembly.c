#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "dag_tcp_reassembly.h"

#define TCP_REASM_MAX_OOO_SEGMENTS 8

typedef struct {
    uint32_t seq;
    uint16_t len;
    uint8_t  data[1500];
    bool     in_use;
} ooo_segment_t;

typedef struct {
    uint32_t next_seq;
    bool     base_seq_known;
    bool     has_drained;
    uint8_t  *buf;
    size_t   buf_len;
    size_t   buf_cap;
    ooo_segment_t ooo[TCP_REASM_MAX_OOO_SEGMENTS];
} tcp_reasm_dir_t;

typedef struct {
    bool     in_use;
    uint32_t stream_id;
    uint8_t  addr_key[32]; // [0..15]=addr0, [16..31]=addr1
    uint16_t port_key[2];  // [0]=port0, [1]=port1
    uint64_t last_touched_seq_no;
    tcp_reasm_dir_t dir[2];
} tcp_stream_t;

struct tcp_reasm_table {
    tcp_stream_t *streams;
    uint32_t max_streams;
    size_t   max_buffer_per_direction;
    uint32_t next_stream_id;
    uint64_t global_seq_no;
};

static void evict_stream(tcp_stream_t *st) {
    if (!st || !st->in_use) return;
    for (int d = 0; d < 2; d++) {
        if (st->dir[d].buf) {
            free(st->dir[d].buf);
            st->dir[d].buf = NULL;
        }
    }
    memset(st, 0, sizeof(*st));
}

tcp_reasm_table_t *tcp_reasm_create(uint32_t max_streams, size_t max_buffer_per_direction) {
    if (max_streams == 0) max_streams = 4096;
    if (max_buffer_per_direction == 0) max_buffer_per_direction = 256 * 1024;

    tcp_reasm_table_t *t = calloc(1, sizeof(tcp_reasm_table_t));
    if (!t) return NULL;

    t->streams = calloc(max_streams, sizeof(tcp_stream_t));
    if (!t->streams) {
        free(t);
        return NULL;
    }

    t->max_streams = max_streams;
    t->max_buffer_per_direction = max_buffer_per_direction;
    t->next_stream_id = 1;
    t->global_seq_no = 0;
    return t;
}

void tcp_reasm_destroy(tcp_reasm_table_t *t) {
    if (!t) return;
    if (t->streams) {
        for (uint32_t i = 0; i < t->max_streams; i++) {
            evict_stream(&t->streams[i]);
        }
        free(t->streams);
    }
    free(t);
}

static bool append_to_dir_buf(tcp_reasm_dir_t *d, size_t max_buf, const uint8_t *data, size_t len) {
    if (!data || len == 0) return true;
    if (d->buf_len + len > max_buf) return false;

    if (d->buf_len + len > d->buf_cap) {
        size_t new_cap = d->buf_cap == 0 ? 4096 : d->buf_cap * 2;
        while (new_cap < d->buf_len + len) {
            new_cap *= 2;
        }
        if (new_cap > max_buf) new_cap = max_buf;
        uint8_t *new_buf = realloc(d->buf, new_cap);
        if (!new_buf) return false;
        d->buf = new_buf;
        d->buf_cap = new_cap;
    }

    memcpy(d->buf + d->buf_len, data, len);
    d->buf_len += len;
    return true;
}

static bool prepend_to_dir_buf(tcp_reasm_dir_t *d, size_t max_buf, const uint8_t *data, size_t len) {
    if (!data || len == 0) return true;
    if (d->buf_len + len > max_buf) return false;

    if (d->buf_len + len > d->buf_cap) {
        size_t new_cap = d->buf_cap == 0 ? 4096 : d->buf_cap * 2;
        while (new_cap < d->buf_len + len) {
            new_cap *= 2;
        }
        if (new_cap > max_buf) new_cap = max_buf;
        uint8_t *new_buf = realloc(d->buf, new_cap);
        if (!new_buf) return false;
        d->buf = new_buf;
        d->buf_cap = new_cap;
    }

    if (d->buf_len > 0) {
        memmove(d->buf + len, d->buf, d->buf_len);
    }
    memcpy(d->buf, data, len);
    d->buf_len += len;
    return true;
}

static void process_ooo(tcp_stream_t *st, int dir_idx, size_t max_buf) {
    tcp_reasm_dir_t *d = &st->dir[dir_idx];
    bool progress = true;

    while (progress) {
        progress = false;
        uint32_t base_seq = d->next_seq - (uint32_t)d->buf_len;

        for (int i = 0; i < TCP_REASM_MAX_OOO_SEGMENTS; i++) {
            if (!d->ooo[i].in_use) continue;
            ooo_segment_t *seg = &d->ooo[i];
            uint32_t end_seq = seg->seq + (uint32_t)seg->len;

            if (seg->seq == d->next_seq) {
                if (!append_to_dir_buf(d, max_buf, seg->data, seg->len)) {
                    evict_stream(st);
                    return;
                }
                d->next_seq += seg->len;
                seg->in_use = false;
                progress = true;
                break;
            } else if (seg->seq > d->next_seq) {
                continue;
            } else if (seg->seq >= base_seq) {
                // Starts within currently buffered data
                if (end_seq > d->next_seq) {
                    size_t overlap = (size_t)(d->next_seq - seg->seq);
                    size_t new_bytes = seg->len - overlap;
                    if (!append_to_dir_buf(d, max_buf, seg->data + overlap, new_bytes)) {
                        evict_stream(st);
                        return;
                    }
                    d->next_seq += (uint32_t)new_bytes;
                    seg->in_use = false;
                    progress = true;
                    break;
                } else {
                    // Fully redundant
                    seg->in_use = false;
                }
            } else {
                // seg->seq < base_seq
                if (!d->has_drained) {
                    if (end_seq >= base_seq) {
                        size_t new_prefix = (size_t)(base_seq - seg->seq);
                        if (!prepend_to_dir_buf(d, max_buf, seg->data, new_prefix)) {
                            evict_stream(st);
                            return;
                        }
                        if (end_seq > d->next_seq) {
                            size_t overlap = (size_t)(d->next_seq - seg->seq);
                            size_t new_suffix = seg->len - overlap;
                            d->next_seq += (uint32_t)new_suffix;
                            if (!append_to_dir_buf(d, max_buf, seg->data + overlap, new_suffix)) {
                                evict_stream(st);
                                return;
                            }
                        }
                        seg->in_use = false;
                        progress = true;
                        break;
                    }
                    // end_seq < base_seq: wait for earlier segments before prepending
                } else {
                    // has_drained == true: data before base_seq was already consumed
                    if (end_seq > d->next_seq) {
                        size_t overlap = (size_t)(d->next_seq - seg->seq);
                        size_t new_bytes = seg->len - overlap;
                        d->next_seq += (uint32_t)new_bytes;
                        if (!append_to_dir_buf(d, max_buf, seg->data + overlap, new_bytes)) {
                            evict_stream(st);
                            return;
                        }
                        seg->in_use = false;
                        progress = true;
                        break;
                    } else {
                        // Stale retransmission of already drained data or duplicate within buffer
                        seg->in_use = false;
                    }
                }
            }
        }
    }
}

static void drain_dns_messages(tcp_stream_t *st, int dir_idx, tcp_reasm_message_cb cb, void *user_ctx) {
    tcp_reasm_dir_t *d = &st->dir[dir_idx];
    while (d->buf_len >= 2) {
        uint16_t msg_len = ((uint16_t)d->buf[0] << 8) | d->buf[1];
        if (msg_len < 12) {
            // DNS message length in TCP must be at least 12 bytes (standard header).
            // Do not drain; waiting for missing prefix segments or unaligned stream.
            break;
        }
        if (d->buf_len < 2 + (size_t)msg_len) break;

        if (cb) {
            cb(user_ctx, st->stream_id, dir_idx, st->addr_key, st->port_key, d->buf + 2, (size_t)msg_len);
        }
        d->has_drained = true;

        size_t total_consumed = 2 + (size_t)msg_len;
        if (d->buf_len > total_consumed) {
            memmove(d->buf, d->buf + total_consumed, d->buf_len - total_consumed);
        }
        d->buf_len -= total_consumed;
    }
}

void tcp_reasm_feed(tcp_reasm_table_t *t, const pcap_l4_info_t *l4, tcp_reasm_message_cb cb, void *user_ctx) {
    if (!t || !l4 || l4->l4_proto != 6) return;
    if (l4->l4_payload_len == 0) return; // Pure ACK/SYN/FIN without payload

    uint8_t addr_key[32];
    uint16_t port_key[2];
    int direction = 0;
    pcap_canonicalize_endpoints(l4->src_addr, l4->src_port, l4->dst_addr, l4->dst_port,
                                addr_key, port_key, &direction);

    // Find existing stream or empty/LRU slot
    tcp_stream_t *target_stream = NULL;
    tcp_stream_t *empty_stream = NULL;
    tcp_stream_t *lru_stream = NULL;
    uint64_t min_lru = UINT64_MAX;

    for (uint32_t i = 0; i < t->max_streams; i++) {
        tcp_stream_t *st = &t->streams[i];
        if (st->in_use) {
            if (st->port_key[0] == port_key[0] && st->port_key[1] == port_key[1] &&
                memcmp(st->addr_key, addr_key, 32) == 0) {
                target_stream = st;
                break;
            }
            if (st->last_touched_seq_no < min_lru) {
                min_lru = st->last_touched_seq_no;
                lru_stream = st;
            }
        } else if (!empty_stream) {
            empty_stream = st;
        }
    }

    if (!target_stream) {
        if (empty_stream) {
            target_stream = empty_stream;
        } else if (lru_stream) {
            evict_stream(lru_stream);
            target_stream = lru_stream;
        } else {
            return; // Should not happen
        }

        target_stream->in_use = true;
        target_stream->stream_id = t->next_stream_id++;
        memcpy(target_stream->addr_key, addr_key, 32);
        target_stream->port_key[0] = port_key[0];
        target_stream->port_key[1] = port_key[1];
    }

    target_stream->last_touched_seq_no = ++t->global_seq_no;
    tcp_reasm_dir_t *d = &target_stream->dir[direction];
    uint32_t seq = l4->tcp_seq;
    size_t len = l4->l4_payload_len;
    const uint8_t *payload = l4->l4_payload;
    uint32_t end_seq = seq + (uint32_t)len;

    if (!d->base_seq_known) {
        d->base_seq_known = true;
        d->next_seq = seq + (uint32_t)len;
        if (!append_to_dir_buf(d, t->max_buffer_per_direction, payload, len)) {
            evict_stream(target_stream);
            return;
        }
        process_ooo(target_stream, direction, t->max_buffer_per_direction);
    } else {
        uint32_t base_seq = d->next_seq - (uint32_t)d->buf_len;
        if (seq == d->next_seq) {
            d->next_seq += (uint32_t)len;
            if (!append_to_dir_buf(d, t->max_buffer_per_direction, payload, len)) {
                evict_stream(target_stream);
                return;
            }
            process_ooo(target_stream, direction, t->max_buffer_per_direction);
        } else if (seq > d->next_seq) {
            // Forward out-of-order segment
            if (len <= sizeof(d->ooo[0].data)) {
                int slot = -1;
                for (int i = 0; i < TCP_REASM_MAX_OOO_SEGMENTS; i++) {
                    if (!d->ooo[i].in_use) {
                        slot = i;
                        break;
                    }
                    if (d->ooo[i].seq == seq) {
                        slot = -2; // Duplicate
                        break;
                    }
                }
                if (slot >= 0) {
                    d->ooo[slot].in_use = true;
                    d->ooo[slot].seq = seq;
                    d->ooo[slot].len = (uint16_t)len;
                    memcpy(d->ooo[slot].data, payload, len);
                } else if (slot == -1) {
                    d->ooo[0].in_use = true;
                    d->ooo[0].seq = seq;
                    d->ooo[0].len = (uint16_t)len;
                    memcpy(d->ooo[0].data, payload, len);
                }
            }
        } else if (seq < base_seq) {
            // Segment starts before currently buffered window
            if (!d->has_drained) {
                // Initial stream startup before any message was drained: allow prepending
                if (end_seq >= base_seq) {
                    size_t new_prefix = (size_t)(base_seq - seq);
                    if (!prepend_to_dir_buf(d, t->max_buffer_per_direction, payload, new_prefix)) {
                        evict_stream(target_stream);
                        return;
                    }
                    if (end_seq > d->next_seq) {
                        size_t overlap = (size_t)(d->next_seq - seq);
                        size_t new_suffix = len - overlap;
                        d->next_seq += (uint32_t)new_suffix;
                        if (!append_to_dir_buf(d, t->max_buffer_per_direction, payload + overlap, new_suffix)) {
                            evict_stream(target_stream);
                            return;
                        }
                    }
                    process_ooo(target_stream, direction, t->max_buffer_per_direction);
                } else {
                    if (len <= sizeof(d->ooo[0].data)) {
                        int slot = -1;
                        for (int i = 0; i < TCP_REASM_MAX_OOO_SEGMENTS; i++) {
                            if (!d->ooo[i].in_use) { slot = i; break; }
                            if (d->ooo[i].seq == seq) { slot = -2; break; }
                        }
                        if (slot >= 0) {
                            d->ooo[slot].in_use = true;
                            d->ooo[slot].seq = seq;
                            d->ooo[slot].len = (uint16_t)len;
                            memcpy(d->ooo[slot].data, payload, len);
                        }
                    }
                }
            } else {
                // has_drained == true: Data before base_seq was already consumed.
                // Ignore retransmissions and only append novel suffix if end_seq > next_seq.
                if (end_seq > d->next_seq) {
                    size_t overlap = (size_t)(d->next_seq - seq);
                    size_t new_bytes = len - overlap;
                    d->next_seq += (uint32_t)new_bytes;
                    if (!append_to_dir_buf(d, t->max_buffer_per_direction, payload + overlap, new_bytes)) {
                        evict_stream(target_stream);
                        return;
                    }
                    process_ooo(target_stream, direction, t->max_buffer_per_direction);
                }
            }
        } else {
            // seq >= base_seq && seq <= d->next_seq
            if (end_seq > d->next_seq) {
                size_t overlap = (size_t)(d->next_seq - seq);
                size_t new_bytes = len - overlap;
                d->next_seq += (uint32_t)new_bytes;
                if (!append_to_dir_buf(d, t->max_buffer_per_direction, payload + overlap, new_bytes)) {
                    evict_stream(target_stream);
                    return;
                }
                process_ooo(target_stream, direction, t->max_buffer_per_direction);
            }
        }
    }

    if (target_stream->in_use) {
        drain_dns_messages(target_stream, direction, cb, user_ctx);
    }
}
